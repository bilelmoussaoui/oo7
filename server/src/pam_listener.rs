//! PAM integration - Unix socket listener for receiving secrets from PAM module

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use oo7::Secret;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    sync::RwLock,
};
use zbus::zvariant::{
    self, Type,
    serialized::{Context, Data},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Service, error::Error};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Type, PartialEq, Eq)]
#[repr(u8)]
enum PamOperation {
    Unlock = 0,
    ChangePassword = 1,
}

#[derive(Debug, Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
struct PamMessage {
    #[zeroize(skip)]
    operation: PamOperation,
    username: String,
    old_secret: Vec<u8>,
    new_secret: Vec<u8>,
}

impl PamMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}

/// PAM listener that receives authentication secrets from the PAM module
#[derive(Clone)]
pub struct PamListener {
    socket_path: PathBuf,
    service: Service,
    /// Current user's secret, used to unlock their keyring <username, secret>
    user_secrets: Arc<RwLock<std::collections::HashMap<String, Secret>>>,
}

impl PamListener {
    pub fn new(service: Service) -> Self {
        let uid = unsafe { libc::getuid() };
        let socket_path = std::env::var("OO7_PAM_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(format!("/run/user/{uid}/oo7-pam.sock")));

        Self {
            socket_path,
            service,
            user_secrets: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Start the PAM listener
    pub async fn start(self) -> Result<(), Error> {
        // Remove old socket if it exists
        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        tracing::info!("PAM listener started on {}", self.socket_path.display());

        // Set socket permissions to 0600
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&self.socket_path, perms)?;

        let listener = Arc::new(listener);

        // Accept connections in a loop
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let pam_listener = self.clone();

                    tokio::spawn(async move {
                        if let Err(e) = pam_listener.handle_connection(stream).await {
                            tracing::error!("Error handling PAM connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Error accepting PAM connection: {}", e);
                }
            }
        }
    }

    /// Handle a single PAM connection
    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        // Accept connections from:
        // 1. Root (UID 0) as PAM modules run as root during authentication
        // 2. Same UID as us
        let peer_cred = stream.peer_cred()?;
        let our_uid = unsafe { libc::getuid() };
        let peer_uid = peer_cred.uid();

        if peer_uid != 0 && peer_uid != our_uid {
            tracing::warn!(
                "Rejected PAM connection from UID {} PID {} (expected UID 0 or {})",
                peer_uid,
                peer_cred.pid().unwrap_or(0),
                our_uid
            );
            return Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Connection rejected: unauthorized UID (peer={}, daemon={}, root=0)",
                    peer_uid, our_uid
                ),
            )));
        }

        tracing::debug!(
            "Accepted PAM connection from {} (UID {}, PID {})",
            if peer_uid == 0 {
                "root/PAM"
            } else {
                "same user"
            },
            peer_uid,
            peer_cred.pid().unwrap_or(0)
        );

        // Read the message length prefix (4 bytes, little-endian)
        let mut length_bytes = [0u8; 4];
        stream.read_exact(&mut length_bytes).await?;
        let message_length = u32::from_le_bytes(length_bytes) as usize;

        let mut message_bytes = vec![0u8; message_length];
        stream.read_exact(&mut message_bytes).await?;

        let message = PamMessage::from_bytes(&message_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match message.operation {
            PamOperation::Unlock => {
                tracing::info!("Received unlock request for user: {}", message.username);
                tracing::debug!(
                    "Received secret of length {} bytes",
                    message.new_secret.len()
                );

                let secret = Secret::from(message.new_secret.to_vec());
                self.user_secrets
                    .write()
                    .await
                    .insert(message.username.clone(), secret.clone());

                match self.try_unlock_collections(&secret).await {
                    Ok(_) => {
                        tracing::info!(
                            "Successfully unlocked collections for user: {}",
                            message.username
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to unlock collections for user {}: {}",
                            message.username,
                            e
                        );
                    }
                }
            }
            PamOperation::ChangePassword => {
                tracing::info!(
                    "Received password change request for user: {}",
                    message.username
                );
                tracing::debug!(
                    "Old secret: {} bytes, new secret: {} bytes",
                    message.old_secret.len(),
                    message.new_secret.len()
                );

                let old_secret = Secret::from(message.old_secret.to_vec());
                let new_secret = Secret::from(message.new_secret.to_vec());

                match self
                    .change_collection_passwords(&old_secret, &new_secret)
                    .await
                {
                    Ok(changed_count) => {
                        tracing::info!(
                            "Successfully changed password for {} collection(s) for user: {}",
                            changed_count,
                            message.username
                        );
                        // Update stored secret
                        self.user_secrets
                            .write()
                            .await
                            .insert(message.username.clone(), new_secret);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to change password for user {}: {}",
                            message.username,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn try_unlock_collections(&self, secret: &Secret) -> Result<(), Error> {
        // First, try to migrate any pending v0 keyrings
        let migrated = self.service.migrate_pending_keyrings(secret).await;
        if !migrated.is_empty() {
            tracing::info!("Migrated {} v0 keyring(s): {:?}", migrated.len(), migrated);
        }

        let collections = self.service.collections.lock().await;

        for (_path, collection) in collections.iter() {
            if collection.is_locked().await {
                tracing::debug!("Attempting to unlock collection: {}", collection.path());

                // Try to unlock with the provided secret
                if let Err(e) = collection.set_locked(false, Some(secret.clone())).await {
                    tracing::debug!("Failed to unlock collection {}: {}", collection.path(), e);
                } else {
                    tracing::info!("Unlocked collection: {}", collection.path());
                }
            }
        }

        Ok(())
    }

    /// Change password for all collections that match the old password
    async fn change_collection_passwords(
        &self,
        old_secret: &Secret,
        new_secret: &Secret,
    ) -> Result<usize, Error> {
        let collections = self.service.collections.lock().await;
        let mut changed_count = 0;

        for (path, collection) in collections.iter() {
            // Skip session collection (it's temporary and doesn't persist)
            if collection.alias().await == oo7::dbus::Service::SESSION_COLLECTION {
                tracing::debug!("Skipping session collection: {}", path);
                continue;
            }

            // Get the keyring from the collection
            let keyring_guard = collection.keyring.read().await;
            let Some(keyring) = keyring_guard.as_ref() else {
                tracing::debug!("Collection {} has no keyring", path);
                continue;
            };

            // Track if we unlocked the collection (so we can re-lock it after)
            let was_locked = keyring.is_locked();

            // Check if the keyring is locked and unlock if needed
            if was_locked {
                // Try to unlock with old password first
                tracing::debug!(
                    "Collection {} is locked, attempting to unlock with old password",
                    path
                );
                drop(keyring_guard);

                if let Err(e) = collection.set_locked(false, Some(old_secret.clone())).await {
                    tracing::warn!(
                        "Failed to unlock collection {} with old password: {}",
                        path,
                        e
                    );
                    continue;
                }
            } else {
                drop(keyring_guard);
            }

            // Re-acquire the lock to get the unlocked keyring
            let keyring_guard = collection.keyring.read().await;
            let Some(oo7::file::Keyring::Unlocked(uk)) = keyring_guard.as_ref() else {
                tracing::warn!("Collection {} is not unlocked", path);
                continue;
            };

            // Validate that the old password can decrypt items in the keyring
            let can_decrypt = match uk.validate_secret(old_secret).await {
                Ok(valid) => valid,
                Err(e) => {
                    tracing::warn!(
                        "Failed to validate old password for collection {}: {}",
                        path,
                        e
                    );
                    continue;
                }
            };

            if !can_decrypt {
                tracing::debug!(
                    "Old password does not match keyring {} password, skipping",
                    path
                );
                continue;
            }

            // Change the keyring password
            match uk.change_secret(new_secret.clone()).await {
                Ok(_) => {
                    tracing::info!("Successfully changed password for collection: {}", path);
                    changed_count += 1;

                    // Re-lock the collection if it was locked before we unlocked it
                    drop(keyring_guard);
                    if was_locked {
                        if let Err(e) = collection.set_locked(true, None).await {
                            tracing::warn!(
                                "Failed to re-lock collection {} after password change: {}",
                                path,
                                e
                            );
                        } else {
                            tracing::debug!("Re-locked collection: {}", path);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to change password for collection {}: {}", path, e);
                }
            }
        }

        Ok(changed_count)
    }
}

impl Drop for PamListener {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use oo7::file::UnlockedKeyring;
    use zbus::zvariant::serialized::Context;

    use super::*;

    fn create_pam_message(
        operation: PamOperation,
        username: &str,
        old_secret: &[u8],
        new_secret: &[u8],
    ) -> Vec<u8> {
        let message = PamMessage {
            operation,
            username: username.to_owned(),
            old_secret: old_secret.to_vec(),
            new_secret: new_secret.to_vec(),
        };

        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = zvariant::to_bytes(ctxt, &message).unwrap();
        let message_bytes = encoded.to_vec();

        // Prepend length prefix (4 bytes, little-endian)
        let mut result = (message_bytes.len() as u32).to_le_bytes().to_vec();
        result.extend_from_slice(&message_bytes);
        result
    }

    async fn send_pam_message(
        socket_path: &std::path::Path,
        message_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncWriteExt;

        let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
        stream.write_all(message_bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn pam_migrates_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        unsafe { std::env::set_var("XDG_DATA_HOME", temp_dir.path()) };
        unsafe { std::env::set_var("OO7_PAM_SOCKET", temp_dir.path().join("pam.sock")) };

        let keyrings_dir = temp_dir.path().join("keyrings");
        let v1_dir = keyrings_dir.join("v1");
        tokio::fs::create_dir_all(&v1_dir).await?;

        let v0_secret = Secret::from("test");
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("client/fixtures/legacy.keyring");
        let v0_path = keyrings_dir.join("legacy.keyring");
        tokio::fs::copy(&fixture_path, &v0_path).await?;

        let setup = crate::tests::TestServiceSetup::with_disk_keyrings(None).await?;

        assert_eq!(
            setup.server.pending_migrations.lock().await.len(),
            1,
            "V0 keyring should be pending migration"
        );

        let pam_listener = PamListener::new(setup.server.clone());
        let socket_path = pam_listener.socket_path.clone();
        tokio::spawn(async move {
            let _ = pam_listener.start().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let message =
            create_pam_message(PamOperation::Unlock, "testuser", &[], v0_secret.as_bytes());
        send_pam_message(&socket_path, &message).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        assert_eq!(
            setup.server.pending_migrations.lock().await.len(),
            0,
            "V0 keyring should be migrated"
        );

        let collections = setup.server.collections.lock().await;
        let mut legacy_collection = None;
        for collection in collections.values() {
            if collection.label().await == "Legacy" {
                legacy_collection = Some(collection);
                break;
            }
        }
        assert!(
            legacy_collection.is_some(),
            "Migrated Legacy collection should exist"
        );

        let v1_migrated = v1_dir.join("legacy.keyring");
        assert!(v1_migrated.exists(), "V1 file should exist after migration");

        assert!(
            !v0_path.exists(),
            "V0 file should be removed after migration"
        );

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        unsafe { std::env::remove_var("OO7_PAM_SOCKET") };
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn pam_unlocks_locked_collections() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        unsafe { std::env::set_var("XDG_DATA_HOME", temp_dir.path()) };
        unsafe { std::env::set_var("OO7_PAM_SOCKET", temp_dir.path().join("pam.sock")) };

        // Create a v1 keyring with a known password
        let secret = Secret::from("my-secure-password");
        let keyring = UnlockedKeyring::open("work", secret.clone()).await?;
        keyring
            .create_item(
                "Work Item",
                &[("type", "work")],
                Secret::text("work-secret"),
                false,
            )
            .await?;
        keyring.write().await?;

        let setup = crate::tests::TestServiceSetup::with_disk_keyrings(None).await?;

        let collections = setup.server.collections.lock().await;
        let mut work_collection = None;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                work_collection = Some(collection);
                break;
            }
        }
        assert!(work_collection.is_some(), "Work collection should exist");
        let work_collection = work_collection.unwrap();
        assert!(
            work_collection.is_locked().await,
            "Work collection should be locked"
        );
        drop(collections);

        let pam_listener = PamListener::new(setup.server.clone());
        let socket_path = pam_listener.socket_path.clone();
        tokio::spawn(async move {
            let _ = pam_listener.start().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let message = create_pam_message(PamOperation::Unlock, "testuser", &[], secret.as_bytes());
        send_pam_message(&socket_path, &message).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let collections = setup.server.collections.lock().await;
        let mut work_collection = None;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                work_collection = Some(collection);
                break;
            }
        }
        let work_collection = work_collection.unwrap();
        assert!(
            !work_collection.is_locked().await,
            "Work collection should be unlocked"
        );

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        unsafe { std::env::remove_var("OO7_PAM_SOCKET") };
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn pam_change_password() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        unsafe { std::env::set_var("XDG_DATA_HOME", temp_dir.path()) };
        unsafe { std::env::set_var("OO7_PAM_SOCKET", temp_dir.path().join("pam.sock")) };

        let old_secret = Secret::from("old-password");
        let keyring = UnlockedKeyring::open("work", old_secret.clone()).await?;
        keyring
            .create_item(
                "Work Item",
                &[("type", "work")],
                Secret::text("work-secret"),
                false,
            )
            .await?;
        keyring.write().await?;

        let setup = crate::tests::TestServiceSetup::with_disk_keyrings(None).await?;

        let collections = setup.server.collections.lock().await;
        let mut work_collection = None;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                work_collection = Some(collection);
                break;
            }
        }
        let work_collection = work_collection.unwrap();
        assert!(
            work_collection.is_locked().await,
            "Work collection should be locked"
        );
        drop(collections);

        let pam_listener = PamListener::new(setup.server.clone());
        let socket_path = pam_listener.socket_path.clone();
        tokio::spawn(async move {
            let _ = pam_listener.start().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let new_secret = Secret::from("new-password");
        let message = create_pam_message(
            PamOperation::ChangePassword,
            "testuser",
            old_secret.as_bytes(),
            new_secret.as_bytes(),
        );
        send_pam_message(&socket_path, &message).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let collections = setup.server.collections.lock().await;
        let mut work_collection = None;
        for collection in collections.values() {
            if collection.label().await == "Work" {
                work_collection = Some(collection);
                break;
            }
        }
        let work_collection = work_collection.unwrap();
        assert!(
            work_collection.is_locked().await,
            "Collection should be locked after password change"
        );

        let unlock_result = work_collection
            .set_locked(false, Some(old_secret.clone()))
            .await;
        assert!(
            unlock_result.is_err(),
            "Old password should not unlock collection"
        );

        work_collection
            .set_locked(false, Some(new_secret.clone()))
            .await?;
        assert!(
            !work_collection.is_locked().await,
            "New password should unlock collection"
        );

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        unsafe { std::env::remove_var("OO7_PAM_SOCKET") };
        Ok(())
    }

    #[tokio::test]
    async fn message_serialization() -> Result<(), Box<dyn std::error::Error>> {
        // Test that PamMessage can be properly serialized and deserialized
        let message = PamMessage {
            operation: PamOperation::Unlock,
            username: "testuser".to_owned(),
            old_secret: vec![],
            new_secret: b"my-password".to_vec(),
        };

        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = zvariant::to_bytes(ctxt, &message)?;
        let decoded = PamMessage::from_bytes(&encoded)?;

        assert_eq!(decoded.operation, PamOperation::Unlock);
        assert_eq!(decoded.username, "testuser");
        assert_eq!(decoded.new_secret, b"my-password");

        let message = PamMessage {
            operation: PamOperation::ChangePassword,
            username: "testuser".to_owned(),
            old_secret: b"old-pass".to_vec(),
            new_secret: b"new-pass".to_vec(),
        };

        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = zvariant::to_bytes(ctxt, &message)?;
        let decoded = PamMessage::from_bytes(&encoded)?;

        assert_eq!(decoded.operation, PamOperation::ChangePassword);
        assert_eq!(decoded.old_secret, b"old-pass");
        assert_eq!(decoded.new_secret, b"new-pass");

        Ok(())
    }
}
