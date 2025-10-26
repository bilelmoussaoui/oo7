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
        tracing::debug!("Accepted PAM connection");

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
            let was_locked = matches!(keyring, oo7::file::Keyring::Locked(_));

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
