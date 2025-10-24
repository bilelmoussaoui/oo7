//! PAM integration - Unix socket listener for receiving secrets from PAM module

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use oo7::Secret;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
struct PamMessage {
    username: String,
    secret: Vec<u8>,
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
            .unwrap_or_else(|_| PathBuf::from(format!("/run/user/{}/oo7-pam.sock", uid)));

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

        tracing::info!("Received PAM authentication for user: {}", message.username);
        tracing::debug!("Received secret of length {} bytes", message.secret.len());

        let secret = Secret::from(message.secret.to_vec());
        self.user_secrets
            .write()
            .await
            .insert(message.username.clone(), secret.clone());

        // Try to unlock the default collection with this secret
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

        Ok(())
    }

    async fn try_unlock_collections(&self, secret: &Secret) -> Result<(), Error> {
        let collections = self.service.collections.lock().await;

        for (_path, collection) in collections.iter() {
            if collection.is_locked().await {
                tracing::debug!("Attempting to unlock collection: {}", collection.path());

                // Try to unlock with the provided secret
                if let Err(e) = collection.set_locked(false, Some(secret.clone())).await {
                    collection.dispatch_items().await?;
                    tracing::debug!("Failed to unlock collection {}: {}", collection.path(), e);
                } else {
                    tracing::info!("Unlocked collection: {}", collection.path());
                }
            }
        }

        Ok(())
    }
}

impl Drop for PamListener {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}
