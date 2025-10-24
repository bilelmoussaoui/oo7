//! PAM integration - Unix socket listener for receiving secrets from PAM module

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use oo7::Secret;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::RwLock,
};
use zbus::zvariant::{
    self, Type,
    serialized::{Context, Data},
    to_bytes,
};

use crate::{Service, error::Error};

/// Default socket path for PAM communication
const DEFAULT_PAM_SOCKET_PATH: &str = "/run/oo7/pam.sock";

#[derive(Debug, Serialize, Deserialize, Type)]
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

#[derive(Debug, Serialize, Deserialize, Type)]
enum PamResponse {
    Success(String),
    Error(String),
}

impl PamResponse {
    fn to_bytes(&self) -> Result<Vec<u8>, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        to_bytes(ctxt, self).map(|data| data.to_vec())
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
        let socket_path = std::env::var("OO7_PAM_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_PAM_SOCKET_PATH));

        Self {
            socket_path,
            service,
            user_secrets: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Start the PAM listener
    pub async fn start(self) -> Result<(), Error> {
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        tracing::info!("PAM listener started on {}", self.socket_path.display());

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

        let secret = Secret::from(message.secret);
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

        let response_bytes = PamResponse::Success(String::new())
            .to_bytes()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let length = response_bytes.len() as u32;
        stream.write_all(&length.to_le_bytes()).await?;
        stream.write_all(&response_bytes).await?;
        stream.flush().await?;

        tracing::debug!("Sent response to PAM module");

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
