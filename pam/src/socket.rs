use std::{io, path::PathBuf, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::protocol::{PamMessage, PamResponse};

/// Default socket path for oo7 PAM communication
const DEFAULT_SOCKET_PATH: &str = "/run/oo7/pam.sock";

/// Timeout for socket operations (in milliseconds)
const SOCKET_TIMEOUT_MS: u64 = 5000;

/// Error type for socket operations
#[derive(Debug)]
pub enum SocketError {
    Connect(io::Error),
    Send(io::Error),
    Receive(io::Error),
    Serialize(zvariant::Error),
    Deserialize(zvariant::Error),
    Timeout,
    DaemonError(String),
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "Failed to connect to daemon socket: {}", e),
            Self::Send(e) => write!(f, "Failed to send message: {}", e),
            Self::Receive(e) => write!(f, "Failed to receive response: {}", e),
            Self::Serialize(e) => write!(f, "Failed to serialize message: {}", e),
            Self::Deserialize(e) => write!(f, "Failed to deserialize response: {}", e),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::DaemonError(msg) => write!(f, "Daemon returned error: {}", msg),
        }
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Send(e) | Self::Receive(e) => Some(e),
            Self::Serialize(e) | Self::Deserialize(e) => Some(e),
            Self::Timeout | Self::DaemonError(_) => None,
        }
    }
}

pub fn send_secret_to_daemon(message: PamMessage) -> Result<(), SocketError> {
    let runtime = tokio::runtime::Runtime::new().map_err(SocketError::Connect)?;

    runtime.block_on(async { send_secret_to_daemon_async(message).await })
}

async fn send_secret_to_daemon_async(message: PamMessage) -> Result<(), SocketError> {
    let socket_path = std::env::var("OO7_PAM_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));

    tracing::debug!("Connecting to daemon socket at: {}", socket_path.display());

    let mut stream = timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        UnixStream::connect(&socket_path),
    )
    .await
    .map_err(|_| SocketError::Timeout)?
    .map_err(SocketError::Connect)?;

    tracing::debug!("Connected to daemon socket");

    let message_bytes = Zeroizing::new(message.to_bytes().map_err(SocketError::Serialize)?);

    let length = message_bytes.len() as u32;
    stream
        .write_all(&length.to_le_bytes())
        .await
        .map_err(SocketError::Send)?;

    timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        stream.write_all(&message_bytes),
    )
    .await
    .map_err(|_| SocketError::Timeout)?
    .map_err(SocketError::Send)?;

    stream.flush().await.map_err(SocketError::Send)?;

    tracing::debug!("Sent message to daemon, waiting for response");

    let mut length_bytes = [0u8; 4];
    timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        stream.read_exact(&mut length_bytes),
    )
    .await
    .map_err(|_| SocketError::Timeout)?
    .map_err(SocketError::Receive)?;

    let response_length = u32::from_le_bytes(length_bytes) as usize;

    let mut response_bytes = vec![0u8; response_length];
    timeout(
        Duration::from_millis(SOCKET_TIMEOUT_MS),
        stream.read_exact(&mut response_bytes),
    )
    .await
    .map_err(|_| SocketError::Timeout)?
    .map_err(SocketError::Receive)?;

    let response = PamResponse::from_bytes(&response_bytes).map_err(SocketError::Deserialize)?;

    match response {
        PamResponse::Success(_) => {
            tracing::debug!("Daemon acknowledged secret successfully");
            Ok(())
        }
        PamResponse::Error(message) => {
            tracing::error!("Daemon returned error: {}", message);
            Err(SocketError::DaemonError(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

    use super::*;

    #[tokio::test]
    async fn test_send_receive() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        let socket_path = temp_dir.path().join("test.sock");

        // Set the environment variable to use our test socket
        unsafe {
            std::env::set_var("OO7_PAM_SOCKET", socket_path.to_str().unwrap());
        }

        let server = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).await.unwrap();
            let message_length = u32::from_le_bytes(length_bytes) as usize;

            let mut message_bytes = vec![0u8; message_length];
            stream.read_exact(&mut message_bytes).await.unwrap();

            let message = PamMessage::from_bytes(&message_bytes).unwrap();
            assert_eq!(message.username, "testuser");
            assert_eq!(message.secret, b"testpassword");

            let response = PamResponse::Success(String::new());
            let response_bytes = response.to_bytes().unwrap();
            let length = response_bytes.len() as u32;
            stream.write_all(&length.to_le_bytes()).await.unwrap();
            stream.write_all(&response_bytes).await.unwrap();
            stream.flush().await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let message = PamMessage {
            username: "testuser".to_string(),
            secret: b"testpassword".to_vec(),
        };

        let result = send_secret_to_daemon_async(message).await;
        assert!(result.is_ok());

        server.await?;

        unsafe {
            std::env::remove_var("OO7_PAM_SOCKET");
        }

        Ok(())
    }
}
