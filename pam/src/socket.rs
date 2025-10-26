use std::{io, path::PathBuf, time::Duration};

use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};
use zeroize::Zeroizing;

use crate::protocol::PamMessage;

/// Timeout for socket operations (in milliseconds)
const SOCKET_TIMEOUT_MS: u64 = 5000;

/// Error type for socket operations
#[derive(Debug)]
pub enum SocketError {
    Connect(io::Error),
    Send(io::Error),
    Serialize(zvariant::Error),
    Timeout,
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "Failed to connect to daemon socket: {e}"),
            Self::Send(e) => write!(f, "Failed to send message: {e}"),
            Self::Serialize(e) => write!(f, "Failed to serialize message: {e}"),
            Self::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Send(e) => Some(e),
            Self::Serialize(e) => Some(e),
            Self::Timeout => None,
        }
    }
}

pub fn send_secret_to_daemon(
    message: PamMessage,
    uid: u32,
    auto_start: bool,
) -> Result<(), SocketError> {
    let runtime = tokio::runtime::Runtime::new().map_err(SocketError::Connect)?;

    runtime.block_on(async { send_secret_to_daemon_async(message, uid, auto_start).await })
}

/// Start the oo7-daemon for the current user
fn start_daemon() -> Result<(), SocketError> {
    tracing::info!("Attempting to start oo7-daemon directly");

    // Fork and exec the daemon directly (like gnome-keyring does)
    // We can't use systemctl --user here because the user session bus isn't ready
    // yet
    match unsafe { libc::fork() } {
        -1 => {
            tracing::error!("Failed to fork process");
            Err(SocketError::Connect(io::Error::last_os_error()))
        }
        0 => {
            // Child process - exec oo7-daemon
            // Close stdin, stdout, stderr and reopen to /dev/null
            unsafe {
                let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if dev_null >= 0 {
                    libc::dup2(dev_null, 0);
                    libc::dup2(dev_null, 1);
                    libc::dup2(dev_null, 2);
                    if dev_null > 2 {
                        libc::close(dev_null);
                    }
                }

                // Exec the daemon
                let daemon_path = c"/usr/bin/oo7-daemon".as_ptr();
                let args = [daemon_path, std::ptr::null()];
                libc::execv(daemon_path, args.as_ptr());

                // If exec fails, exit the child process
                libc::_exit(1);
            }
        }
        child_pid => {
            // Parent process - daemon is starting in background
            tracing::info!("Started oo7-daemon with PID {}", child_pid);
            Ok(())
        }
    }
}

async fn send_secret_to_daemon_async(
    message: PamMessage,
    uid: u32,
    auto_start: bool,
) -> Result<(), SocketError> {
    let socket_path = std::env::var("OO7_PAM_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("/run/user/{uid}/oo7-pam.sock")));

    tracing::debug!("Connecting to daemon socket at: {}", socket_path.display());

    // Try to connect with retries if auto_start is enabled
    // We don't check if socket exists to avoid SELinux getattr denials
    let mut stream = None;
    let max_retries = if auto_start { 20 } else { 1 }; // 20 * 100ms = 2 seconds
    let mut daemon_started = false;

    for attempt in 0..max_retries {
        match timeout(
            Duration::from_millis(SOCKET_TIMEOUT_MS),
            UnixStream::connect(&socket_path),
        )
        .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                if daemon_started {
                    tracing::info!("Successfully connected to daemon socket");
                }
                break;
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound && auto_start && !daemon_started => {
                // Socket doesn't exist yet, start daemon on first attempt
                tracing::info!("Socket not found, attempting to start daemon");
                start_daemon()?;
                daemon_started = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(Err(e))
                if (e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::ConnectionRefused)
                    && auto_start
                    && attempt + 1 < max_retries =>
            {
                // Socket not ready yet, retry
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(Err(e)) => {
                return Err(SocketError::Connect(e));
            }
            Err(_) => {
                return Err(SocketError::Timeout);
            }
        }
    }

    let mut stream = stream.ok_or_else(|| {
        SocketError::Connect(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to connect to daemon socket after retries",
        ))
    })?;

    tracing::debug!("Connected to daemon socket");

    tracing::debug!("Sending message for user {}", message.username);
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncReadExt, net::UnixListener};

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
            assert_eq!(message.new_secret, b"testpassword");
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let message = PamMessage::unlock("testuser".to_string(), b"testpassword".to_vec());

        let result = send_secret_to_daemon_async(message, 1000, false).await;
        assert!(result.is_ok());

        server.await?;

        unsafe {
            std::env::remove_var("OO7_PAM_SOCKET");
        }

        Ok(())
    }
}
