use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A safe wrapper around a combination of (secret, content-type).
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub enum Secret {
    /// Corresponds to `text/plain`
    Text(String),
    /// Corresponds to application/octet-stream
    Blob(Vec<u8>),
}

impl Secret {
    /// Generate a random secret, used when creating a session collection.
    pub fn random() -> Self {
        Self::Blob(rand::thread_rng().gen::<[u8; 8]>().to_vec())
    }

    /// Create a text secret, stored with `text/plain` content type.
    pub fn text(value: impl AsRef<str>) -> Self {
        Self::Text(value.as_ref().to_owned())
    }

    /// Create a blob secret, stored with `application/octet-stream` content
    /// type.
    pub fn blob(value: impl AsRef<[u8]>) -> Self {
        Self::Blob(value.as_ref().to_owned())
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Text(_) => "text/plain",
            Self::Blob(_) => "application/octet-stream",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Blob(bytes) => bytes.as_ref(),
        }
    }
}

impl From<&[u8]> for Secret {
    fn from(value: &[u8]) -> Self {
        Self::blob(value)
    }
}

impl From<Zeroizing<Vec<u8>>> for Secret {
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        Self::blob(value)
    }
}

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self::blob(value)
    }
}

impl From<&Vec<u8>> for Secret {
    fn from(value: &Vec<u8>) -> Self {
        Self::blob(value)
    }
}

impl<const N: usize> From<&[u8; N]> for Secret {
    fn from(value: &[u8; N]) -> Self {
        Self::blob(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::text(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::text(value)
    }
}

impl std::ops::Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
