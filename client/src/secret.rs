use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Default, PartialEq, Eq, Copy, Clone, Debug, zvariant::Type)]
#[zvariant(signature = "s")]
pub enum ContentType {
    Text,
    #[default]
    Blob,
}

impl Serialize for ContentType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContentType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for ContentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text/plain" => Ok(Self::Text),
            "application/octet-stream" => Ok(Self::Blob),
            e => Err(format!("Invalid content type: {}", e)),
        }
    }
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text/plain",
            Self::Blob => "application/octet-stream",
        }
    }
}

/// A wrapper around a combination of (secret, content-type).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Secret {
    /// Corresponds to [`ContentType::Text`]
    Text(String),
    /// Corresponds to [`ContentType::Blob`]
    Blob(Vec<u8>),
}

impl Secret {
    /// Generate a random secret, used when creating a session collection.
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut secret = [0; 64];
        // Equivalent of `ring::rand::SecureRandom`
        getrandom::fill(&mut secret)?;

        Ok(Self::blob(secret))
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

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Text(_) => ContentType::Text,
            Self::Blob(_) => ContentType::Blob,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Blob(bytes) => bytes.as_ref(),
        }
    }

    pub fn with_content_type(content_type: ContentType, secret: impl AsRef<[u8]>) -> Self {
        match content_type {
            ContentType::Text => match String::from_utf8(secret.as_ref().to_owned()) {
                Ok(text) => Secret::text(text),
                Err(_e) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        "Failed to decode secret as UTF-8: {}, falling back to blob",
                        _e
                    );

                    Secret::blob(secret)
                }
            },
            _ => Secret::blob(secret),
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
