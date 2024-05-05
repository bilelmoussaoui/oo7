use serde::{Deserialize, Serialize};

#[derive(Debug, zvariant::Type, PartialEq, Eq, Copy, Clone)]
#[zvariant(signature = "s")]
/// Algorithm used to start a new session.
///
/// The communication between the Secret Service and the application can either
/// be encrypted or the items can be sent in plain text.
pub enum Algorithm {
    /// Plain text, per <https://specifications.freedesktop.org/secret-service/latest/ch07s02.html>.
    Plain,
    /// Encrypted, per <https://specifications.freedesktop.org/secret-service/latest/ch07s03.html>.
    Encrypted,
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Plain => String::serialize(&"plain".to_owned(), serializer),
            Self::Encrypted => String::serialize(
                &"dh-ietf1024-sha256-aes128-cbc-pkcs7".to_owned(),
                serializer,
            ),
        }
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "plain" => Ok(Self::Plain),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => Ok(Self::Encrypted),
            e => Err(serde::de::Error::custom(format!("Invalid algorithm {e}"))),
        }
    }
}
