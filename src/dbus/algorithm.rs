use serde::Serialize;
use zbus::zvariant;

#[derive(Debug, zvariant::Type, PartialEq, Eq, Copy, Clone)]
#[zvariant(signature = "s")]
pub enum Algorithm {
    Plain,
    Encrypted,
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Algorithm::Plain => String::serialize(&"plain".to_owned(), serializer),
            Algorithm::Encrypted => String::serialize(
                &"dh-ietf1024-sha256-aes128-cbc-pkcs7".to_owned(),
                serializer,
            ),
        }
    }
}
