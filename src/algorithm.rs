use serde::Serialize;
use zbus::zvariant::{self, Type};

#[derive(Debug, zvariant::Type, PartialEq, Eq, Copy, Clone)]
#[zvariant(signature = "s")]
pub enum Algorithm {
    Plain,
    Encrypted,
}

impl Algorithm {
    pub(crate) fn client_key(&self) -> zvariant::OwnedValue {
        match self {
            Self::Plain => zvariant::Str::default().into(),
            Self::Encrypted => {
                let mut array = zvariant::Array::new(u8::signature());
                let key: &[u8] = unimplemented!();
                for byte in key {
                    array
                        .append(zvariant::Value::U8(*byte))
                        .expect("Element of valid type");
                }
                array.into()
            }
        }
    }
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
