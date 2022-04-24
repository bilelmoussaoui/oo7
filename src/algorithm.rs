use serde::Serialize;
use zbus::zvariant::{self, Type};

#[derive(Debug, zvariant::Type, PartialEq, Eq)]
#[zvariant(signature = "s")]
pub enum Algorithm {
    Plain,
    Dh(Vec<u8>),
}

impl Algorithm {
    pub(crate) fn client_key(&self) -> zvariant::OwnedValue {
        match self {
            Self::Plain => zvariant::Str::default().into(),
            Self::Dh(key) => {
                let mut array = zvariant::Array::new(u8::signature());
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
            Algorithm::Dh(_) => String::serialize(
                &"dh-ietf1024-sha256-aes128-cbc-pkcs7".to_owned(),
                serializer,
            ),
        }
    }
}
