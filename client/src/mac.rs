use serde::{Deserialize, Serialize};
#[cfg(feature = "native_crypto")]
use subtle::ConstantTimeEq;
use zbus::zvariant::Type;

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub struct Mac(Vec<u8>);

impl Mac {
    pub(crate) fn new(inner: Vec<u8>) -> Self {
        Mac(inner)
    }

    #[cfg(feature = "native_crypto")]
    pub fn verify_slice(&self, other: &[u8]) -> bool {
        self.0.ct_eq(other).into()
    }

    #[cfg(feature = "openssl_crypto")]
    pub fn verify_slice(&self, other: &[u8]) -> bool {
        openssl::memcmp::eq(&self.0, other)
    }
}

impl AsRef<[u8]> for Mac {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        self.verify_slice(&other.0)
    }
}
