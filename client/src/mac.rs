use serde::{Deserialize, Serialize};
#[cfg(feature = "native_crypto")]
use subtle::ConstantTimeEq;
use zbus::zvariant::Type;

// There is no constructor to avoid performing sanity checks, e.g. length.
/// A message authentication code. It provides constant-time comparison when
/// compared against another mac or against a slice of bytes.
#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub struct Mac(Vec<u8>);

impl Mac {
    pub(crate) fn new(inner: Vec<u8>) -> Self {
        Mac(inner)
    }

    /// Constant-time comparison against a slice of bytes.
    pub fn verify_slice(&self, other: &[u8]) -> bool {
        #[cfg(feature = "native_crypto")]
        {
            self.0.ct_eq(other).into()
        }
        #[cfg(feature = "openssl_crypto")]
        {
            openssl::memcmp::eq(&self.0, other)
        }
    }

    // This is made private to prevent non-constant-time comparisons.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        self.verify_slice(&other.0)
    }
}
