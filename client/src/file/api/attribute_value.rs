use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Key, crypto};

/// An attribute value.
#[derive(Deserialize, Serialize, Type, Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AttributeValue(String);

impl AttributeValue {
    pub(crate) fn mac(&self, key: &Key) -> Result<Vec<u8>, crate::crypto::Error> {
        crypto::compute_mac(self.0.as_bytes(), key)
    }
}

impl<S: ToString> From<S> for AttributeValue {
    fn from(value: S) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for AttributeValue {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl std::ops::Deref for AttributeValue {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}
