use digest::Mac;
use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::MacAlg;
use crate::Key;

/// An encrypted attribute value.
#[derive(Deserialize, Serialize, Type, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AttributeValue(String);

impl AttributeValue {
    pub(crate) fn mac(&self, key: &Key) -> digest::CtOutput<MacAlg> {
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(self.0.as_bytes());
        mac.finalize()
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
