use std::collections::HashMap;

use digest::Mac;
use serde::{Deserialize, Serialize};
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    api::{AttributeValue, EncryptedItem, GVARIANT_ENCODING},
    Error,
};
use crate::{
    crypto::{self, MacAlg},
    Key,
};

/// An item stored in the file backend.
#[derive(Deserialize, Serialize, Type, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    #[zeroize(skip)]
    attributes: HashMap<String, AttributeValue>,
    #[zeroize(skip)]
    label: String,
    #[zeroize(skip)]
    created: u64,
    #[zeroize(skip)]
    modified: u64,
    secret: Vec<u8>,
}

impl Item {
    pub(crate) fn new(
        label: impl ToString,
        attributes: HashMap<impl ToString, impl ToString>,
        secret: impl AsRef<[u8]>,
    ) -> Self {
        let now = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();

        Self {
            attributes: attributes
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into()))
                .collect(),
            label: label.to_string(),
            created: now,
            modified: now,
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Retrieve the item attributes.
    pub fn attributes(&self) -> &HashMap<String, AttributeValue> {
        &self.attributes
    }

    /// Update the item attributes.
    pub fn set_attributes(&mut self, attributes: HashMap<&str, &str>) {
        self.attributes = attributes
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect();
    }

    /// The item label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the item label.
    pub fn set_label(&mut self, label: impl ToString) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.label = label.to_string();
    }

    /// Retrieve the currently stored secret.
    pub fn secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret.clone())
    }

    /// Store a new secret.
    pub fn set_secret(&mut self, secret: impl AsRef<[u8]>) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.secret = secret.as_ref().to_vec();
    }

    pub(crate) fn encrypt(&self, key: &Key) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(*GVARIANT_ENCODING, &self)?);

        let iv = crypto::generate_iv();

        let mut blob = crypto::encrypt(&*decrypted, key, iv);

        blob.append(&mut iv.as_slice().into());

        // Unwrapping since arbitrary keylength allowed
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(&blob);
        blob.append(&mut mac.finalize().into_bytes().as_slice().into());

        let hashed_attributes = self
            .attributes
            .iter()
            .map(|(k, v)| (k.to_owned(), v.mac(key).into_bytes().as_slice().into()))
            .collect();

        Ok(EncryptedItem {
            hashed_attributes,
            blob,
        })
    }
}

impl TryFrom<&[u8]> for Item {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        Ok(zvariant::from_slice(value, *GVARIANT_ENCODING)?)
    }
}
