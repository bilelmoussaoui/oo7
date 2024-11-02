use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    api::{AttributeValue, EncryptedItem, GVARIANT_ENCODING},
    Error,
};
use crate::{crypto, AsAttributes, Key, Secret};

/// An item stored in the file backend.
#[derive(Deserialize, Serialize, zvariant::Type, Clone, Debug, Zeroize, ZeroizeOnDrop)]
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
        attributes: &impl AsAttributes,
        secret: impl Into<Secret>,
    ) -> Self {
        let now = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();

        Self {
            attributes: attributes
                .as_attributes()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into()))
                .collect(),
            label: label.to_string(),
            created: now,
            modified: now,
            secret: secret.into().as_bytes().to_vec(),
        }
    }

    /// Retrieve the item attributes.
    pub fn attributes(&self) -> &HashMap<String, AttributeValue> {
        &self.attributes
    }

    /// Update the item attributes.
    pub fn set_attributes(&mut self, attributes: &impl AsAttributes) {
        self.attributes = attributes
            .as_attributes()
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
    pub fn set_secret(&mut self, secret: impl Into<Secret>) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.secret = secret.into().as_bytes().to_vec();
    }

    /// The UNIX time when the item was created.
    pub fn created(&self) -> Duration {
        let secs = self.created;
        Duration::from_secs(secs)
    }

    /// The UNIX time when the item was modified.
    pub fn modified(&self) -> Duration {
        let secs = self.modified;
        Duration::from_secs(secs)
    }

    pub(crate) fn encrypt(&self, key: &Key) -> Result<EncryptedItem, Error> {
        key.check_strength()?;

        let decrypted = Zeroizing::new(zvariant::to_bytes(*GVARIANT_ENCODING, &self)?.to_vec());

        let iv = crypto::generate_iv();

        let mut blob = crypto::encrypt(&*decrypted, key, &iv);

        blob.append(&mut iv.as_slice().into());
        blob.append(&mut crypto::compute_mac(&blob, key).as_slice().into());

        let hashed_attributes = self
            .attributes
            .iter()
            .map(|(k, v)| (k.to_owned(), v.mac(key).as_slice().into()))
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
        Ok(zvariant::serialized::Data::new(value, *GVARIANT_ENCODING)
            .deserialize()?
            .0)
    }
}
