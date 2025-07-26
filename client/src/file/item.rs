use std::{collections::HashMap, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    Error,
    api::{AttributeValue, EncryptedItem, GVARIANT_ENCODING},
};
use crate::{AsAttributes, CONTENT_TYPE_ATTRIBUTE, Key, Secret, crypto, secret::ContentType};

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

        let mut item_attributes: HashMap<String, AttributeValue> = attributes
            .as_attributes()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect();

        let secret = secret.into();
        // Set default MIME type if not provided
        if !item_attributes.contains_key(CONTENT_TYPE_ATTRIBUTE) {
            item_attributes.insert(
                CONTENT_TYPE_ATTRIBUTE.to_owned(),
                secret.content_type().as_str().into(),
            );
        }

        Self {
            attributes: item_attributes,
            label: label.to_string(),
            created: now,
            modified: now,
            secret: secret.as_bytes().to_vec(),
        }
    }

    /// Retrieve the item attributes.
    pub fn attributes(&self) -> &HashMap<String, AttributeValue> {
        &self.attributes
    }

    /// Update the item attributes.
    pub fn set_attributes(&mut self, attributes: &impl AsAttributes) {
        let mut new_attributes: HashMap<String, AttributeValue> = attributes
            .as_attributes()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect();

        // Preserve MIME type if not explicitly set in new attributes
        if !new_attributes.contains_key(CONTENT_TYPE_ATTRIBUTE) {
            if let Some(existing_mime_type) = self.attributes.get(CONTENT_TYPE_ATTRIBUTE) {
                new_attributes.insert(
                    CONTENT_TYPE_ATTRIBUTE.to_string(),
                    existing_mime_type.clone(),
                );
            } else {
                new_attributes.insert(
                    CONTENT_TYPE_ATTRIBUTE.to_owned(),
                    ContentType::default().as_str().into(),
                );
            }
        }

        self.attributes = new_attributes;
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
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
    pub fn secret(&self) -> Secret {
        let content_type = self
            .attributes
            .get(CONTENT_TYPE_ATTRIBUTE)
            .and_then(|c| ContentType::from_str(c).ok())
            .unwrap_or_default();

        Secret::with_content_type(content_type, &self.secret)
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

        let iv = crypto::generate_iv()?;

        self.encrypt_inner(key, &iv)
    }

    fn encrypt_inner(&self, key: &Key, iv: &[u8]) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(*GVARIANT_ENCODING, &self)?.to_vec());

        let mut blob = crypto::encrypt(&*decrypted, key, iv)?;

        blob.extend_from_slice(iv);
        let mut mac = crypto::compute_mac(&blob, key)?;
        blob.append(&mut mac);

        let hashed_attributes = self
            .attributes
            .iter()
            .filter_map(|(k, v)| Some((k.to_owned(), v.mac(key).ok()?)))
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
        let mut item: Item = zvariant::serialized::Data::new(value, *GVARIANT_ENCODING)
            .deserialize()?
            .0;

        // Ensure MIME type attribute exists for backward compatibility
        if !item.attributes.contains_key(CONTENT_TYPE_ATTRIBUTE) {
            item.attributes.insert(
                CONTENT_TYPE_ATTRIBUTE.to_owned(),
                ContentType::default().as_str().into(),
            );
        }

        Ok(item)
    }
}
