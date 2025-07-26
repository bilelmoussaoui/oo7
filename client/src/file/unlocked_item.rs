use std::{collections::HashMap, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    Error,
    api::{AttributeValue, EncryptedItem, GVARIANT_ENCODING},
};
use crate::{AsAttributes, CONTENT_TYPE_ATTRIBUTE, Key, Secret, crypto, secret::ContentType};

/// An item stored in the file backend.
#[derive(
    Deserialize, Serialize, zvariant::Type, Clone, Debug, Zeroize, ZeroizeOnDrop, PartialEq,
)]
pub struct UnlockedItem {
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

impl UnlockedItem {
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

impl TryFrom<&[u8]> for UnlockedItem {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let mut item: UnlockedItem = zvariant::serialized::Data::new(value, *GVARIANT_ENCODING)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_item_serialization() {
        let key = Key::new(vec![
            204, 53, 139, 40, 55, 167, 183, 240, 191, 252, 186, 174, 28, 36, 229, 26,
        ]);
        let n_mac = crypto::mac_len();
        let n_iv = crypto::iv_len();

        let iv = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0];
        assert_eq!(iv.len(), n_iv);

        let attribute_value = AttributeValue::from("5");
        let attribute_value_mac = attribute_value.mac(&key).unwrap();

        let mut item = UnlockedItem {
            attributes: HashMap::from([("fooness".to_string(), attribute_value)]),
            label: "foo".to_string(),
            created: 50,
            modified: 50,
            secret: b"bar".to_vec(),
        };

        let encrypted = item.encrypt_inner(&key, &iv).unwrap();
        assert!(encrypted.has_attribute("fooness", &attribute_value_mac));

        let blob = &encrypted.blob;
        let n = blob.len();

        // encrypted.blob should be the concatenation of the encrypted data, the
        // iv, and the mac.
        let encrypted_item_blob = &encrypted.blob[..n - n_mac - n_iv];
        let item_mac = crypto::compute_mac(&encrypted.blob[..n - n_mac], &key).unwrap();

        assert_eq!(&blob[n - n_mac..], &item_mac);
        assert_eq!(&blob[n - n_mac - n_iv..n - n_mac], &iv);
        assert_eq!(
            encrypted_item_blob,
            vec![
                196, 246, 127, 53, 194, 30, 176, 37, 128, 145, 195, 96, 211, 161, 60, 150, 160,
                126, 85, 125, 85, 238, 5, 93, 153, 128, 176, 205, 31, 87, 48, 82, 121, 230, 143,
                152, 153, 193, 182, 114, 59, 157, 85, 41, 50, 1, 142, 112
            ]
        );

        let decrypted = encrypted.decrypt(&key).unwrap();

        // The decrypted item matches the original one but with the content-type
        // attribute set.
        item.attributes.insert(
            crate::CONTENT_TYPE_ATTRIBUTE.to_string(),
            AttributeValue::from(crate::secret::ContentType::Blob.as_str()),
        );
        assert_eq!(decrypted, item);
    }
}
