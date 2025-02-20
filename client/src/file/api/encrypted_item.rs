use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

use super::{Error, Item};
use crate::{Key, crypto};

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub(crate) struct EncryptedItem {
    pub(crate) hashed_attributes: HashMap<String, Vec<u8>>,
    pub(crate) blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn has_attribute(&self, key: &str, blob: &[u8]) -> bool {
        self.hashed_attributes.get(key).map(|b| b.as_slice()) == Some(blob)
    }

    pub fn decrypt(mut self, key: &Key) -> Result<Item, Error> {
        let mac_tag = self.blob.split_off(self.blob.len() - crypto::mac_len());

        // verify item
        if !crypto::verify_mac(&self.blob, key, mac_tag)? {
            return Err(Error::MacError);
        }

        let iv = self.blob.split_off(self.blob.len() - crypto::iv_len());

        // decrypt item
        let decrypted = crypto::decrypt(self.blob, key, iv)?;

        let item = Item::try_from(decrypted.as_slice())?;

        Self::validate(&self.hashed_attributes, &item, key)?;

        Ok(item)
    }

    fn validate(
        hashed_attributes: &HashMap<String, Vec<u8>>,
        item: &Item,
        key: &Key,
    ) -> Result<(), Error> {
        for (attribute_key, hashed_attribute) in hashed_attributes.iter() {
            if let Some(attribute_plaintext) = item.attributes().get(attribute_key) {
                if !crypto::verify_mac(attribute_plaintext.as_bytes(), key, hashed_attribute)? {
                    return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
                }
            } else {
                return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
            }
        }

        Ok(())
    }
}
