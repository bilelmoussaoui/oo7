use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

use crate::{
    Key, crypto,
    file::{Error, UnlockedItem},
};

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub(crate) struct EncryptedItem {
    pub(crate) hashed_attributes: HashMap<String, Vec<u8>>,
    pub(crate) blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn has_attribute(&self, key: &str, value_mac: &[u8]) -> bool {
        self.hashed_attributes.get(key).map(|b| b.as_slice()) == Some(value_mac)
    }

    pub fn decrypt(self, key: &Key) -> Result<UnlockedItem, Error> {
        let n = self.blob.len();
        let n_mac = crypto::mac_len();
        let n_iv = crypto::iv_len();

        // The encrypted data, the iv, and the mac are concatenated into blob.
        let (encrypted_data_with_iv, mac_tag) = &self.blob.split_at(n - n_mac);

        // verify item
        if !crypto::verify_mac(encrypted_data_with_iv, key, mac_tag)? {
            return Err(Error::MacError);
        }

        let (encrypted_data, iv) = encrypted_data_with_iv.split_at(n - n_mac - n_iv);

        // decrypt item
        let decrypted = crypto::decrypt(encrypted_data, key, iv)?;

        let item = UnlockedItem::try_from(decrypted.as_slice())?;

        Self::validate(&self.hashed_attributes, &item, key)?;

        Ok(item)
    }

    fn validate(
        hashed_attributes: &HashMap<String, Vec<u8>>,
        item: &UnlockedItem,
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
