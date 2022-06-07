use std::collections::HashMap;

use cipher::IvSizeUser;
use digest::{Mac, OutputSizeUser};
use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

use super::{super::KeyExt, Error, Item};
use crate::{
    crypto::{self, DecAlg, MacAlg},
    Key,
};

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub(crate) struct EncryptedItem {
    pub(crate) hashed_attributes: HashMap<String, Vec<u8>>,
    pub(crate) blob: Vec<u8>,
}

impl EncryptedItem {
    pub async fn decrypt(mut self, key_ext: impl KeyExt) -> Result<Item, Error> {
        let key = key_ext.key().await;
        let mac_tag = self.blob.split_off(self.blob.len() - MacAlg::output_size());

        // verify item
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(&self.blob);
        mac.verify_slice(&mac_tag)?;

        let iv = self.blob.split_off(self.blob.len() - DecAlg::iv_size());

        // decrypt item
        let decrypted = crypto::decrypt(self.blob, key, &iv);

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
                let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
                mac.update(attribute_plaintext.as_bytes());
                if mac.verify_slice(hashed_attribute).is_err() {
                    return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
                }
            } else {
                return Err(Error::HashedAttributeMac(attribute_key.to_owned()));
            }
        }

        Ok(())
    }
}
