use std::collections::HashMap;

use cipher::{
    block_padding::Pkcs7, crypto_common::rand_core, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
use digest::Mac;
use serde::{Deserialize, Serialize};
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{AttributeValue, EncAlg, EncryptedItem, Error, MacAlg, GVARIANT_ENCODING};
use crate::Key;

#[derive(Deserialize, Serialize, Type, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    #[zeroize(skip)]
    attributes: HashMap<String, AttributeValue>,
    label: String,
    created: u64,
    modified: u64,
    password: Vec<u8>,
}

impl Item {
    pub fn new(
        label: impl ToString,
        attributes: HashMap<impl ToString, impl ToString>,
        password: impl AsRef<[u8]>,
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
            password: password.as_ref().to_vec(),
        }
    }

    pub fn attributes(&self) -> &HashMap<String, AttributeValue> {
        &self.attributes
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn set_label(&mut self, label: impl ToString) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.label = label.to_string();
    }

    pub fn password(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.password.clone())
    }

    pub fn set_password<P: AsRef<[u8]>>(&mut self, password: P) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.password = password.as_ref().to_vec();
    }

    pub(crate) fn encrypt(&self, key: &Key) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(*GVARIANT_ENCODING, &self)?);

        let iv = EncAlg::generate_iv(rand_core::OsRng);

        let mut blob = vec![0; decrypted.len() + EncAlg::block_size()];

        // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for PKCS7
        let encrypted_len = EncAlg::new(key.as_ref().into(), &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(&decrypted, &mut blob)
            .unwrap()
            .len();

        blob.truncate(encrypted_len);
        blob.append(&mut iv.as_slice().into());

        // Unwrapping since arbitrary keylength allowed
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(&blob);
        blob.append(&mut mac.finalize().into_bytes().as_slice().into());

        let hashed_attributes = self
            .attributes
            .iter()
            .map(|(k, v)| (k.to_string(), v.mac(key).into_bytes().as_slice().into()))
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
