use std::collections::HashMap;

use cipher::{
    block_padding::Pkcs7, crypto_common::rand_core, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
use digest::Mac;
use serde::{Deserialize, Serialize};
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::api::{AttributeValue, EncAlg, EncryptedItem, Error, MacAlg, GVARIANT_ENCODING};
use crate::Key;

/// An item stored in the file backend.
#[derive(Deserialize, Serialize, Type, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    #[zeroize(skip)]
    attributes: HashMap<String, AttributeValue>,
    label: String,
    created: u64,
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
    pub fn set_secret<P: AsRef<[u8]>>(&mut self, secret: P) {
        self.modified = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.secret = secret.as_ref().to_vec();
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
