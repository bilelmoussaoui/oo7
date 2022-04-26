/*!
GNOME Keyring format low level api

Only use this if you know what you are doing.

### To Do

- Order user calls
- Keep proxis around
- Make more things async
*/
use async_std::prelude::*;

use async_std::{fs, io, path::Path};
use cipher::{
    block_padding::Pkcs7, crypto_common::rand_core, BlockDecryptMut, BlockEncryptMut,
    BlockSizeUser, IvSizeUser, KeyIvInit,
};
use digest::OutputSizeUser;
use hmac::Mac;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const SALT_SIZE: usize = 32;
pub(crate) const ITERATION_COUNT: u32 = 100000;

pub(crate) const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
pub(crate) const FILE_HEADER_LEN: usize = FILE_HEADER.len();

pub(crate) const MAJOR_VERSION: u8 = 1;
pub(crate) const MINOR_VERSION: u8 = 0;

pub(crate) type MacAlg = hmac::Hmac<sha2::Sha256>;
pub(crate) type EncAlg = cbc::Encryptor<aes::Aes128>;
pub(crate) type DecAlg = cbc::Decryptor<aes::Aes128>;

pub(crate) static GVARIANT_ENCODING: Lazy<zvariant::EncodingContext<byteorder::LE>> =
    Lazy::new(|| zvariant::EncodingContext::<byteorder::LE>::new_gvariant(0));

mod attribute_value;
mod encrypted_item;
mod item;

pub use crate::portal::Error;
pub use attribute_value::AttributeValue;
pub use encrypted_item::EncryptedItem;
pub use item::Item;

use crate::Key;

/// Logical contents of a keyring file
#[derive(Deserialize, Serialize, Type, Debug)]
pub struct Keyring {
    salt_size: u32,
    salt: Vec<u8>,
    iteration_count: u32,
    modified_time: u64,
    pub usage_count: u32,
    pub items: Vec<EncryptedItem>,
}

impl Keyring {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>().to_vec();

        Self {
            salt_size: salt.len() as u32,
            salt,
            iteration_count: ITERATION_COUNT,
            // TODO: UTC?
            modified_time: std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .unwrap()
                .as_secs(),
            usage_count: 0,
            items: Vec::new(),
        }
    }

    /// Load from a keyring file
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = async_std::fs::read(path).await?;
        Self::try_from(content.as_slice())
    }

    /// Write to a keyring file
    pub async fn dump<P: AsRef<Path>>(
        &self,
        path: P,
        mtime: Option<std::time::SystemTime>,
    ) -> Result<(), Error> {
        let tmp_path = if let Some(parent) = path.as_ref().parent() {
            let rnd: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            let mut tmp_path = parent.to_path_buf();
            tmp_path.push(format!(".tmpkeyring{}", rnd));

            if !parent.exists().await {
                fs::DirBuilder::new().recursive(true).create(parent).await?;
            }

            Ok(tmp_path)
        } else {
            Err(Error::NoParentDir(path.as_ref().display().to_string()))
        }?;

        let mut tmpfile_builder = fs::OpenOptions::new();

        tmpfile_builder.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            tmpfile_builder.mode(0o600);
        }
        let mut tmpfile = tmpfile_builder.open(&tmp_path).await?;

        let blob = self.as_bytes()?;

        tmpfile.write_all(&blob).await?;
        tmpfile.sync_all().await?;

        let target_file = fs::File::open(&path).await;

        let target_mtime = match target_file {
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err.into()),
            Ok(file) => file.metadata().await?.modified().ok(),
        };

        if mtime != target_mtime {
            return Err(Error::TargetFileChanged(
                path.as_ref().display().to_string(),
            ));
        }

        fs::rename(tmp_path, path).await?;

        Ok(())
    }

    pub fn search_items(
        &self,
        attributes: HashMap<impl AsRef<str>, impl AsRef<str>>,
        key: &Key,
    ) -> Result<Vec<Item>, Error> {
        let hashed_search = hash_attributes(attributes, key);

        self.items
            .iter()
            .filter(|e| {
                hashed_search.iter().all(|(search_key, search_hash)| {
                    e.hashed_attributes.get(search_key.as_ref()) == Some(search_hash)
                })
            })
            .map(|e| (*e).clone().decrypt(key))
            .collect()
    }

    pub fn remove_items(
        &mut self,
        attributes: HashMap<impl AsRef<str>, impl AsRef<str>>,
        key: &Key,
    ) -> Result<(), Error> {
        let hashed_search = hash_attributes(attributes, key);

        let (remove, keep): (Vec<EncryptedItem>, _) =
            self.items.clone().into_iter().partition(|e| {
                hashed_search.iter().all(|(search_key, search_hash)| {
                    e.hashed_attributes.get(search_key.as_ref()) == Some(search_hash)
                })
            });

        // check hashes for the ones to be removed
        for item in remove {
            item.decrypt(key)?;
        }

        self.items = keep;

        Ok(())
    }

    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut blob = FILE_HEADER.to_vec();

        blob.push(MAJOR_VERSION);
        blob.push(MINOR_VERSION);
        blob.append(&mut zvariant::to_bytes(*GVARIANT_ENCODING, &self)?);

        Ok(blob)
    }

    pub fn default_path() -> Result<PathBuf, Error> {
        if let Some(mut path) = dirs::data_dir() {
            path.push("keyrings");
            path.push("default.keyring");
            Ok(path)
        } else {
            Err(Error::NoDataDir)
        }
    }

    pub fn derive_key(&self, secret: &[u8]) -> Key {
        let mut key = Key(vec![0; EncAlg::block_size()]);

        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            secret,
            &self.salt,
            self.iteration_count,
            key.as_mut(),
        );

        key
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let header = value.get(..FILE_HEADER.len());
        if header != Some(FILE_HEADER) {
            return Err(Error::FileHeaderMismatch(
                header.map(|x| String::from_utf8_lossy(x).to_string()),
            ));
        }

        let version = value.get(FILE_HEADER_LEN..(FILE_HEADER_LEN + 2));
        if version != Some(&[MAJOR_VERSION, MINOR_VERSION]) {
            return Err(Error::VersionMismatch(version.map(|x| x.to_vec())));
        }

        if let Some(data) = value.get((FILE_HEADER_LEN + 2)..) {
            Ok(zvariant::from_slice(data, *GVARIANT_ENCODING)?)
        } else {
            Err(Error::NoData)
        }
    }
}

pub fn hash_attributes<K: AsRef<str>>(
    attributes: HashMap<K, impl AsRef<str>>,
    key: &Key,
) -> Vec<(K, Vec<u8>)> {
    attributes
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                AttributeValue::from(v.as_ref())
                    .mac(key)
                    .into_bytes()
                    .as_slice()
                    .to_vec(),
            )
        })
        .collect()
}
