//! GNOME Keyring file format low level API.

// TODO:
// - Order user calls
// - Keep proxis around
// - Make more things async

#[cfg(feature = "async-std")]
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "async-std")]
use async_fs as fs;
#[cfg(feature = "async-std")]
use async_fs::unix::OpenOptionsExt;
#[cfg(feature = "async-std")]
use futures_lite::AsyncWriteExt;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "tokio")]
use tokio::{fs, io, io::AsyncWriteExt};
use zbus::zvariant::{self, Type};

/// Used for newly created [`Keyring`]s
const DEFAULT_ITERATION_COUNT: u32 = 100000;
/// Used for newly created [`Keyring`]s
const DEFAULT_SALT_SIZE: usize = 32;

const MIN_ITERATION_COUNT: u32 = 100000;
const MIN_SALT_SIZE: usize = 32;
const MIN_PASSWORD_LENGTH: usize = 64;

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

pub(super) static GVARIANT_ENCODING: Lazy<zvariant::EncodingContext<byteorder::LE>> =
    Lazy::new(|| zvariant::EncodingContext::<byteorder::LE>::new_gvariant(0));

mod attribute_value;
mod encrypted_item;

pub use attribute_value::AttributeValue;
pub(super) use encrypted_item::EncryptedItem;

use super::{Item, Secret};
use crate::{
    crypto,
    portal::{Error, WeakKeyError},
    AsAttributes, Key,
};

/// Logical contents of a keyring file
#[derive(Deserialize, Serialize, Type, Debug)]
pub struct Keyring {
    salt_size: u32,
    salt: Vec<u8>,
    iteration_count: u32,
    modified_time: u64,
    usage_count: u32,
    pub(in crate::portal) items: Vec<EncryptedItem>,
}

impl Keyring {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        let salt = rand::thread_rng().gen::<[u8; DEFAULT_SALT_SIZE]>().to_vec();

        Self {
            salt_size: salt.len() as u32,
            salt,
            iteration_count: DEFAULT_ITERATION_COUNT,
            // TODO: UTC?
            modified_time: std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .unwrap()
                .as_secs(),
            usage_count: 0,
            items: Vec::new(),
        }
    }

    pub fn key_strength(&self, secret: &[u8]) -> Result<(), WeakKeyError> {
        if self.iteration_count < MIN_ITERATION_COUNT {
            Err(WeakKeyError::IterationCountTooLow(self.iteration_count))
        } else if self.salt.len() < MIN_SALT_SIZE {
            Err(WeakKeyError::SaltTooShort(self.salt.len()))
        } else if secret.len() < MIN_PASSWORD_LENGTH {
            Err(WeakKeyError::PasswordTooShort(secret.len()))
        } else {
            Ok(())
        }
    }

    /// Write to a keyring file
    pub async fn dump(
        &mut self,
        path: impl AsRef<Path>,
        mtime: Option<std::time::SystemTime>,
    ) -> Result<(), Error> {
        let tmp_path = if let Some(parent) = path.as_ref().parent() {
            let rnd: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            let mut tmp_path = parent.to_path_buf();
            tmp_path.push(format!(".tmpkeyring{rnd}"));

            if !parent.exists() {
                #[cfg(feature = "tracing")]
                tracing::debug!("Parent directory {:?} doesn't exists, creating it", parent);
                fs::DirBuilder::new().recursive(true).create(parent).await?;
            }

            Ok(tmp_path)
        } else {
            Err(Error::NoParentDir(path.as_ref().display().to_string()))
        }?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            "Created a temporary file to store the keyring on {:?}",
            tmp_path
        );

        let mut tmpfile_builder = fs::OpenOptions::new();

        tmpfile_builder.write(true).create_new(true);
        tmpfile_builder.mode(0o600);
        let mut tmpfile = tmpfile_builder.open(&tmp_path).await?;

        self.modified_time = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();
        self.usage_count += 1;

        let blob = self.as_bytes()?;

        tmpfile.write_all(&blob).await?;
        tmpfile.sync_all().await?;

        let target_file = fs::File::open(path.as_ref()).await;

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

        fs::rename(tmp_path, path.as_ref()).await?;

        Ok(())
    }

    pub fn search_items(
        &self,
        attributes: &impl AsAttributes,
        key: &Key,
    ) -> Result<Vec<Item>, Error> {
        let hashed_search = attributes.hash(key);

        self.items
            .iter()
            .filter(|e| hashed_search.iter().all(|(k, v)| e.has_attribute(k, v)))
            .map(|e| (*e).clone().decrypt(key))
            .collect()
    }

    pub fn lookup_item(
        &self,
        attributes: &impl AsAttributes,
        key: &Key,
    ) -> Result<Option<Item>, Error> {
        let hashed_search = attributes.hash(key);

        self.items
            .iter()
            .find(|e| hashed_search.iter().all(|(k, v)| e.has_attribute(k, v)))
            .map(|e| (*e).clone().decrypt(key))
            .transpose()
    }

    pub fn remove_items(&mut self, attributes: &impl AsAttributes, key: &Key) -> Result<(), Error> {
        let hashed_search = attributes.hash(key);

        let (remove, keep): (Vec<EncryptedItem>, _) = self
            .items
            .clone()
            .into_iter()
            .partition(|e| hashed_search.iter().all(|(k, v)| e.has_attribute(k, v)));

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
        if let Some(mut path) = crate::helpers::data_dir() {
            path.push("keyrings");
            path.push("default.keyring");
            Ok(path)
        } else {
            Err(Error::NoDataDir)
        }
    }

    pub fn derive_key(&self, secret: &Secret) -> Key {
        crypto::derive_key(
            &**secret,
            self.key_strength(secret),
            &self.salt,
            self.iteration_count.try_into().unwrap(),
        )
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
            let keyring: Self = zvariant::from_slice(data, *GVARIANT_ENCODING)?;

            if keyring.salt.len() != keyring.salt_size as usize {
                Err(Error::SaltSizeMismatch(
                    keyring.salt.len(),
                    keyring.salt_size,
                ))
            } else {
                Ok(keyring)
            }
        } else {
            Err(Error::NoData)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SECRET: [u8; 64] = [
        44, 173, 251, 20, 203, 56, 241, 169, 91, 54, 51, 244, 40, 40, 202, 92, 71, 233, 174, 17,
        145, 58, 7, 107, 31, 204, 175, 245, 112, 174, 31, 198, 162, 149, 13, 127, 119, 113, 13, 3,
        191, 143, 162, 153, 183, 7, 21, 116, 81, 45, 51, 198, 73, 127, 147, 40, 52, 25, 181, 188,
        48, 159, 0, 146,
    ];

    #[tokio::test]
    async fn keyfile_add_remove() -> Result<(), Error> {
        let needle = HashMap::from([("key", "value")]);

        let mut keyring = Keyring::new();
        let key = keyring.derive_key(&SECRET.to_vec().into());

        keyring
            .items
            .push(Item::new("Label", &needle, b"MyPassword").encrypt(&key)?);

        assert_eq!(keyring.search_items(&needle, &key)?.len(), 1);

        keyring.remove_items(&needle, &key)?;

        assert_eq!(keyring.search_items(&needle, &key)?.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn keyfile_dump_load() -> Result<(), Error> {
        let _silent = std::fs::remove_file("/tmp/test.keyring");

        let mut new_keyring = Keyring::new();
        let key = new_keyring.derive_key(&SECRET.to_vec().into());

        new_keyring.items.push(
            Item::new(
                "My Label",
                &HashMap::from([("my-tag", "my tag value")]),
                "A Password".as_bytes(),
            )
            .encrypt(&key)?,
        );
        new_keyring.dump("/tmp/test.keyring", None).await?;

        let blob = tokio::fs::read("/tmp/test.keyring").await?;

        let loaded_keyring = Keyring::try_from(blob.as_slice())?;
        let loaded_items =
            loaded_keyring.search_items(&HashMap::from([("my-tag", "my tag value")]), &key)?;

        assert_eq!(*loaded_items[0].secret(), "A Password".as_bytes());

        let _silent = std::fs::remove_file("/tmp/test.keyring");

        Ok(())
    }
}
