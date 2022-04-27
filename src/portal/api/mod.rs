/*!
GNOME Keyring file format low level API.
*/

/*
TODO:
- Order user calls
- Keep proxis around
- Make more things async
*/

#[cfg(feature = "async-std")]
use async_std::{fs, io, prelude::*};
#[cfg(feature = "tokio")]
#[cfg(not(feature = "async-std"))]
use tokio::{fs, io, io::AsyncWriteExt};

use std::os::unix::fs::OpenOptionsExt;

use cipher::BlockSizeUser;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zbus::zvariant::{self, Type};

const SALT_SIZE: usize = 32;
const ITERATION_COUNT: u32 = 100000;

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

type MacAlg = hmac::Hmac<sha2::Sha256>;
type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

static GVARIANT_ENCODING: Lazy<zvariant::EncodingContext<byteorder::LE>> =
    Lazy::new(|| zvariant::EncodingContext::<byteorder::LE>::new_gvariant(0));

mod attribute_value;
mod encrypted_item;
mod item;

pub use crate::portal::Error;
pub use attribute_value::AttributeValue;
pub use item::Item;

use crate::Key;
use encrypted_item::EncryptedItem;

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

            if !parent.exists() {
                #[cfg(feature = "tracing")]
                tracing::debug!("Parent directory {:?} deosn't exists, creating it", parent);
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

fn hash_attributes<K: AsRef<str>>(
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

#[cfg(test)]
#[cfg(feature = "async-std")]
mod tests {
    use super::*;

    const SECRET: [u8; 64] = [
        44, 173, 251, 20, 203, 56, 241, 169, 91, 54, 51, 244, 40, 40, 202, 92, 71, 233, 174, 17,
        145, 58, 7, 107, 31, 204, 175, 245, 112, 174, 31, 198, 162, 149, 13, 127, 119, 113, 13, 3,
        191, 143, 162, 153, 183, 7, 21, 116, 81, 45, 51, 198, 73, 127, 147, 40, 52, 25, 181, 188,
        48, 159, 0, 146,
    ];

    #[async_std::test]
    async fn keyfile_add_remove() -> Result<(), Error> {
        let needle = HashMap::from([(String::from("key"), String::from("value"))]);

        let mut keyring = Keyring::new();
        let key = keyring.derive_key(&SECRET);

        keyring
            .items
            .push(Item::new(String::from("Label"), needle.clone(), b"MyPassword").encrypt(&key)?);

        assert_eq!(keyring.search_items(needle.clone(), &key)?.len(), 1);

        keyring.remove_items(needle.clone(), &key)?;

        assert_eq!(keyring.search_items(needle, &key)?.len(), 0);

        Ok(())
    }

    #[async_std::test]
    async fn keyfile_dump_load() -> Result<(), Error> {
        let _silent = std::fs::remove_file("/tmp/test.keyring");

        let mut new_keyring = Keyring::new();
        let key = new_keyring.derive_key(&SECRET);

        new_keyring.items.push(
            Item::new(
                String::from("My Label"),
                HashMap::from([(String::from("my-tag"), String::from("my tag value"))]),
                "A Password".as_bytes(),
            )
            .encrypt(&key)?,
        );
        new_keyring.dump("/tmp/test.keyring", None).await?;

        let blob = async_std::fs::read("/tmp/test.keyring").await?;

        let loaded_keyring = Keyring::try_from(blob.as_slice())?;
        let loaded_items =
            loaded_keyring.search_items(HashMap::from([("my-tag", "my tag value")]), &key)?;

        assert_eq!(*loaded_items[0].secret(), "A Password".as_bytes());

        let _silent = std::fs::remove_file("/tmp/test.keyring");

        Ok(())
    }
}
