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
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::Error;

const SALT_SIZE: usize = 32;
const ITERATION_COUNT: u32 = 100000;

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

type MacAlg = hmac::Hmac<sha2::Sha256>;
type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

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
            modified_time: now(),
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
        blob.append(&mut zvariant::to_bytes(gvariant_encoding(), &self)?);

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
            Ok(zvariant::from_slice(data, gvariant_encoding())?)
        } else {
            Err(Error::NoData)
        }
    }
}

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub struct EncryptedItem {
    pub hashed_attributes: HashMap<String, Vec<u8>>,
    pub blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn decrypt(mut self, key: &Key) -> Result<Item, Error> {
        let mac_tag = self.blob.split_off(self.blob.len() - MacAlg::output_size());

        // verify item
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(&self.blob);
        mac.verify_slice(&mac_tag)?;

        let iv = self.blob.split_off(self.blob.len() - DecAlg::iv_size());
        let mut data = Zeroizing::new(self.blob);

        // decrypt item
        let decrypted = DecAlg::new(key.as_ref().into(), iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .unwrap();

        let item = Item::try_from(decrypted)?;

        Self::validate(&self.hashed_attributes, &item, key)?;

        Ok(item)
    }

    fn validate(
        hashed_attributes: &HashMap<String, Vec<u8>>,
        item: &Item,
        key: &Key,
    ) -> Result<(), Error> {
        for (attribute_key, hashed_attribute) in hashed_attributes.iter() {
            if let Some(attribute_plaintext) = item.attributes.get(attribute_key) {
                let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
                mac.update(attribute_plaintext.as_bytes());
                if mac.verify_slice(hashed_attribute).is_err() {
                    return Err(Error::HashedAttributeMac(attribute_key.to_string()));
                }
            } else {
                return Err(Error::HashedAttributeMac(attribute_key.to_string()));
            }
        }

        Ok(())
    }
}

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
        let now = now();

        Item {
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
        self.modified = now();
        self.label = label.to_string();
    }

    pub fn password(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.password.clone())
    }

    pub fn set_password<P: AsRef<[u8]>>(&mut self, password: P) {
        self.modified = now();
        self.password = password.as_ref().to_vec();
    }

    pub fn encrypt(&self, key: &Key) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(gvariant_encoding(), &self)?);

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
        Ok(zvariant::from_slice(value, gvariant_encoding())?)
    }
}

#[derive(Deserialize, Serialize, Type, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AttributeValue(String);

impl AttributeValue {
    pub fn mac(&self, key: &Key) -> digest::CtOutput<MacAlg> {
        let mut mac = MacAlg::new_from_slice(key.as_ref()).unwrap();
        mac.update(self.0.as_bytes());
        mac.finalize()
    }
}

impl<S: ToString> From<S> for AttributeValue {
    fn from(value: S) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for AttributeValue {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl std::ops::Deref for AttributeValue {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

/// AES key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key(Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
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

pub fn gvariant_encoding() -> zvariant::EncodingContext<byteorder::LE> {
    zvariant::EncodingContext::<byteorder::LE>::new_gvariant(0)
}

fn now() -> u64 {
    std::time::SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap()
        .as_secs()
}
