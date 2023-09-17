//! File backend implementation backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret).
//!
//! ```no_run
//! use std::collections::HashMap;
//!
//! use oo7::portal::Keyring;
//!
//! # async fn run() -> oo7::Result<()> {
//! let keyring = Keyring::load_default().await?;
//! keyring
//!     .create_item(
//!         "My Label",
//!         &HashMap::from([("account", "alice")]),
//!         b"My Password",
//!         true,
//!     )
//!     .await?;
//!
//! let items = keyring
//!     .search_items(&HashMap::from([("account", "alice")]))
//!     .await?;
//! assert_eq!(*items[0].secret(), b"My Password");
//!
//! keyring
//!     .delete(&HashMap::from([("account", "alice")]))
//!     .await?;
//! #   Ok(())
//! # }
//! ```

#[cfg(feature = "async-std")]
use std::io;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "async-std")]
use async_fs as fs;
#[cfg(feature = "async-std")]
use async_lock::{Mutex, RwLock};
#[cfg(feature = "async-std")]
use futures_lite::AsyncReadExt;
use once_cell::sync::OnceCell;
#[cfg(feature = "tokio")]
use tokio::{
    fs, io,
    io::AsyncReadExt,
    sync::{Mutex, RwLock},
};
use zeroize::Zeroizing;

use crate::{AsAttributes, Key};

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

pub(crate) use api::AttributeValue;

mod error;
mod item;
mod secret;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use item::Item;
pub use secret::Secret;
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub use secret::SecretProxy;

type ItemDefinition = (String, HashMap<String, String>, Zeroizing<Vec<u8>>, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct Keyring {
    keyring: Arc<RwLock<api::Keyring>>,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Mutex<Option<std::time::SystemTime>>,
    key: OnceCell<Key>,
    secret: Arc<Secret>,
}

impl Keyring {
    /// Load from default keyring file
    pub async fn load_default() -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Loading default keyring file");
        let secret = secret::retrieve().await?;
        Self::load(api::Keyring::default_path()?, secret).await
    }

    /// Load from a keyring file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file backend.
    /// * `secret` - The service key, usually retrieved from the Secrets portal.
    pub async fn load(path: impl AsRef<Path>, secret: Secret) -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Trying to load keyring file at {:?}", path.as_ref());
        let (mtime, keyring) = match fs::File::open(path.as_ref()).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Keyring file not found, creating a new one");
                (None, api::Keyring::new())
            }
            Err(err) => return Err(err.into()),
            Ok(mut file) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Keyring file found, loading it content");
                let mtime = file.metadata().await?.modified().ok();

                let mut content = Vec::new();
                file.read_to_end(&mut content).await?;

                let keyring = api::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        Ok(Self {
            keyring: Arc::new(RwLock::new(keyring)),
            path: path.as_ref().to_path_buf(),
            mtime: Mutex::new(mtime),
            key: Default::default(),
            secret: Arc::new(secret),
        })
    }

    /// Retrieve the number of items
    ///
    /// This function will not trigger a key derivation and can therefore be
    /// faster than [`items().len()`](Self::items).
    pub async fn n_items(&self) -> usize {
        self.keyring.read().await.items.len()
    }

    /// Retrieve the list of available [`Item`]s.
    ///
    /// If items cannot be decrypted, [`InvalidItemError`]s are returned for
    /// them instead of [`Item`]s.
    pub async fn items(&self) -> Vec<Result<Item, InvalidItemError>> {
        let key = self.derive_key().await;
        let keyring = self.keyring.read().await;
        keyring
            .items
            .iter()
            .map(|e| {
                (*e).clone().decrypt(key).map_err(|err| {
                    InvalidItemError::new(
                        err,
                        e.hashed_attributes.keys().map(|x| x.to_string()).collect(),
                    )
                })
            })
            .collect()
    }

    /// Search items matching the attributes.
    pub async fn search_items(&self, attributes: &impl AsAttributes) -> Result<Vec<Item>, Error> {
        let key = self.derive_key().await;
        let keyring = self.keyring.read().await;
        keyring.search_items(attributes, key)
    }

    /// Find the first item matching the attributes.
    pub async fn lookup_item(&self, attributes: &impl AsAttributes) -> Result<Option<Item>, Error> {
        let key = self.derive_key().await;
        let keyring = self.keyring.read().await;
        keyring.lookup_item(attributes, key)
    }

    /// Delete an item.
    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        {
            let key = self.derive_key().await;
            let mut keyring = self.keyring.write().await;
            keyring.remove_items(attributes, key)?;
        };
        self.write().await
    }

    /// Create a new item
    ///
    /// # Arguments
    ///
    /// * `label` - A user visible label of the item.
    /// * `attributes` - A map of key/value attributes, used to find the item
    ///   later.
    /// * `secret` - The secret to store.
    /// * `replace` - Whether to replace the value if the `attributes` matches
    ///   an existing `secret`.
    pub async fn create_item(
        &self,
        label: &str,
        attributes: &impl AsAttributes,
        secret: impl AsRef<[u8]>,
        replace: bool,
    ) -> Result<Item, Error> {
        let item = {
            let key = self.derive_key().await;
            let mut keyring = self.keyring.write().await;
            if replace {
                keyring.remove_items(attributes, key)?;
            }
            let item = Item::new(label, attributes, secret);
            let encrypted_item = item.encrypt(key)?;
            keyring.items.push(encrypted_item);
            item
        };
        match self.write().await {
            Err(e) => Err(e),
            Ok(_) => Ok(item),
        }
    }

    /// Replaces item at the given index.
    ///
    /// The `index` refers to the index of the [`Vec`] returned by
    /// [`items()`](Self::items). If the index does not exist, the functions
    /// returns an error.
    pub async fn replace_item_index(&self, index: usize, item: &Item) -> Result<(), Error> {
        {
            let key = self.derive_key().await;
            let mut keyring = self.keyring.write().await;

            if let Some(item_store) = keyring.items.get_mut(index) {
                *item_store = item.encrypt(key)?;
            } else {
                return Err(Error::InvalidItemIndex(index));
            }
        }
        self.write().await
    }

    /// Deletes item at the given index.
    ///
    /// The `index` refers to the index of the [`Vec`](Vec) returned by
    /// [`items()`](Self::items). If the index does not exist, the functions
    /// returns an error.
    pub async fn delete_item_index(&self, index: usize) -> Result<(), Error> {
        {
            let mut keyring = self.keyring.write().await;

            if index < keyring.items.len() {
                keyring.items.remove(index);
            } else {
                return Err(Error::InvalidItemIndex(index));
            }
        }
        self.write().await
    }

    /// Helper used for migration to avoid re-writing the file multiple times
    pub(crate) async fn create_items(&self, items: Vec<ItemDefinition>) -> Result<(), Error> {
        let key = self.derive_key().await;
        let mut keyring = self.keyring.write().await;
        for (label, attributes, secret, replace) in items {
            if replace {
                keyring.remove_items(&attributes, key)?;
            }
            let item = Item::new(label, &attributes, &*secret);
            let encrypted_item = item.encrypt(key)?;
            keyring.items.push(encrypted_item);
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file");
        keyring.dump(&self.path, *self.mtime.lock().await).await?;

        Ok(())
    }

    /// Write the changes to the keyring file.
    pub async fn write(&self) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file {:?}", self.path);
        let mut mtime = self.mtime.lock().await;
        {
            let mut keyring = self.keyring.write().await;
            #[cfg(feature = "tracing")]
            tracing::debug!("Current modified time {:?}", mtime);
            keyring.dump(&self.path, *mtime).await?;
        };
        if let Ok(modified) = fs::metadata(&self.path).await?.modified() {
            #[cfg(feature = "tracing")]
            tracing::debug!("New modified time {:?}", modified);
            *mtime = Some(modified);
        }
        Ok(())
    }

    /// Return key, derive and store it first if not initialized
    async fn derive_key(&self) -> &Key {
        if self.key.get().is_none() {
            let key = self.keyring.read().await.derive_key(&self.secret);
            self.key.set(key).unwrap();
        }
        self.key.get().unwrap()
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use super::*;

    #[tokio::test]
    async fn repeated_write() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/test.keyring");

        let secret = Secret::from(vec![1, 2]);
        let keyring = Keyring::load(&path, secret).await?;

        keyring.write().await?;
        keyring.write().await?;

        Ok(())
    }

    #[tokio::test]
    async fn delete() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/test-delete.keyring");

        let keyring = Keyring::load(&path, strong_key()).await?;
        let attributes: HashMap<&str, &str> = HashMap::default();
        keyring
            .create_item("Label", &attributes, "secret", false)
            .await?;

        keyring.delete_item_index(0).await?;

        let result = keyring.delete_item_index(100).await;

        assert!(matches!(result, Err(Error::InvalidItemIndex(100))));

        Ok(())
    }

    #[tokio::test]
    async fn write_with_weak_key() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/write_with_weak_key.keyring");

        let secret = Secret::from(vec![1, 2]);
        let keyring = Keyring::load(&path, secret).await?;
        let attributes: HashMap<&str, &str> = HashMap::default();

        let result = keyring
            .create_item("label", &attributes, "my-password", false)
            .await;

        assert!(matches!(
            result,
            Err(Error::WeakKey(WeakKeyError::PasswordTooShort(2)))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn write_with_strong_key() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/write_with_strong_key.keyring");

        let keyring = Keyring::load(&path, strong_key()).await?;
        let attributes: HashMap<&str, &str> = HashMap::default();

        keyring
            .create_item("label", &attributes, "my-password", false)
            .await?;

        Ok(())
    }

    fn strong_key() -> Secret {
        Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>())
    }

    #[tokio::test]
    async fn concurrent_writes() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/concurrent_writes.keyring");

        let keyring = Arc::new(Keyring::load(&path, strong_key()).await?);

        let keyring_clone = keyring.clone();
        let handle_1 = tokio::task::spawn(async move { keyring_clone.write().await });
        let handle_2 = tokio::task::spawn(async move { keyring.write().await });

        let (res_1, res_2) = futures_util::future::join(handle_1, handle_2).await;
        res_1.unwrap()?;
        res_2.unwrap()?;

        Ok(())
    }
}
