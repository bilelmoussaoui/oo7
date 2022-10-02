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
//!         HashMap::from([("account", "alice")]),
//!         b"My Password",
//!         true,
//!     )
//!     .await?;
//!
//! let items = keyring
//!     .search_items(HashMap::from([("account", "alice")]))
//!     .await?;
//! assert_eq!(*items[0].secret(), b"My Password");
//!
//! keyring
//!     .delete(HashMap::from([("account", "alice")]))
//!     .await?;
//! #   Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(feature = "async-std")]
use async_std::{fs, io, prelude::*, sync::RwLock};
use once_cell::sync::OnceCell;
#[cfg(feature = "tokio")]
use tokio::{fs, io, io::AsyncReadExt, sync::RwLock};

#[cfg(feature = "unstable")]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

mod error;
mod item;
mod secret;

pub use error::Error;
pub use item::Item;
pub use secret::Secret;
use zeroize::Zeroizing;

type ItemDefinition = (String, HashMap<String, String>, Zeroizing<Vec<u8>>, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct Keyring {
    keyring: RwLock<api::Keyring>,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: RwLock<Option<std::time::SystemTime>>,
    key: RwLock<OnceCell<crate::Key>>,
    secret: Secret,
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
            keyring: RwLock::new(keyring),
            path: path.as_ref().to_path_buf(),
            mtime: RwLock::new(mtime),
            key: Default::default(),
            secret,
        })
    }

    /// Retrieve the number of items
    ///
    /// This function will not trigger a key derivation.
    pub async fn n_items(&self) -> usize {
        self.keyring.read().await.items.len()
    }

    /// Retrieve the list of available [`Item`].
    pub async fn items(&self) -> Result<Vec<Item>, Error> {
        let keyring = self.keyring.read().await;
        let mut opt_key = self.key.write().await;
        let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
        keyring
            .items
            .iter()
            .map(|e| (*e).clone().decrypt(key))
            .collect()
    }

    /// Search items matching the attributes.
    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>, Error> {
        let keyring = self.keyring.read().await;
        let mut opt_key = self.key.write().await;
        let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
        keyring.search_items(attributes, key)
    }

    /// Find the first item matching the attributes.
    pub async fn lookup_item(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Option<Item>, Error> {
        let keyring = self.keyring.read().await;
        let mut opt_key = self.key.write().await;
        let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
        keyring.lookup_item(attributes, key)
    }

    /// Delete an item.
    pub async fn delete(&self, attributes: HashMap<&str, &str>) -> Result<(), Error> {
        {
            let mut keyring = self.keyring.write().await;
            let mut opt_key = self.key.write().await;
            let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
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
        attributes: HashMap<&str, &str>,
        secret: impl AsRef<[u8]>,
        replace: bool,
    ) -> Result<(), Error> {
        {
            let mut keyring = self.keyring.write().await;
            let mut opt_key = self.key.write().await;
            let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
            if replace {
                keyring.remove_items(attributes.clone(), key)?;
            }
            let item = Item::new(label, attributes, secret);
            let encrypted_item = item.encrypt(key)?;
            keyring.items.push(encrypted_item);
        };
        self.write().await
    }

    /// Helper used for migration to avoid re-writing the file multiple times
    pub(crate) async fn create_items(&self, items: Vec<ItemDefinition>) -> Result<(), Error> {
        let mut keyring = self.keyring.write().await;
        let mut opt_key = self.key.write().await;
        let key = derive_key(&mut opt_key, &keyring, &self.secret).await;
        for (label, attributes, secret, replace) in items {
            if replace {
                keyring.remove_items(attributes.clone(), key)?;
            }
            let item = Item::new(label, attributes, &*secret);
            let encrypted_item = item.encrypt(key)?;
            keyring.items.push(encrypted_item);
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file");
        keyring.dump(&self.path, *self.mtime.read().await).await?;

        Ok(())
    }

    /// Write the changes to the keyring file.
    pub async fn write(&self) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file {:?}", self.path);
        {
            let mtime = self.mtime.read().await;
            let mut keyring = self.keyring.write().await;
            #[cfg(feature = "tracing")]
            tracing::debug!("Current modified time {:?}", mtime);
            keyring.dump(&self.path, *mtime).await?;
        };
        if let Ok(modified) = fs::metadata(&self.path).await?.modified() {
            #[cfg(feature = "tracing")]
            tracing::debug!("New modified time {:?}", modified);
            self.mtime.write().await.replace(modified);
        }
        Ok(())
    }
}

/// Return key, derive and store it first if not initialized
async fn derive_key<'a>(
    key: &'a mut OnceCell<crate::Key>,
    keyring: &api::Keyring,
    secret: &Secret,
) -> &'a crate::Key {
    key.get_or_init(|| keyring.derive_key(secret))
}

#[cfg(test)]
#[cfg(feature = "async-std")]
mod tests {
    use super::*;

    #[async_std::test]
    async fn repeated_write() -> Result<(), Error> {
        let path = std::path::PathBuf::from("../../tests/test.keyring");

        let secret = Secret::from(vec![1, 2]);
        let keyring = Keyring::load(&path, secret).await?;

        keyring.write().await?;
        keyring.write().await?;

        Ok(())
    }
}
