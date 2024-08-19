//! File backend implementation backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
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

type ItemDefinition = (String, HashMap<String, String>, Zeroizing<Vec<u8>>, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct Keyring {
    keyring: Arc<RwLock<api::Keyring>>,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Mutex<Option<std::time::SystemTime>>,
    key: Mutex<Option<Arc<Key>>>,
    secret: Mutex<Arc<Secret>>,
}

impl Keyring {
    /// Load from default keyring file
    pub async fn load_default() -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Loading default keyring file");
        let secret = Secret::from(ashpd::desktop::secret::retrieve().await?);
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
            secret: Mutex::new(Arc::new(secret)),
        })
    }

    async fn migrate(
        file: &mut fs::File,
        path: impl AsRef<Path>,
        secret: Secret,
    ) -> Result<Self, Error> {
        let mut content = Vec::new();
        file.read_to_end(&mut content).await?;

        match api::Keyring::try_from(content.as_slice()) {
            Ok(keyring) => Ok(Self {
                keyring: Arc::new(RwLock::new(keyring)),
                path: path.as_ref().to_path_buf(),
                mtime: Default::default(),
                key: Default::default(),
                secret: Mutex::new(Arc::new(secret)),
            }),
            Err(Error::VersionMismatch(Some(version)))
                if version[0] == api::LEGACY_MAJOR_VERSION =>
            {
                #[cfg(feature = "tracing")]
                tracing::debug!("Migrating from legacy keyring format");

                let legacy_keyring = api::LegacyKeyring::try_from(content.as_slice())?;
                let mut keyring = api::Keyring::new();
                let key = keyring.derive_key(&secret);

                for item in legacy_keyring.decrypt_items(&secret)? {
                    let encrypted_item = item.encrypt(&key)?;
                    keyring.items.push(encrypted_item);
                }

                Ok(Self {
                    keyring: Arc::new(RwLock::new(keyring)),
                    path: path.as_ref().to_path_buf(),
                    mtime: Default::default(),
                    key: Default::default(),
                    secret: Mutex::new(Arc::new(secret)),
                })
            }
            Err(err) => Err(err),
        }
    }

    /// Open a keyring with given name from the default directory.
    ///
    /// This function will automatically migrate the keyring to the
    /// latest format.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the keyring.
    /// * `secret` - The service key, usually retrieved from the Secrets portal.
    pub async fn open(name: &str, secret: Secret) -> Result<Self, Error> {
        let v1_path = api::Keyring::path(name, api::MAJOR_VERSION)?;
        if v1_path.exists() {
            return Keyring::load(v1_path, secret).await;
        }

        let v0_path = api::Keyring::path(name, api::LEGACY_MAJOR_VERSION)?;
        if v0_path.exists() {
            #[cfg(feature = "tracing")]
            tracing::debug!("Trying to load keyring file at {:?}", v0_path);
            match fs::File::open(&v0_path).await {
                Err(err) => Err(err.into()),
                Ok(mut file) => Self::migrate(&mut file, v1_path, secret).await,
            }
        } else {
            Ok(Self {
                keyring: Arc::new(RwLock::new(api::Keyring::new())),
                path: v1_path,
                mtime: Default::default(),
                key: Default::default(),
                secret: Mutex::new(Arc::new(secret)),
            })
        }
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
                (*e).clone().decrypt(&key).map_err(|err| {
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
        keyring.search_items(attributes, &key)
    }

    /// Find the first item matching the attributes.
    pub async fn lookup_item(&self, attributes: &impl AsAttributes) -> Result<Option<Item>, Error> {
        let key = self.derive_key().await;
        let keyring = self.keyring.read().await;
        keyring.lookup_item(attributes, &key)
    }

    /// Find the index in the list of items of the first item matching the
    /// attributes.
    pub async fn lookup_item_index(&self, attributes: &impl AsAttributes) -> Option<usize> {
        let key = self.derive_key().await;
        let keyring = self.keyring.read().await;
        keyring.lookup_item_index(attributes, &key)
    }

    /// Delete an item.
    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        {
            let key = self.derive_key().await;
            let mut keyring = self.keyring.write().await;
            keyring.remove_items(attributes, &key)?;
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
                keyring.remove_items(attributes, &key)?;
            }
            let item = Item::new(label, attributes, secret);
            let encrypted_item = item.encrypt(&key)?;
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
                *item_store = item.encrypt(&key)?;
            } else {
                return Err(Error::InvalidItemIndex(index));
            }
        }
        self.write().await
    }

    /// Deletes item at the given index.
    ///
    /// The `index` refers to the index of the [`Vec`] returned by
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
                keyring.remove_items(&attributes, &key)?;
            }
            let item = Item::new(label, &attributes, &*secret);
            let encrypted_item = item.encrypt(&key)?;
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
    async fn derive_key(&self) -> Arc<Key> {
        let keyring = Arc::clone(&self.keyring);
        let secret_lock = self.secret.lock().await;
        let secret = Arc::clone(&secret_lock);
        drop(secret_lock);

        let mut key_lock = self.key.lock().await;
        if key_lock.is_none() {
            #[cfg(feature = "async-std")]
            let key = blocking::unblock(move || {
                async_io::block_on(async { keyring.read().await.derive_key(&secret) })
            })
            .await;
            #[cfg(feature = "tokio")]
            let key =
                tokio::task::spawn_blocking(move || keyring.blocking_read().derive_key(&secret))
                    .await
                    .unwrap();

            *key_lock = Some(Arc::new(key));
        }

        Arc::clone(key_lock.as_ref().unwrap())
    }

    /// Change keyring secret
    ///
    /// # Arguments
    ///
    /// * `secret` - The new secret to store.
    pub async fn change_secret(&self, secret: Secret) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Changing keyring secret and key");

        let keyring = self.keyring.read().await;
        let key = self.derive_key().await;
        let mut items = Vec::with_capacity(keyring.items.len());
        for item in &keyring.items {
            items.push(item.clone().decrypt(&key)?);
        }
        drop(keyring);

        let mut secret_lock = self.secret.lock().await;
        *secret_lock = Arc::new(secret);
        drop(secret_lock);

        let mut key_lock = self.key.lock().await;
        // Unset the old key
        *key_lock = None;
        drop(key_lock);

        // Reset Keyring content before setting the new key
        let mut keyring = self.keyring.write().await;
        keyring.reset();
        drop(keyring);

        // Set new key
        let key = self.derive_key().await;

        let mut keyring = self.keyring.write().await;
        for item in items {
            let encrypted_item = item.encrypt(&key)?;
            keyring.items.push(encrypted_item);
        }
        drop(keyring);

        self.write().await
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use tempfile::tempdir;

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

    async fn check_items(keyring: &Keyring) -> Result<(), Error> {
        assert_eq!(keyring.n_items().await, 1);
        let items: Result<Vec<_>, _> = keyring.items().await.into_iter().collect();
        let items = items.expect("unable to retrieve items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "foo");
        assert_eq!(items[0].secret().as_ref(), b"foo".to_vec());
        let attributes = items[0].attributes();
        assert_eq!(attributes.len(), 1);
        assert_eq!(
            attributes.get("xdg:schema").map(|v| v.as_ref()),
            Some("org.gnome.keyring.Note")
        );

        Ok(())
    }

    #[tokio::test]
    async fn migrate_from_legacy() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("legacy.keyring");
        fs::copy(&fixture_path, &v0_dir.join("default.keyring")).await?;

        std::env::set_var("XDG_DATA_HOME", &data_dir.path());

        assert!(!v1_dir.join("default.keyring").exists());

        let password = b"test";
        let secret = Secret::from(password.to_vec());
        let keyring = Keyring::open("default", secret).await?;

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn migrate() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        fs::copy(&fixture_path, &v0_dir.join("default.keyring")).await?;

        std::env::set_var("XDG_DATA_HOME", &data_dir.path());

        let password = b"test";
        let secret = Secret::from(password.to_vec());
        let keyring = Keyring::open("default", secret).await?;

        assert!(!v1_dir.join("default.keyring").exists());

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn open() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        fs::copy(&fixture_path, &v1_dir.join("default.keyring")).await?;

        std::env::set_var("XDG_DATA_HOME", &data_dir.path());

        let password = b"test";
        let secret = Secret::from(password.to_vec());
        let keyring = Keyring::open("default", secret).await?;

        assert!(v1_dir.join("default.keyring").exists());

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn open_nonexistent() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        std::env::set_var("XDG_DATA_HOME", &data_dir.path());

        let password = b"test";
        let secret = Secret::from(password.to_vec());
        let keyring = Keyring::open("default", secret).await?;

        assert!(!v1_dir.join("default.keyring").exists());

        keyring
            .create_item(
                "foo",
                &HashMap::from([("xdg:schema", "org.gnome.keyring.Note")]),
                b"foo",
                false,
            )
            .await?;
        keyring.write().await?;

        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn change_secret() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/test_rekeying.keyring");

        let keyring = Keyring::load(&path, strong_key()).await?;
        let attributes = HashMap::from([("attr", "value")]);
        let item_before = keyring
            .create_item("test", &attributes, "password", false)
            .await?;

        let new_secret = Secret::from(b"password".to_vec());
        keyring.change_secret(new_secret).await?;

        let new_secret = Secret::from(b"password".to_vec());
        let keyring = Keyring::load(&path, new_secret).await?;
        let item_now = keyring.lookup_item(&attributes).await?.unwrap();

        assert_eq!(item_before.label(), item_now.label());
        assert_eq!(item_before.secret(), item_now.secret());
        assert_eq!(item_before.attributes(), item_now.attributes());

        fs::remove_file(path).await?;

        Ok(())
    }
}
