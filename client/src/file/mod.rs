//! File backend implementation that can be backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
//!
//! ```no_run
//! use std::collections::HashMap;
//!
//! use oo7::file::UnlockedKeyring;
//!
//! # async fn run() -> oo7::Result<()> {
//! let keyring = UnlockedKeyring::load_default().await?;
//! keyring
//!     .create_item(
//!         "My Label",
//!         &HashMap::from([("account", "alice")]),
//!         "My Password",
//!         true,
//!     )
//!     .await?;
//!
//! let items = keyring
//!     .search_items(&HashMap::from([("account", "alice")]))
//!     .await?;
//! assert_eq!(items[0].secret(), oo7::Secret::blob("My Password"));
//!
//! keyring
//!     .delete(&HashMap::from([("account", "alice")]))
//!     .await?;
//! #   Ok(())
//! # }
//! ```

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
    fs,
    io::AsyncReadExt,
    sync::{Mutex, RwLock},
};

use crate::{AsAttributes, Key, Secret};

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

pub(crate) use api::AttributeValue;

mod error;
mod item;
mod locked_keyring;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use item::Item;
pub use locked_keyring::LockedKeyring;

type ItemDefinition = (String, HashMap<String, String>, Secret, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct UnlockedKeyring {
    keyring: Arc<RwLock<api::Keyring>>,
    path: Option<PathBuf>,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Mutex<Option<std::time::SystemTime>>,
    key: Mutex<Option<Arc<Key>>>,
    secret: Mutex<Arc<Secret>>,
}

impl UnlockedKeyring {
    /// Locks the keyring
    pub fn lock(self) -> LockedKeyring {
        LockedKeyring {
            mtime: self.mtime,
            keyring: self.keyring,
            path: self.path,
        }
    }

    /// Load from default keyring file
    pub async fn load_default() -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Loading default keyring file");
        let secret = Secret::from(ashpd::desktop::secret::retrieve().await?);
        Self::load(api::Keyring::default_path()?, secret).await
    }

    /// Load from default keyring file
    ///
    /// # Safety
    ///
    /// The secret validation is skipped.
    pub async unsafe fn load_default_unchecked() -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Loading default keyring file");
        let secret = Secret::from(ashpd::desktop::secret::retrieve().await?);
        unsafe { Self::load_unchecked(api::Keyring::default_path()?, secret).await }
    }

    /// Load from a keyring file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file backend.
    /// * `secret` - The service key, usually retrieved from the Secrets portal.
    pub async fn load(path: impl AsRef<Path>, secret: Secret) -> Result<Self, Error> {
        let locked = LockedKeyring::load(path.as_ref().to_owned()).await?;
        let unlocked = locked.unlock(secret).await?;
        Ok(unlocked)
    }

    /// Load from a keyring file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file backend.
    /// * `secret` - The service key, usually retrieved from the Secrets portal.
    ///
    /// # Safety
    ///
    /// The secret is not validated to be the correct one to decrypt the keyring
    /// items. Allowing the API user to write new items with a different
    /// secret on top of previously added items with a different secret.
    ///
    /// As it is not a supported behaviour, this API is mostly meant for
    /// recovering broken keyrings.
    pub async unsafe fn load_unchecked(
        path: impl AsRef<Path>,
        secret: Secret,
    ) -> Result<Self, Error> {
        let locked = LockedKeyring::load(path.as_ref().to_owned()).await?;
        let unlocked = unsafe { locked.unlock_unchecked(secret).await? };
        Ok(unlocked)
    }

    /// Creates a temporary backend, that is never stored on disk.
    pub async fn temporary(secret: Secret) -> Result<Self, Error> {
        let keyring = api::Keyring::new();
        Ok(Self {
            keyring: Arc::new(RwLock::new(keyring)),
            path: None,
            mtime: Default::default(),
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
                path: Some(path.as_ref().to_path_buf()),
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
                let key = keyring.derive_key(&secret)?;

                for item in legacy_keyring.decrypt_items(&secret)? {
                    let encrypted_item = item.encrypt(&key)?;
                    keyring.items.push(encrypted_item);
                }

                Ok(Self {
                    keyring: Arc::new(RwLock::new(keyring)),
                    path: Some(path.as_ref().to_path_buf()),
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
            return UnlockedKeyring::load(v1_path, secret).await;
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
                path: Some(v1_path),
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
    pub async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;
        Ok(keyring
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
            .collect())
    }

    /// Search items matching the attributes.
    pub async fn search_items(&self, attributes: &impl AsAttributes) -> Result<Vec<Item>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;
        keyring.search_items(attributes, &key)
    }

    /// Find the first item matching the attributes.
    pub async fn lookup_item(&self, attributes: &impl AsAttributes) -> Result<Option<Item>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;
        keyring.lookup_item(attributes, &key)
    }

    /// Find the index in the list of items of the first item matching the
    /// attributes.
    pub async fn lookup_item_index(
        &self,
        attributes: &impl AsAttributes,
    ) -> Result<Option<usize>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;
        Ok(keyring.lookup_item_index(attributes, &key))
    }

    /// Delete an item.
    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        {
            let key = self.derive_key().await?;
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
        secret: impl Into<Secret>,
        replace: bool,
    ) -> Result<Item, Error> {
        let item = {
            let key = self.derive_key().await?;
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
            let key = self.derive_key().await?;
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
        let key = self.derive_key().await?;
        let mut keyring = self.keyring.write().await;
        for (label, attributes, secret, replace) in items {
            if replace {
                keyring.remove_items(&attributes, &key)?;
            }
            let item = Item::new(label, &attributes, secret);
            let encrypted_item = item.encrypt(&key)?;
            keyring.items.push(encrypted_item);
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file");
        if let Some(ref path) = self.path {
            keyring.dump(path, *self.mtime.lock().await).await?;
        }
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
            if let Some(ref path) = self.path {
                keyring.dump(path, *mtime).await?;
            }
        };
        let Some(ref path) = self.path else {
            return Ok(());
        };
        if let Ok(modified) = fs::metadata(path).await?.modified() {
            #[cfg(feature = "tracing")]
            tracing::debug!("New modified time {:?}", modified);
            *mtime = Some(modified);
        }
        Ok(())
    }

    /// Return key, derive and store it first if not initialized
    async fn derive_key(&self) -> Result<Arc<Key>, crate::crypto::Error> {
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
            .await?;
            #[cfg(feature = "tokio")]
            let key =
                tokio::task::spawn_blocking(move || keyring.blocking_read().derive_key(&secret))
                    .await
                    .unwrap()?;

            *key_lock = Some(Arc::new(key));
        }

        Ok(Arc::clone(key_lock.as_ref().unwrap()))
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
        let key = self.derive_key().await?;
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
        let key = self.derive_key().await?;

        let mut keyring = self.keyring.write().await;
        for item in items {
            let encrypted_item = item.encrypt(&key)?;
            keyring.items.push(encrypted_item);
        }
        drop(keyring);

        self.write().await
    }

    /// Delete any item that cannot be decrypted with the key associated to the
    /// keyring.
    ///
    /// This can only happen if an item was created using
    /// [`Self::load_unchecked`] or prior to 0.4 where we didn't validate
    /// the secret when using [`Self::load`] or modified externally.
    pub async fn delete_broken_items(&self) -> Result<usize, Error> {
        let key = self.derive_key().await?;
        let mut keyring = self.keyring.write().await;
        let mut broken_items = vec![];
        for (index, encrypted_item) in keyring.items.iter().enumerate() {
            if let Err(_err) = encrypted_item.clone().decrypt(&key) {
                broken_items.push(index);
            }
        }
        let n_broken_items = broken_items.len();
        for index in broken_items {
            keyring.items.remove(index);
        }
        drop(keyring);

        self.write().await?;
        Ok(n_broken_items)
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
        let keyring = UnlockedKeyring::load(&path, secret).await?;

        keyring.write().await?;
        keyring.write().await?;

        Ok(())
    }

    #[tokio::test]
    async fn delete() -> Result<(), Error> {
        let path = PathBuf::from("../../tests/test-delete.keyring");

        let keyring = UnlockedKeyring::load(&path, strong_key()).await?;
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
        let keyring = UnlockedKeyring::load(&path, secret).await?;
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

        let keyring = UnlockedKeyring::load(&path, strong_key()).await?;
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

        let keyring = Arc::new(UnlockedKeyring::load(&path, strong_key()).await?);

        let keyring_clone = keyring.clone();
        let handle_1 = tokio::task::spawn(async move { keyring_clone.write().await });
        let handle_2 = tokio::task::spawn(async move { keyring.write().await });

        let (res_1, res_2) = futures_util::future::join(handle_1, handle_2).await;
        res_1.unwrap()?;
        res_2.unwrap()?;

        Ok(())
    }

    async fn check_items(keyring: &UnlockedKeyring) -> Result<(), Error> {
        assert_eq!(keyring.n_items().await, 1);
        let items: Result<Vec<_>, _> = keyring.items().await?.into_iter().collect();
        let items = items.expect("unable to retrieve items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "foo");
        assert_eq!(items[0].secret(), Secret::blob("foo"));
        let attributes = items[0].attributes();
        assert_eq!(attributes.len(), 2);
        assert_eq!(
            attributes
                .get(crate::XDG_SCHEMA_ATTRIBUTE)
                .map(|v| v.as_ref()),
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

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        assert!(!v1_dir.join("default.keyring").exists());

        let secret = Secret::blob("test");
        let keyring = UnlockedKeyring::open("default", secret).await?;

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

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        let secret = Secret::blob("test");
        let keyring = UnlockedKeyring::open("default", secret).await?;

        assert!(!v1_dir.join("default.keyring").exists());

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn open_wrong_password() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        fs::copy(&fixture_path, &v1_dir.join("default.keyring")).await?;

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        let secret = Secret::blob("wrong");
        let keyring = UnlockedKeyring::open("default", secret).await;

        assert!(keyring.is_err());
        assert!(matches!(keyring.unwrap_err(), Error::IncorrectSecret));

        let secret = Secret::blob("test");
        let keyring = UnlockedKeyring::open("default", secret).await;

        assert!(keyring.is_ok());

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

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        let secret = Secret::blob("test");
        let keyring = UnlockedKeyring::open("default", secret).await?;

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

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        let secret = Secret::blob("test");
        let keyring = UnlockedKeyring::open("default", secret).await?;

        assert!(!v1_dir.join("default.keyring").exists());

        keyring
            .create_item(
                "foo",
                &HashMap::from([(crate::XDG_SCHEMA_ATTRIBUTE, "org.gnome.keyring.Note")]),
                "foo",
                false,
            )
            .await?;
        keyring.write().await?;

        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    async fn delete_broken_items() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        let keyring_path = v1_dir.join("default.keyring");
        fs::copy(&fixture_path, &keyring_path).await?;

        let keyring = UnlockedKeyring::load(&keyring_path, Secret::blob("test")).await?;
        keyring
            .create_item(
                "test 3",
                &HashMap::from([("attr3", "value3")]),
                "password3",
                false,
            )
            .await?;
        drop(keyring);

        let keyring = unsafe {
            UnlockedKeyring::load_unchecked(&keyring_path, Secret::blob("wrong_password")).await?
        };
        keyring
            .create_item(
                "test",
                &HashMap::from([("attr", "value")]),
                "password",
                false,
            )
            .await?;
        drop(keyring);

        assert!(
            UnlockedKeyring::load(&keyring_path, Secret::blob("wrong_password"))
                .await
                .is_err()
        );

        let keyring = UnlockedKeyring::load(&keyring_path, Secret::blob("test")).await?;
        keyring
            .create_item(
                "test 2",
                &HashMap::from([("attr2", "value2")]),
                "password2",
                false,
            )
            .await?;

        assert_eq!(keyring.delete_broken_items().await?, 1);
        assert_eq!(keyring.delete_broken_items().await?, 0);

        fs::remove_file(keyring_path).await?;

        Ok(())
    }

    #[tokio::test]
    async fn change_secret() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        let keyring_path = v1_dir.join("default.keyring");
        fs::copy(&fixture_path, &keyring_path).await?;

        let keyring = UnlockedKeyring::load(&keyring_path, Secret::blob("test")).await?;
        let attributes = HashMap::from([("attr", "value")]);
        let item_before = keyring
            .create_item("test", &attributes, "password", false)
            .await?;

        let secret = Secret::blob("new_secret");
        keyring.change_secret(secret).await?;

        let secret = Secret::blob("new_secret");
        let keyring = UnlockedKeyring::load(&keyring_path, secret).await?;
        let item_now = keyring.lookup_item(&attributes).await?.unwrap();

        assert_eq!(item_before.label(), item_now.label());
        assert_eq!(item_before.secret(), item_now.secret());
        assert_eq!(item_before.attributes(), item_now.attributes());

        // No items were broken during the secret change
        assert_eq!(keyring.delete_broken_items().await?, 0);

        fs::remove_file(keyring_path).await?;

        Ok(())
    }

    #[tokio::test]
    async fn content_type() -> Result<(), Error> {
        use crate::secret::ContentType;

        let keyring = UnlockedKeyring::temporary(Secret::blob("test_password")).await?;

        // Add items with different MIME types
        keyring
            .create_item(
                "Text",
                &HashMap::from([("type", "text")]),
                Secret::text("Hello, World!"),
                false,
            )
            .await?;

        keyring
            .create_item(
                "Password",
                &HashMap::from([("type", "password")]),
                Secret::blob("super_secret_password"),
                false,
            )
            .await?;

        let items = keyring
            .search_items(&HashMap::from([("type", "text")]))
            .await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secret().content_type(), ContentType::Text);

        let items = keyring
            .search_items(&HashMap::from([("type", "password")]))
            .await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secret().content_type(), ContentType::Blob);

        Ok(())
    }
}
