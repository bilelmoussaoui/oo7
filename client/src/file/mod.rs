//! File backend implementation that can be backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
//!
//! ```no_run
//! use std::collections::HashMap;
//!
//! use oo7::file::Keyring;
//!
//! # async fn run() -> oo7::Result<()> {
//! let keyring = Keyring::load_default().await?;
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

use crate::{AsAttributes, Key, Secret};

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

pub(crate) use api::AttributeValue;

mod error;
mod item;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use item::Item;

type ItemDefinition = (String, HashMap<String, String>, Secret, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct Keyring {
    keyring: Arc<RwLock<api::Keyring>>,
    path: Option<PathBuf>,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Mutex<Option<std::time::SystemTime>>,
    key: Mutex<Option<Arc<Key>>>,
    secret: Mutex<Arc<Secret>>,
}

impl Keyring {
    /// Load from default keyring file
    #[cfg_attr(feature = "tracing", tracing::instrument())]
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
    #[cfg_attr(feature = "tracing", tracing::instrument())]
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret), fields(path = ?path.as_ref())))]
    pub async fn load(path: impl AsRef<Path>, secret: Secret) -> Result<Self, Error> {
        Self::load_inner(path, secret, true).await
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret), fields(path = ?path.as_ref())))]
    pub async unsafe fn load_unchecked(
        path: impl AsRef<Path>,
        secret: Secret,
    ) -> Result<Self, Error> {
        Self::load_inner(path, secret, false).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret), fields(path = ?path.as_ref(), validate_items = validate_items)))]
    async fn load_inner(
        path: impl AsRef<Path>,
        secret: Secret,
        validate_items: bool,
    ) -> Result<Self, Error> {
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
                tracing::debug!("Keyring file found, loading its content");
                let mtime = file.metadata().await?.modified().ok();

                let mut content = Vec::new();
                file.read_to_end(&mut content).await?;

                #[cfg(feature = "tracing")]
                tracing::debug!("Read {} bytes from keyring file", content.len());

                let keyring = api::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        let key = if validate_items {
            let key = keyring.derive_key(&secret)?;

            let mut broken_items = 0;
            let mut valid_items = 0;
            for encrypted_item in &keyring.items {
                if !encrypted_item.is_valid(&key) {
                    broken_items += 1;
                } else {
                    valid_items += 1;
                }
            }

            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Validation complete: {} valid items, {} broken items",
                valid_items,
                broken_items
            );

            if valid_items == 0 && broken_items != 0 {
                #[cfg(feature = "tracing")]
                tracing::error!("Keyring cannot be decrypted. Invalid secret.");
                return Err(Error::IncorrectSecret);
            } else if broken_items > valid_items {
                #[cfg(feature = "tracing")]
                {
                    tracing::warn!(
                        "The file contains {broken_items} broken items and {valid_items} valid ones."
                    );
                    tracing::info!(
                        "Please switch to `Keyring::load_unchecked` to load the keyring without the secret validation.
                        `Keyring::delete_broken_items` can be used to remove them or alternatively with `oo7-cli --repair`."
                    );
                }
                return Err(Error::PartiallyCorruptedKeyring {
                    valid_items,
                    broken_items,
                });
            }

            Some(Arc::new(key))
        } else {
            None
        };

        Ok(Self {
            keyring: Arc::new(RwLock::new(keyring)),
            path: Some(path.as_ref().to_path_buf()),
            mtime: Mutex::new(mtime),
            key: Mutex::new(key),
            secret: Mutex::new(Arc::new(secret)),
        })
    }

    /// Creates a temporary backend, that is never stored on disk.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret)))]
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

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(file, secret), fields(path = ?path.as_ref())))]
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

                let decrypted_items = legacy_keyring.decrypt_items(&secret)?;

                #[cfg(feature = "tracing")]
                let _migrate_span =
                    tracing::debug_span!("migrate_items", item_count = decrypted_items.len());

                for item in decrypted_items {
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(secret)))]
    pub async fn open(name: &str, secret: Secret) -> Result<Self, Error> {
        let v1_path = api::Keyring::path(name, api::MAJOR_VERSION)?;
        if v1_path.exists() {
            #[cfg(feature = "tracing")]
            tracing::debug!("Loading v1 keyring file");
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
            #[cfg(feature = "tracing")]
            tracing::debug!("Creating new keyring");
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn n_items(&self) -> usize {
        self.keyring.read().await.items.len()
    }

    /// Retrieve the list of available [`Item`]s.
    ///
    /// If items cannot be decrypted, [`InvalidItemError`]s are returned for
    /// them instead of [`Item`]s.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;

        #[cfg(feature = "tracing")]
        let _span = tracing::debug_span!("decrypt", total_items = keyring.items.len());

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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, attributes)))]
    pub async fn search_items(&self, attributes: &impl AsAttributes) -> Result<Vec<Item>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;
        let results = keyring.search_items(attributes, &key)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Found {} matching items", results.len());

        Ok(results)
    }

    /// Find the first item matching the attributes.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, attributes)))]
    pub async fn lookup_item(&self, attributes: &impl AsAttributes) -> Result<Option<Item>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;

        keyring.lookup_item(attributes, &key)
    }

    /// Find the index in the list of items of the first item matching the
    /// attributes.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, attributes)))]
    pub async fn lookup_item_index(
        &self,
        attributes: &impl AsAttributes,
    ) -> Result<Option<usize>, Error> {
        let key = self.derive_key().await?;
        let keyring = self.keyring.read().await;

        Ok(keyring.lookup_item_index(attributes, &key))
    }

    /// Delete an item.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, attributes)))]
    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        let items_before = { self.keyring.read().await.items.len() };

        {
            let key = self.derive_key().await?;
            let mut keyring = self.keyring.write().await;
            keyring.remove_items(attributes, &key)?;
        };

        self.write().await?;

        #[cfg(feature = "tracing")]
        {
            let items_after = self.keyring.read().await.items.len();
            let deleted_count = items_before.saturating_sub(items_after);
            tracing::info!("Deleted {} items", deleted_count);
        }

        Ok(())
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, secret, attributes), fields(replace = replace)))]
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
            Err(e) => {
                #[cfg(feature = "tracing")]
                tracing::error!("Failed to write keyring after item creation");
                Err(e)
            }
            Ok(_) => {
                #[cfg(feature = "tracing")]
                tracing::info!("Successfully created item");
                Ok(item)
            }
        }
    }

    /// Replaces item at the given index.
    ///
    /// The `index` refers to the index of the [`Vec`] returned by
    /// [`items()`](Self::items). If the index does not exist, the functions
    /// returns an error.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, item), fields(index = index)))]
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), fields(index = index)))]
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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, items), fields(item_count = items.len())))]
    pub(crate) async fn create_items(&self, items: Vec<ItemDefinition>) -> Result<(), Error> {
        let key = self.derive_key().await?;
        let mut keyring = self.keyring.write().await;

        #[cfg(feature = "tracing")]
        let _span = tracing::debug_span!("bulk_create", items_to_create = items.len());

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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn write(&self) -> Result<(), Error> {
        let mut mtime = self.mtime.lock().await;
        {
            let mut keyring = self.keyring.write().await;

            if let Some(ref path) = self.path {
                keyring.dump(path, *mtime).await?;
            }
        };
        let Some(ref path) = self.path else {
            return Ok(());
        };

        if let Ok(modified) = fs::metadata(path).await?.modified() {
            *mtime = Some(modified);
        }
        Ok(())
    }

    /// Return key, derive and store it first if not initialized
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
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
            let key = {
                tokio::task::spawn_blocking(move || keyring.blocking_read().derive_key(&secret))
                    .await
                    .unwrap()?
            };

            *key_lock = Some(Arc::new(key));
        }

        Ok(Arc::clone(key_lock.as_ref().unwrap()))
    }

    /// Change keyring secret
    ///
    /// # Arguments
    ///
    /// * `secret` - The new secret to store.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, secret)))]
    pub async fn change_secret(&self, secret: Secret) -> Result<(), Error> {
        let keyring = self.keyring.read().await;
        let key = self.derive_key().await?;
        let mut items = Vec::with_capacity(keyring.items.len());

        #[cfg(feature = "tracing")]
        let _decrypt_span =
            tracing::debug_span!("decrypt_for_reencrypt", total_items = keyring.items.len());

        for item in &keyring.items {
            items.push(item.clone().decrypt(&key)?);
        }
        drop(keyring);

        #[cfg(feature = "tracing")]
        tracing::debug!("Updating secret and resetting key");

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

        #[cfg(feature = "tracing")]
        let _reencrypt_span = tracing::debug_span!("reencrypt", total_items = items.len());

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
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub async fn delete_broken_items(&self) -> Result<usize, Error> {
        let key = self.derive_key().await?;
        let mut keyring = self.keyring.write().await;
        let mut broken_items = vec![];

        #[cfg(feature = "tracing")]
        let _span = tracing::debug_span!("identify_broken", total_items = keyring.items.len());

        for (index, encrypted_item) in keyring.items.iter().enumerate() {
            if !encrypted_item.is_valid(&key) {
                broken_items.push(index);
            }
        }
        let n_broken_items = broken_items.len();

        #[cfg(feature = "tracing")]
        tracing::info!("Found {} broken items to delete", n_broken_items);

        #[cfg(feature = "tracing")]
        let _remove_span = tracing::debug_span!("remove_broken", broken_count = n_broken_items);

        for index in broken_items.into_iter().rev() {
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
    #[serial_test::serial]
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
        let keyring = Keyring::open("default", secret).await?;

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
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
        let keyring = Keyring::open("default", secret).await?;

        assert!(!v1_dir.join("default.keyring").exists());

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
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
        let keyring = Keyring::open("default", secret).await;

        assert!(keyring.is_err());
        assert!(matches!(keyring.unwrap_err(), Error::IncorrectSecret));

        let secret = Secret::blob("test");
        let keyring = Keyring::open("default", secret).await;

        assert!(keyring.is_ok());

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
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
        let keyring = Keyring::open("default", secret).await?;

        assert!(v1_dir.join("default.keyring").exists());

        check_items(&keyring).await?;

        keyring.write().await?;
        assert!(v1_dir.join("default.keyring").exists());

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn open_nonexistent() -> Result<(), Error> {
        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        unsafe {
            std::env::set_var("XDG_DATA_HOME", data_dir.path());
        }

        let secret = Secret::blob("test");
        let keyring = Keyring::open("default", secret).await?;

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
        const VALID_TO_ADD: usize = 5;
        const BROKEN_TO_ADD: usize = 3;

        let data_dir = tempdir()?;
        let v0_dir = data_dir.path().join("keyrings");
        let v1_dir = v0_dir.join("v1");
        fs::create_dir_all(&v1_dir).await?;

        let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("default.keyring");
        let keyring_path = v1_dir.join("default.keyring");
        fs::copy(&fixture_path, &keyring_path).await?;

        // 1) Load with the correct password and add several valid items. This ensures
        //    valid_items > broken_items that we'll add later.
        let keyring = Keyring::load(&keyring_path, Secret::blob("test")).await?;
        for i in 0..VALID_TO_ADD {
            keyring
                .create_item(
                    &format!("valid {}", i),
                    &HashMap::from([("attr_valid", "value")]),
                    format!("password_valid_{}", i),
                    false,
                )
                .await?;
        }
        drop(keyring);

        // 2) Load_unchecked with the wrong password and add a few "broken" items.
        let keyring = unsafe {
            Keyring::load_unchecked(&keyring_path, Secret::blob("wrong_password")).await?
        };
        for i in 0..BROKEN_TO_ADD {
            keyring
                .create_item(
                    &format!("bad{}", i),
                    &HashMap::from([("attr_bad", "value_bad")]),
                    format!("pw_bad{}", i),
                    false,
                )
                .await?;
        }
        drop(keyring);

        // 3) Load with the correct password and run the deletion.
        let keyring = Keyring::load(&keyring_path, Secret::blob("test")).await?;
        let removed = keyring.delete_broken_items().await?;
        assert!(
            removed >= BROKEN_TO_ADD,
            "expected at least {} broken items removed, got {}",
            BROKEN_TO_ADD,
            removed
        );

        // Second call should find nothing left to clean up.
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

        let keyring = Keyring::load(&keyring_path, Secret::blob("test")).await?;
        let attributes = HashMap::from([("attr", "value")]);
        let item_before = keyring
            .create_item("test", &attributes, "password", false)
            .await?;

        let secret = Secret::blob("new_secret");
        keyring.change_secret(secret).await?;

        let secret = Secret::blob("new_secret");
        let keyring = Keyring::load(&keyring_path, secret).await?;
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

        let keyring = Keyring::temporary(Secret::blob("test_password")).await?;

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

    #[tokio::test]
    async fn wrong_password_error_type() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("wrong_password_test.keyring");
        let correct_secret = Secret::from("correct-password-that-is-long-enough".as_bytes());
        let wrong_secret = Secret::from("wrong-password-that-is-long-enough".as_bytes());

        // Create a keyring with the correct password
        let keyring = Keyring::load(&keyring_path, correct_secret).await?;
        keyring
            .create_item(
                "Test Item",
                &HashMap::from([("app", "test")]),
                "my-secret",
                false,
            )
            .await?;

        // Try to load with wrong password
        let result = Keyring::load(&keyring_path, wrong_secret).await;

        // Verify this returns IncorrectSecret, not ChecksumMismatch
        assert!(matches!(result, Err(Error::IncorrectSecret)));

        Ok(())
    }

    #[tokio::test]
    async fn comprehensive_search_patterns() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("search_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        // Create diverse test data
        let test_items = vec![
            (
                "Email Password",
                vec![
                    ("app", "email"),
                    ("user", "alice@example.com"),
                    ("type", "password"),
                ],
            ),
            (
                "Email Token",
                vec![
                    ("app", "email"),
                    ("user", "alice@example.com"),
                    ("type", "token"),
                ],
            ),
            (
                "SSH Key",
                vec![("app", "ssh"), ("user", "alice"), ("type", "key")],
            ),
            (
                "Database Password",
                vec![
                    ("app", "database"),
                    ("env", "production"),
                    ("type", "password"),
                ],
            ),
            (
                "API Key",
                vec![("app", "api"), ("service", "github"), ("type", "key")],
            ),
        ];

        for (i, (label, attrs)) in test_items.iter().enumerate() {
            let attrs_map: HashMap<&str, &str> = attrs.iter().cloned().collect();
            keyring
                .create_item(label, &attrs_map, format!("secret{}", i), false)
                .await?;
        }

        // Test exact match
        let exact = keyring
            .search_items(&HashMap::from([
                ("app", "email"),
                ("user", "alice@example.com"),
                ("type", "password"),
            ]))
            .await?;
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].label(), "Email Password");

        // Test partial match - by app
        let email_items = keyring
            .search_items(&HashMap::from([("app", "email")]))
            .await?;
        assert_eq!(email_items.len(), 2);

        // Test partial match - by type
        let passwords = keyring
            .search_items(&HashMap::from([("type", "password")]))
            .await?;
        assert_eq!(passwords.len(), 2);

        let keys = keyring
            .search_items(&HashMap::from([("type", "key")]))
            .await?;
        assert_eq!(keys.len(), 2);

        // Test no match
        let nonexistent = keyring
            .search_items(&HashMap::from([("app", "nonexistent")]))
            .await?;
        assert_eq!(nonexistent.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn item_replacement_behavior() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("replace_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        let attrs = HashMap::from([("app", "test"), ("user", "alice")]);

        // Create initial item
        keyring
            .create_item("Original", &attrs, "secret1", false)
            .await?;

        // Verify initial state
        let items = keyring.search_items(&attrs).await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "Original");
        assert_eq!(items[0].secret(), Secret::text("secret1"));

        // With replace=false, allows duplicates (discovered behavior)
        keyring
            .create_item("Duplicate", &attrs, "secret2", false)
            .await?;

        // Verify we now have 2 items with same attributes
        let items = keyring.search_items(&attrs).await?;
        assert_eq!(items.len(), 2);

        // Verify both items exist with different content
        let labels: Vec<_> = items.iter().map(|i| i.label()).collect();
        assert!(labels.contains(&"Original"));
        assert!(labels.contains(&"Duplicate"));

        // Now test replace=true behavior - should remove existing items with same
        // attributes
        keyring
            .create_item("Replacement", &attrs, "secret3", true)
            .await?;

        // After replace=true, should only have the new item
        let items = keyring.search_items(&attrs).await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label(), "Replacement");
        assert_eq!(items[0].secret(), Secret::text("secret3"));

        // Test replace=true on empty attributes (should just add)
        let unique_attrs = HashMap::from([("app", "unique"), ("user", "bob")]);
        keyring
            .create_item("Unique Item", &unique_attrs, "unique_secret", true)
            .await?;

        let unique_items = keyring.search_items(&unique_attrs).await?;
        assert_eq!(unique_items.len(), 1);
        assert_eq!(unique_items[0].label(), "Unique Item");

        // Test replace=true again on the unique item - should replace it
        keyring
            .create_item("Updated Unique", &unique_attrs, "updated_secret", true)
            .await?;

        let unique_items = keyring.search_items(&unique_attrs).await?;
        assert_eq!(unique_items.len(), 1);
        assert_eq!(unique_items[0].label(), "Updated Unique");
        assert_eq!(unique_items[0].secret(), Secret::text("updated_secret"));

        Ok(())
    }

    #[tokio::test]
    async fn empty_keyring_operations() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("empty_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        // Test operations on empty keyring
        let items = keyring.items().await?;
        assert_eq!(items.len(), 0);

        let search_results = keyring
            .search_items(&HashMap::from([("any", "thing")]))
            .await?;
        assert_eq!(search_results.len(), 0);

        // Delete on empty keyring should succeed
        keyring
            .delete(&HashMap::from([("nonexistent", "key")]))
            .await?;

        // Verify still empty after delete
        assert_eq!(keyring.n_items().await, 0);

        // Test lookup on empty keyring
        let lookup_result = keyring
            .lookup_item(&HashMap::from([("test", "value")]))
            .await?;
        assert!(lookup_result.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn secret_types_handling() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("secret_types_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        // Test text secret
        keyring
            .create_item(
                "Text Secret",
                &HashMap::from([("type", "text")]),
                Secret::text("Hello, World!"),
                false,
            )
            .await?;

        // Test binary secret
        keyring
            .create_item(
                "Binary Secret",
                &HashMap::from([("type", "binary")]),
                Secret::blob(&[0x00, 0x01, 0x02, 0xFF]),
                false,
            )
            .await?;

        // Test large secret
        let large_data = vec![42u8; 10000];
        keyring
            .create_item(
                "Large Secret",
                &HashMap::from([("type", "large")]),
                Secret::blob(&large_data),
                false,
            )
            .await?;

        // Test empty secret
        keyring
            .create_item(
                "Empty Secret",
                &HashMap::from([("type", "empty")]),
                Secret::text(""),
                false,
            )
            .await?;

        // Verify all secrets can be retrieved correctly
        let text_items = keyring
            .search_items(&HashMap::from([("type", "text")]))
            .await?;
        assert_eq!(text_items.len(), 1);
        assert_eq!(text_items[0].secret(), Secret::text("Hello, World!"));
        assert_eq!(
            text_items[0].secret().content_type(),
            crate::secret::ContentType::Text
        );

        let binary_items = keyring
            .search_items(&HashMap::from([("type", "binary")]))
            .await?;
        assert_eq!(binary_items.len(), 1);
        assert_eq!(&*binary_items[0].secret(), &[0x00, 0x01, 0x02, 0xFF]);
        assert_eq!(
            binary_items[0].secret().content_type(),
            crate::secret::ContentType::Blob
        );

        let large_items = keyring
            .search_items(&HashMap::from([("type", "large")]))
            .await?;
        assert_eq!(large_items.len(), 1);
        assert_eq!(&*large_items[0].secret(), &large_data);

        let empty_items = keyring
            .search_items(&HashMap::from([("type", "empty")]))
            .await?;
        assert_eq!(empty_items.len(), 1);
        assert_eq!(empty_items[0].secret(), Secret::text(""));

        Ok(())
    }

    #[tokio::test]
    async fn item_lifecycle_operations() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("lifecycle_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        // Test creating multiple items
        keyring
            .create_item(
                "Test Item 1",
                &HashMap::from([("app", "myapp"), ("user", "alice")]),
                "secret1",
                false,
            )
            .await?;

        keyring
            .create_item(
                "Test Item 2",
                &HashMap::from([("app", "myapp"), ("user", "bob")]),
                "secret2",
                false,
            )
            .await?;

        // Test retrieving all items
        let items = keyring.items().await?;
        let valid_items: Vec<_> = items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(valid_items.len(), 2);

        // Test searching by user
        let alice_items = keyring
            .search_items(&HashMap::from([("user", "alice")]))
            .await?;
        assert_eq!(alice_items.len(), 1);
        assert_eq!(alice_items[0].label(), "Test Item 1");
        assert_eq!(alice_items[0].secret(), Secret::text("secret1"));

        // Test searching by app (should find both)
        let app_items = keyring
            .search_items(&HashMap::from([("app", "myapp")]))
            .await?;
        assert_eq!(app_items.len(), 2);

        // Test deleting items
        keyring.delete(&HashMap::from([("user", "alice")])).await?;
        let remaining_items = keyring.items().await?;
        let valid_remaining: Vec<_> = remaining_items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(valid_remaining.len(), 1);
        assert_eq!(valid_remaining[0].label(), "Test Item 2");

        Ok(())
    }

    #[tokio::test]
    async fn item_attribute_operations() -> Result<(), Error> {
        let temp_dir = tempdir().unwrap();
        let keyring_path = temp_dir.path().join("attr_test.keyring");
        let keyring = Keyring::load(&keyring_path, strong_key()).await?;

        // Create item with initial attributes
        keyring
            .create_item(
                "Attribute Test",
                &HashMap::from([("app", "testapp"), ("version", "1.0"), ("env", "test")]),
                "test-secret",
                false,
            )
            .await?;

        let items = keyring
            .search_items(&HashMap::from([("app", "testapp")]))
            .await?;
        assert_eq!(items.len(), 1);
        let item = &items[0];

        // Test reading attributes
        let attrs = item.attributes();
        assert_eq!(attrs.len(), 4); // 3 + xdg:schema
        assert_eq!(attrs.get("app").unwrap().to_string(), "testapp");
        assert_eq!(attrs.get("version").unwrap().to_string(), "1.0");
        assert_eq!(attrs.get("env").unwrap().to_string(), "test");

        // Test updating attributes - need to get item from keyring after update
        let index = keyring
            .lookup_item_index(&HashMap::from([("app", "testapp")]))
            .await?
            .unwrap();
        keyring
            .replace_item_index(
                index,
                &crate::file::Item::new(
                    "Attribute Test",
                    &HashMap::from([
                        ("app", "testapp"),
                        ("version", "2.0"),        // updated
                        ("env", "production"),     // updated
                        ("new_attr", "new_value"), // added
                    ]),
                    item.secret(),
                ),
            )
            .await?;

        let updated_items = keyring
            .search_items(&HashMap::from([("app", "testapp")]))
            .await?;
        assert_eq!(updated_items.len(), 1);
        let updated_attrs = updated_items[0].attributes();
        assert_eq!(updated_attrs.get("version").unwrap().to_string(), "2.0");
        assert_eq!(updated_attrs.get("env").unwrap().to_string(), "production");
        assert_eq!(
            updated_attrs.get("new_attr").unwrap().to_string(),
            "new_value"
        );

        Ok(())
    }
}
