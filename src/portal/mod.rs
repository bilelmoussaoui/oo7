/*!

File backend implementation backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret)    .

```ignore
# std::env::set_var("XDG_DATA_HOME", "/tmp/doctest");
# use oo7::keyring::{self, Error};
# use std::collections::HashMap;
# async_std::task::block_on(async {
#
keyring::insert_replace(&keyring::Item::new(
    "My Label",
    HashMap::from([("account", "alice")]),
    b"My Password",
))
.await?;

let items = keyring::lookup(HashMap::from([("account", "alice")])).await?;
assert_eq!(*items[0].password(), b"My Password");

keyring::remove(HashMap::from([("account", "alice")])).await?;
#
# Ok::<(), Error>(())
# }).unwrap()
```
*/

use std::collections::HashMap;

#[cfg(feature = "async-std")]
use async_std::{fs, io, prelude::*, sync::Mutex};
#[cfg(feature = "tokio")]
#[cfg(not(feature = "async-std"))]
use tokio::{fs, io, io::AsyncReadExt, sync::Mutex};

use std::path::{Path, PathBuf};

#[cfg(feature = "unstable")]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

mod error;
mod item;
mod secret;

pub use error::Error;
use zeroize::Zeroizing;

pub use item::Item;

type ItemDefinition = (String, HashMap<String, String>, Zeroizing<Vec<u8>>, bool);

/// File backed keyring.
#[derive(Debug)]
pub struct Keyring {
    keyring: Mutex<api::Keyring>,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Option<std::time::SystemTime>,
    key: crate::Key,
}

impl Keyring {
    /// Load from default keyring file
    pub async fn load_default() -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Loading default keyring file");
        let secret = secret::retrieve().await?;
        Self::load(api::Keyring::default_path()?, &secret).await
    }

    /// Load from a keyring file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file backend.
    /// * `secret` - The service key, usually retrieved from the Secrets portal.
    pub async fn load(path: impl AsRef<Path>, secret: &[u8]) -> Result<Self, Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Tyring to load keyring file at {:?}", path.as_ref());
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

        let key = keyring.derive_key(secret);

        Ok(Self {
            keyring: Mutex::new(keyring),
            path: path.as_ref().to_path_buf(),
            mtime,
            key,
        })
    }

    pub async fn items(&self) -> Result<Vec<Item>, Error> {
        self.keyring
            .lock()
            .await
            .items
            .iter()
            .map(|e| (*e).clone().decrypt(&self.key))
            .collect()
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>, Error> {
        self.keyring
            .lock()
            .await
            .search_items(attributes, &self.key)
    }

    pub async fn delete(&self, attributes: HashMap<&str, &str>) -> Result<(), Error> {
        let mut keyring = self.keyring.lock().await;
        keyring.remove_items(attributes, &self.key)?;
        self.write().await
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: impl AsRef<[u8]>,
        replace: bool,
    ) -> Result<(), Error> {
        let mut keyring = self.keyring.lock().await;
        if replace {
            keyring.remove_items(attributes.clone(), &self.key)?;
        }
        let item = Item::new(label, attributes, secret);
        let encrypted_item = item.encrypt(&self.key)?;
        keyring.items.push(encrypted_item);
        self.write().await
    }

    /// Helper used for migration to avoid re-writing the file multiple times
    pub(crate) async fn create_items(&self, items: Vec<ItemDefinition>) -> Result<(), Error> {
        let mut keyring = self.keyring.lock().await;
        for (label, attributes, secret, replace) in items {
            if replace {
                keyring.remove_items(attributes.clone(), &self.key)?;
            }
            let item = Item::new(label, attributes, &*secret);
            let encrypted_item = item.encrypt(&self.key)?;
            keyring.items.push(encrypted_item);
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file");
        keyring.dump(&self.path, self.mtime).await?;
        Ok(())
    }

    pub async fn write(&self) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Writing keyring back to the file {:?}", self.path);
        self.keyring
            .lock()
            .await
            .dump(&self.path, self.mtime)
            .await?;
        Ok(())
    }
}
