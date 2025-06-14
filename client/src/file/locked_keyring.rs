use std::{path::PathBuf, sync::Arc};

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

use crate::{
    Secret,
    file::{Keyring, api, error::Error},
};

#[derive(Debug)]
pub struct LockedKeyring {
    pub(super) keyring: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
}

impl LockedKeyring {
    /// Unlocks a keyring and validates it
    pub async fn unlock(self, secret: Secret) -> Result<Keyring, Error> {
        self.unlock_inner(secret, true).await
    }

    /// Unlocks a keyring without validating it
    pub(super) async unsafe fn unlock_unchecked(self, secret: Secret) -> Result<Keyring, Error> {
        self.unlock_inner(secret, false).await
    }

    async fn unlock_inner(self, secret: Secret, validate_items: bool) -> Result<Keyring, Error> {
        let key = if validate_items {
            let inner_keyring = self.keyring.read().await;

            let key = inner_keyring.derive_key(&secret)?;

            let mut n_broken_items = 0;
            let mut n_valid_items = 0;
            for encrypted_item in &inner_keyring.items {
                if let Err(_err) = encrypted_item.clone().decrypt(&key) {
                    n_broken_items += 1;
                } else {
                    n_valid_items += 1;
                }
            }

            drop(inner_keyring);

            if n_valid_items == 0 && n_broken_items != 0 {
                #[cfg(feature = "tracing")]
                tracing::error!("Keyring cannot be decrypted. Invalid secret.");
                return Err(Error::IncorrectSecret);
            } else if n_broken_items > n_valid_items {
                #[cfg(feature = "tracing")]
                {
                    tracing::warn!(
                        "The file contains {n_broken_items} broken items and {n_valid_items} valid ones."
                    );
                    tracing::info!(
                        "Please switch to `Keyring::load_unchecked` to load the keyring without the secret validation.
                        `Keyring::delete_broken_items` can be used to remove them or alternatively with `oo7-cli --repair`."
                    );
                }
                return Err(Error::IncorrectSecret);
            }
            Some(Arc::new(key))
        } else {
            None
        };

        Ok(Keyring {
            keyring: self.keyring,
            path: self.path,
            mtime: self.mtime,
            key: Mutex::new(key),
            secret: Mutex::new(Arc::new(secret)),
        })
    }

    pub async fn load(path: PathBuf) -> Result<Self, Error> {
        let (mtime, keyring) = match fs::File::open(&path).await {
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
            path: Some(path),
            mtime: Mutex::new(mtime),
        })
    }

    pub async fn open(name: &str) -> Result<Self, Error> {
        let v1_path = api::Keyring::path(name, api::MAJOR_VERSION)?;
        if v1_path.exists() {
            return Self::load(v1_path).await;
        }

        let v0_path = api::Keyring::path(name, api::LEGACY_MAJOR_VERSION)?;
        if v0_path.exists() {
            // Migrating a locked keyring is more involved without having the
            // secret.
            todo!();
        };

        Ok(Self {
            keyring: Arc::new(RwLock::new(api::Keyring::new())),
            path: Some(v1_path),
            mtime: Default::default(),
        })
    }
}
