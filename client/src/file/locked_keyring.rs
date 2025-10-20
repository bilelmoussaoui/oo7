#[cfg(feature = "async-std")]
use std::io;
use std::{
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
    io::{self, AsyncReadExt},
    sync::{Mutex, RwLock},
};

use super::{Error, UnlockedKeyring, api};
use crate::Secret;

/// A locked keyring that requires a secret to unlock.
#[derive(Debug)]
pub struct LockedKeyring {
    pub(super) keyring: Arc<RwLock<api::Keyring>>,
    pub(super) path: Option<PathBuf>,
    pub(super) mtime: Mutex<Option<std::time::SystemTime>>,
}

impl LockedKeyring {
    /// Unlocks a keyring and validates it
    pub async fn unlock(self, secret: Secret) -> Result<UnlockedKeyring, Error> {
        self.unlock_inner(secret, true).await
    }

    /// Unlocks a keyring without validating it
    ///
    /// # Safety
    ///
    /// The method doesn't validate that the secret can decrypt all the items in
    /// the keyring.
    pub async unsafe fn unlock_unchecked(self, secret: Secret) -> Result<UnlockedKeyring, Error> {
        self.unlock_inner(secret, false).await
    }

    async fn unlock_inner(
        self,
        secret: Secret,
        validate_items: bool,
    ) -> Result<UnlockedKeyring, Error> {
        let key = if validate_items {
            let inner_keyring = self.keyring.read().await;

            let key = inner_keyring.derive_key(&secret)?;

            let mut n_broken_items = 0;
            let mut n_valid_items = 0;
            for encrypted_item in &inner_keyring.items {
                if encrypted_item.clone().decrypt(&key).is_err() {
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
                        "Please switch to `UnlockedKeyring::load_unchecked` to load the keyring without the secret validation.
                        `Keyring::delete_broken_items` can be used to remove them or alternatively with `oo7-cli --repair`."
                    );
                }
                return Err(Error::PartiallyCorruptedKeyring {
                    valid_items: n_valid_items,
                    broken_items: n_broken_items,
                });
            }
            Some(Arc::new(key))
        } else {
            None
        };

        Ok(UnlockedKeyring {
            keyring: self.keyring,
            path: self.path,
            mtime: self.mtime,
            key: Mutex::new(key),
            secret: Mutex::new(Arc::new(secret)),
        })
    }

    /// Load a keyring from a file path.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let (mtime, keyring) = match fs::File::open(&path).await {
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

                let keyring = api::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        Ok(Self {
            keyring: Arc::new(RwLock::new(keyring)),
            path: Some(path.to_path_buf()),
            mtime: Mutex::new(mtime),
        })
    }

    /// Open a named keyring.
    pub async fn open(name: &str) -> Result<Self, Error> {
        let v1_path = api::Keyring::path(name, api::MAJOR_VERSION)?;
        Self::load(v1_path).await
    }
}
