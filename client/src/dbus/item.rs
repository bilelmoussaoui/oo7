use std::{collections::HashMap, sync::Arc, time::Duration};

#[cfg(feature = "async-std")]
use async_lock::RwLock;
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::{api, Algorithm, Error};
use crate::{crypto, Key};

/// A secret with a label and attributes to identify it.
///
/// An item might be locked or unlocked, use [`Item::lock`] or [`Item::unlock`]
/// to lock or unlock it. Note that the Secret Service might not be able to
/// lock/unlock individual items and may lock/unlock the entire collection in
/// such case.
///
/// The item is attributes are used to identify and find the item later using
/// [`Collection::search_items`](crate::dbus::Collection::search_items).
/// They are not stored or transferred in a secure manner.
///
/// **Note**
///
/// If the item is deleted using [`Item::delete`] any future usage of it API
/// will fail with [`Error::Deleted`].
#[derive(Debug)]
pub struct Item<'a> {
    inner: Arc<api::Item<'a>>,
    session: Arc<api::Session<'a>>,
    service: Arc<api::Service<'a>>,
    algorithm: Algorithm,
    /// Defines whether the Item has been deleted or not
    available: RwLock<bool>,
    aes_key: Option<Arc<Key>>,
}

impl<'a> Item<'a> {
    pub(crate) fn new(
        service: Arc<api::Service<'a>>,
        session: Arc<api::Session<'a>>,
        algorithm: Algorithm,
        item: api::Item<'a>,
        aes_key: Option<Arc<Key>>,
    ) -> Item<'a> {
        Self {
            inner: Arc::new(item),
            service,
            session,
            algorithm,
            available: RwLock::new(true),
            aes_key,
        }
    }

    pub(crate) async fn is_available(&self) -> bool {
        *self.available.read().await
    }

    /// Get whether the item is locked.
    pub async fn is_locked(&self) -> Result<bool, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.is_locked().await
        }
    }

    /// The item label.
    pub async fn label(&self) -> Result<String, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.label().await
        }
    }

    /// Set the item label.
    pub async fn set_label(&self, label: &str) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_label(label).await
        }
    }

    /// The UNIX time when the item was created.
    pub async fn created(&self) -> Result<Duration, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.created().await
        }
    }

    /// The UNIX time when the item was modified.
    pub async fn modified(&self) -> Result<Duration, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.modified().await
        }
    }

    /// Retrieve the item attributes.
    pub async fn attributes(&self) -> Result<HashMap<String, String>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.attributes().await
        }
    }

    /// Update the item attributes.
    pub async fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_attributes(attributes).await
        }
    }

    /// Delete the item.
    pub async fn delete(&self) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.delete().await?;
            *self.available.write().await = false;
            Ok(())
        }
    }

    /// Retrieve the currently stored secret.
    pub async fn secret(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = self.inner.secret(&self.session).await?;

            let value = match self.algorithm {
                Algorithm::Plain => Zeroizing::new(secret.value.to_owned()),
                Algorithm::Encrypted => {
                    let iv = &secret.parameters;
                    // Safe unwrap as it is encrypted
                    let aes_key = self.aes_key.as_ref().unwrap();

                    crypto::decrypt(&secret.value, aes_key, iv)
                }
            };
            Ok(value)
        }
    }

    /// Modify the stored secret on the item.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to store.
    /// * `content_type` - The content type of the secret, usually something
    ///   like `text/plain`.
    #[doc(alias = "SetSecret")]
    pub async fn set_secret(
        &self,
        secret: impl AsRef<[u8]>,
        content_type: &str,
    ) -> Result<(), Error> {
        let secret = match self.algorithm {
            Algorithm::Plain => api::Secret::new(Arc::clone(&self.session), secret, content_type),
            Algorithm::Encrypted => {
                let aes_key = self.aes_key.as_ref().unwrap();
                api::Secret::new_encrypted(Arc::clone(&self.session), secret, content_type, aes_key)
            }
        };
        self.inner.set_secret(&secret).await?;
        Ok(())
    }

    /// Unlock the item.
    pub async fn unlock(&self) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.unlock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }

    /// Lock the item.
    pub async fn lock(&self) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.lock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }
}
