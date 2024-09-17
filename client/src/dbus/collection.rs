use std::{sync::Arc, time::Duration};

use ashpd::WindowIdentifier;
#[cfg(feature = "async-std")]
use async_lock::RwLock;
use futures_util::{Stream, StreamExt};
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::{api, Algorithm, Error, Item};
use crate::{AsAttributes, Key};

/// A collection allows to store and retrieve items.
///
/// The collection can be either in a locked or unlocked state, use
/// [`Collection::lock`] or [`Collection::unlock`] to lock or unlock it.
///
/// Using [`Collection::search_items`] or [`Collection::items`] will return no
/// items if the collection is locked.
///
/// **Note**
///
/// If the collection is deleted using [`Collection::delete`] any future usage
/// of it API will fail with [`Error::Deleted`].
#[derive(Debug)]
pub struct Collection<'a> {
    inner: Arc<api::Collection<'a>>,
    service: Arc<api::Service<'a>>,
    session: Arc<api::Session<'a>>,
    algorithm: Algorithm,
    /// Defines whether the Collection has been deleted or not
    available: RwLock<bool>,
    aes_key: Option<Arc<Key>>,
}

impl<'a> Collection<'a> {
    pub(crate) fn new(
        service: Arc<api::Service<'a>>,
        session: Arc<api::Session<'a>>,
        algorithm: Algorithm,
        collection: api::Collection<'a>,
        aes_key: Option<Arc<Key>>,
    ) -> Collection<'a> {
        Self {
            inner: Arc::new(collection),
            session,
            service,
            algorithm,
            available: RwLock::new(true),
            aes_key,
        }
    }

    pub(crate) async fn is_available(&self) -> bool {
        *self.available.read().await
    }

    /// Retrieve the list of available [`Item`] in the collection.
    pub async fn items(&self) -> Result<Vec<Item<'a>>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            Ok(self
                .inner
                .items()
                .await?
                .into_iter()
                .map(|item| self.new_item(item))
                .collect::<Vec<_>>())
        }
    }

    /// The collection label.
    pub async fn label(&self) -> Result<String, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.label().await
        }
    }

    /// Set the collection label.
    pub async fn set_label(&self, label: &str) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_label(label).await
        }
    }

    /// Get whether the collection is locked.
    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.is_locked().await
        }
    }

    /// The UNIX time when the collection was created.
    pub async fn created(&self) -> Result<Duration, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.created().await
        }
    }

    /// The UNIX time when the collection was modified.
    pub async fn modified(&self) -> Result<Duration, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.modified().await
        }
    }

    /// Search for items based on their attributes.
    pub async fn search_items(
        &self,
        attributes: &impl AsAttributes,
    ) -> Result<Vec<Item<'a>>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let items = self.inner.search_items(attributes).await?;
            Ok(items
                .into_iter()
                .map(|item| {
                    Item::new(
                        Arc::clone(&self.service),
                        Arc::clone(&self.session),
                        self.algorithm,
                        item,
                        self.aes_key.clone(), // Cheap clone, it is an Arc,
                    )
                })
                .collect::<Vec<_>>())
        }
    }

    /// Create a new item on the collection
    ///
    /// # Arguments
    ///
    /// * `label` - A user visible label of the item.
    /// * `attributes` - A map of key/value attributes, used to find the item
    ///   later.
    /// * `secret` - The secret to store.
    /// * `replace` - Whether to replace the value if the `attributes` matches
    ///   an existing `secret`.
    /// * `content_type` - The content type of the secret, usually something
    ///   like `text/plain`.
    pub async fn create_item(
        &self,
        label: &str,
        attributes: &impl AsAttributes,
        secret: impl AsRef<[u8]>,
        replace: bool,
        content_type: &str,
        window_id: Option<WindowIdentifier>,
    ) -> Result<Item<'a>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = match self.algorithm {
                Algorithm::Plain => {
                    api::Secret::new(Arc::clone(&self.session), secret, content_type)
                }
                Algorithm::Encrypted => api::Secret::new_encrypted(
                    Arc::clone(&self.session),
                    secret,
                    content_type,
                    self.aes_key.as_ref().unwrap(),
                ),
            };
            let item = self
                .inner
                .create_item(label, attributes, &secret, replace, window_id)
                .await?;

            Ok(self.new_item(item))
        }
    }

    /// Unlock the collection.
    pub async fn unlock(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service
                .unlock(&[self.inner.inner().path()], window_id)
                .await?;
            Ok(())
        }
    }

    /// Lock the collection.
    pub async fn lock(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service
                .lock(&[self.inner.inner().path()], window_id)
                .await?;
            Ok(())
        }
    }

    /// Delete the collection.
    pub async fn delete(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.delete(window_id).await?;
            *self.available.write().await = false;
            Ok(())
        }
    }

    /// Returns collection path
    pub fn path(&self) -> &ObjectPath<'_> {
        self.inner.inner().path()
    }

    /// Stream yielding when new items get created
    pub async fn receive_item_created(&self) -> Result<impl Stream<Item = Item<'a>> + '_, Error> {
        Ok(self
            .inner
            .receive_item_created()
            .await?
            .map(|item| self.new_item(item)))
    }

    /// Stream yielding when existing items get changed
    pub async fn receive_item_changed(&self) -> Result<impl Stream<Item = Item<'a>> + '_, Error> {
        Ok(self
            .inner
            .receive_item_changed()
            .await?
            .map(|item| self.new_item(item)))
    }

    /// Stream yielding when existing items get deleted
    pub async fn receive_item_deleted(&self) -> Result<impl Stream<Item = OwnedObjectPath>, Error> {
        self.inner.receive_item_deleted().await
    }

    // Get public `Item`` from `api::Item`
    fn new_item(&self, item: api::Item<'a>) -> Item<'a> {
        Item::new(
            Arc::clone(&self.service),
            Arc::clone(&self.session),
            self.algorithm,
            item,
            self.aes_key.clone(), // Cheap clone, it is an Arc,
        )
    }
}

#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "local_tests"))]
mod tests {
    use std::collections::HashMap;

    use crate::dbus::Service;

    async fn create_item(service: Service<'_>, encrypted: bool) {
        let mut attributes = HashMap::new();
        let value = if encrypted {
            "encrypted-type-test"
        } else {
            "plain-type-test"
        };
        attributes.insert("type", value);
        let secret = "a password".as_bytes();

        let collection = service.default_collection().await.unwrap();
        let n_items = collection.items().await.unwrap().len();
        let n_search_items = collection.search_items(&attributes).await.unwrap().len();

        let item = collection
            .create_item("A secret", &attributes, secret, true, "text/plain", None)
            .await
            .unwrap();

        assert_eq!(*item.secret().await.unwrap(), secret);
        assert_eq!(item.attributes().await.unwrap()["type"], value);

        assert_eq!(collection.items().await.unwrap().len(), n_items + 1);
        assert_eq!(
            collection.search_items(&attributes).await.unwrap().len(),
            n_search_items + 1
        );

        item.delete(None).await.unwrap();

        assert_eq!(collection.items().await.unwrap().len(), n_items);
        assert_eq!(
            collection.search_items(&attributes).await.unwrap().len(),
            n_search_items
        );
    }

    #[tokio::test]
    async fn create_plain_item() {
        let service = Service::plain().await.unwrap();
        create_item(service, false).await;
    }

    #[tokio::test]
    async fn create_encrypted_item() {
        let service = Service::encrypted().await.unwrap();
        create_item(service, true).await;
    }
}
