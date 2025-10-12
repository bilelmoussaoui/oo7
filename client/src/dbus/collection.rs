use std::{sync::Arc, time::Duration};

use ashpd::WindowIdentifier;
#[cfg(feature = "async-std")]
use async_lock::RwLock;
use futures_util::{Stream, StreamExt};
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::{Algorithm, Error, Item, api};
use crate::{AsAttributes, Key, Secret};

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
    pub async fn create_item(
        &self,
        label: &str,
        attributes: &impl AsAttributes,
        secret: impl Into<Secret>,
        replace: bool,
        window_id: Option<WindowIdentifier>,
    ) -> Result<Item<'a>, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = match self.algorithm {
                Algorithm::Plain => api::DBusSecret::new(Arc::clone(&self.session), secret),
                Algorithm::Encrypted => api::DBusSecret::new_encrypted(
                    Arc::clone(&self.session),
                    secret,
                    self.aes_key.as_ref().unwrap(),
                )?,
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
#[cfg(feature = "tokio")]
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
        let secret = crate::Secret::text("a password");

        let collection = service.default_collection().await.unwrap();
        let n_search_items = collection.search_items(&attributes).await.unwrap().len();

        let item = collection
            .create_item("A secret", &attributes, secret.clone(), true, None)
            .await
            .unwrap();

        assert_eq!(item.secret().await.unwrap(), secret);
        assert_eq!(item.attributes().await.unwrap()["type"], value);

        assert_eq!(
            collection.search_items(&attributes).await.unwrap().len(),
            n_search_items + 1
        );

        item.delete(None).await.unwrap();

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

    #[tokio::test]
    async fn attribute_search_patterns() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let secret = crate::Secret::text("search test");

        // Create items with unique test attributes
        let attrs1 = HashMap::from([("test-pattern", "pattern-test-a"), ("category", "group1")]);
        let item1 = collection
            .create_item("Pattern Test 1", &attrs1, secret.clone(), true, None)
            .await
            .unwrap();

        let attrs2 = HashMap::from([("test-pattern", "pattern-test-a"), ("category", "group2")]);
        let item2 = collection
            .create_item("Pattern Test 2", &attrs2, secret.clone(), true, None)
            .await
            .unwrap();

        let attrs3 = HashMap::from([("test-pattern", "pattern-test-b"), ("category", "group1")]);
        let item3 = collection
            .create_item("Pattern Test 3", &attrs3, secret.clone(), true, None)
            .await
            .unwrap();

        // Search by test-pattern - should find items with pattern-test-a
        let search_pattern_a = HashMap::from([("test-pattern", "pattern-test-a")]);
        let pattern_a_items = collection.search_items(&search_pattern_a).await.unwrap();
        let found_paths: std::collections::HashSet<_> =
            pattern_a_items.iter().map(|item| item.path()).collect();
        assert!(found_paths.contains(item1.path()));
        assert!(found_paths.contains(item2.path()));

        // Search by category - should find items in group1
        let search_group1 = HashMap::from([("category", "group1")]);
        let group1_items = collection.search_items(&search_group1).await.unwrap();
        let found_group1_paths: std::collections::HashSet<_> =
            group1_items.iter().map(|item| item.path()).collect();
        assert!(found_group1_paths.contains(item1.path()));
        assert!(found_group1_paths.contains(item3.path()));

        // Search by both attributes - should find only item1
        let search_specific =
            HashMap::from([("test-pattern", "pattern-test-a"), ("category", "group1")]);
        let specific_items = collection.search_items(&search_specific).await.unwrap();
        let found_specific_paths: std::collections::HashSet<_> =
            specific_items.iter().map(|item| item.path()).collect();
        assert!(found_specific_paths.contains(item1.path()));

        item1.delete(None).await.unwrap();
        item2.delete(None).await.unwrap();
        item3.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn items() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let secret = crate::Secret::text("items test");

        // Create some test items with unique attributes
        let attrs1 = HashMap::from([("test", "items-test-1"), ("unique", "test-1")]);
        let item1 = collection
            .create_item("Test Item 1", &attrs1, secret.clone(), true, None)
            .await
            .unwrap();

        let attrs2 = HashMap::from([("test", "items-test-2"), ("unique", "test-2")]);
        let item2 = collection
            .create_item("Test Item 2", &attrs2, secret.clone(), true, None)
            .await
            .unwrap();

        // Get all items and verify our items are included by path
        let all_items = collection.items().await.unwrap();
        let item_paths: std::collections::HashSet<_> =
            all_items.iter().map(|item| item.path()).collect();

        assert!(item_paths.contains(item1.path()));
        assert!(item_paths.contains(item2.path()));

        // Clean up
        item1.delete(None).await.unwrap();
        item2.delete(None).await.unwrap();
    }
}
