use std::{collections::HashMap, sync::Arc, time::Duration};

use ashpd::WindowIdentifier;
#[cfg(feature = "async-std")]
use async_lock::RwLock;
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;
use zbus::zvariant::ObjectPath;

use super::{Algorithm, Error, api};
use crate::{AsAttributes, Key, Secret};

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
    pub async fn set_attributes(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_attributes(attributes).await
        }
    }

    /// Delete the item.
    pub async fn delete(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.delete(window_id).await?;
            *self.available.write().await = false;
            Ok(())
        }
    }

    /// Retrieve the currently stored secret.
    pub async fn secret(&self) -> Result<Secret, Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner
                .secret(&self.session)
                .await?
                .decrypt(self.aes_key.as_ref())
        }
    }

    /// Modify the stored secret on the item.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to store.
    #[doc(alias = "SetSecret")]
    pub async fn set_secret(&self, secret: impl Into<Secret>) -> Result<(), Error> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = match self.algorithm {
                Algorithm::Plain => api::DBusSecret::new(Arc::clone(&self.session), secret),
                Algorithm::Encrypted => {
                    let aes_key = self.aes_key.as_ref().unwrap();
                    api::DBusSecret::new_encrypted(Arc::clone(&self.session), secret, aes_key)?
                }
            };
            self.inner.set_secret(&secret).await?;
            Ok(())
        }
    }

    /// Unlock the item.
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

    /// Lock the item.
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

    /// Returns item path
    pub fn path(&self) -> &ObjectPath<'_> {
        self.inner.inner().path()
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use crate::dbus::Service;

    #[tokio::test]
    async fn label_mutation() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let secret = crate::Secret::text("test secret");

        let item = collection
            .create_item(
                "Original Label",
                &[("test", "label-mutation")],
                secret,
                true,
                None,
            )
            .await
            .unwrap();

        let initial_label = item.label().await.unwrap();
        assert_eq!(initial_label, "Original Label");

        item.set_label("Updated Label").await.unwrap();

        let updated_label = item.label().await.unwrap();
        assert_eq!(updated_label, "Updated Label");

        item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn secret_mutation() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let original_secret = crate::Secret::text("original secret");

        let item = collection
            .create_item(
                "Secret Test",
                &[("test", "secret-mutation")],
                original_secret.clone(),
                true,
                None,
            )
            .await
            .unwrap();

        assert_eq!(item.secret().await.unwrap(), original_secret);

        let new_secret = crate::Secret::text("updated secret");
        item.set_secret(new_secret.clone()).await.unwrap();

        assert_eq!(item.secret().await.unwrap(), new_secret);

        item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn secret_mutation_encrypted() {
        let service = Service::encrypted().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let original_secret = crate::Secret::text("original encrypted secret");

        let item = collection
            .create_item(
                "Encrypted Secret Test",
                &[("test", "secret-mutation-encrypted")],
                original_secret.clone(),
                true,
                None,
            )
            .await
            .unwrap();

        assert_eq!(item.secret().await.unwrap(), original_secret);

        let new_secret = crate::Secret::text("updated encrypted secret");
        item.set_secret(new_secret.clone()).await.unwrap();

        assert_eq!(item.secret().await.unwrap(), new_secret);

        item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn attributes_mutation() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let secret = crate::Secret::text("test secret");

        let item = collection
            .create_item(
                "Attributes Test",
                &[("service", "email"), ("username", "user1")],
                secret,
                true,
                None,
            )
            .await
            .unwrap();

        let retrieved_attrs = item.attributes().await.unwrap();
        assert_eq!(retrieved_attrs.get("service"), Some(&"email".to_string()));
        assert_eq!(retrieved_attrs.get("username"), Some(&"user1".to_string()));

        item.set_attributes(&[
            ("service", "web"),
            ("username", "user2"),
            ("domain", "example.com"),
        ])
        .await
        .unwrap();

        let updated_attrs = item.attributes().await.unwrap();
        assert_eq!(updated_attrs.get("service"), Some(&"web".to_string()));
        assert_eq!(updated_attrs.get("username"), Some(&"user2".to_string()));
        assert_eq!(
            updated_attrs.get("domain"),
            Some(&"example.com".to_string())
        );
        assert!(!updated_attrs.contains_key("email")); // old attribute should be gone

        item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn text_secret_type() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let text_secret = crate::Secret::text("text password");
        let text_item = collection
            .create_item(
                "Text Secret",
                &[("type", "text-secret")],
                text_secret.clone(),
                true,
                None,
            )
            .await
            .unwrap();

        assert_eq!(text_item.secret().await.unwrap(), text_secret);
        text_item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn blob_secret_type() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let blob_secret = crate::Secret::blob(b"binary data");
        let blob_item = collection
            .create_item(
                "Blob Secret",
                &[("type", "blob-secret")],
                blob_secret.clone(),
                true,
                None,
            )
            .await
            .unwrap();

        let retrieved_secret = blob_item.secret().await.unwrap();

        // TODO: gnome-keyring doesn't preserve content types - everything becomes
        // text/plain But the actual secret data should be preserved
        assert_eq!(retrieved_secret.as_bytes(), blob_secret.as_bytes());
        blob_item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn timestamps() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let secret = crate::Secret::text("timestamp test");

        let item = collection
            .create_item(
                "Timestamp Test",
                &[("test", "timestamps")],
                secret,
                true,
                None,
            )
            .await
            .unwrap();

        let created = item.created().await.unwrap();
        let modified = item.modified().await.unwrap();

        eprintln!("Created: {:?}, Modified: {:?}", created, modified);
        assert_eq!(created, modified);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        item.set_label("Updated Label").await.unwrap();

        // Allow time for D-Bus changes to propagate
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let new_modified = item.modified().await.unwrap();
        assert!(new_modified > modified);
        assert_eq!(item.created().await.unwrap(), created);

        item.delete(None).await.unwrap();
    }

    #[tokio::test]
    async fn deleted_error() {
        let service = Service::plain().await.unwrap();
        let collection = service.default_collection().await.unwrap();

        let attributes = &[("test", "deleted-error")];
        let secret = crate::Secret::text("delete test");

        let item = collection
            .create_item("Delete Test", attributes, secret, true, None)
            .await
            .unwrap();

        // Verify item works before deletion
        assert!(item.label().await.is_ok());

        // Delete the item
        item.delete(None).await.unwrap();

        // All operations should now return Error::Deleted
        assert!(matches!(item.label().await, Err(super::Error::Deleted)));
        assert!(matches!(
            item.set_label("New").await,
            Err(super::Error::Deleted)
        ));
        assert!(matches!(item.secret().await, Err(super::Error::Deleted)));
        assert!(matches!(
            item.set_secret("new secret").await,
            Err(super::Error::Deleted)
        ));
        assert!(matches!(
            item.attributes().await,
            Err(super::Error::Deleted)
        ));
        assert!(matches!(
            item.set_attributes(attributes).await,
            Err(super::Error::Deleted)
        ));
        assert!(matches!(item.created().await, Err(super::Error::Deleted)));
        assert!(matches!(item.modified().await, Err(super::Error::Deleted)));
        assert!(matches!(item.is_locked().await, Err(super::Error::Deleted)));
        assert!(matches!(item.lock(None).await, Err(super::Error::Deleted)));
        assert!(matches!(
            item.unlock(None).await,
            Err(super::Error::Deleted)
        ));
        assert!(matches!(
            item.delete(None).await,
            Err(super::Error::Deleted)
        ));
    }
}
