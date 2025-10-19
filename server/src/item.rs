// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
};

use oo7::dbus::{ServiceError, api::DBusSecretInner};
use tokio::sync::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Service, collection::Collection, error::custom_service_error};

#[derive(Debug, Clone)]
pub struct Item {
    // Properties
    locked: Arc<AtomicBool>,
    inner: Arc<Mutex<oo7::file::UnlockedItem>>,
    // Other attributes
    service: Service,
    collection_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("Prompt"))]
    pub async fn delete(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let Some(collection) = self
            .service
            .collection_from_path(&self.collection_path)
            .await
        else {
            return Err(ServiceError::NoSuchObject(format!(
                "Collection `{}` does not exist.",
                &self.collection_path
            )));
        };

        collection.delete_item(&self.path).await?;
        object_server.remove::<Self, _>(&self.path).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_deleted(&signal_emitter, &self.path).await?;

        tracing::info!("Item `{}` deleted.", &self.path);

        Ok(OwnedObjectPath::default())
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(DBusSecretInner,), ServiceError> {
        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        if self.is_locked().await {
            tracing::error!("Cannot get secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot get secret of a locked object `{}`.",
                self.path
            )));
        }

        let inner = self.inner.lock().await;
        let secret = inner.secret();
        let content_type = secret.content_type();

        tracing::debug!("Secret retrieved from the item: {}.", self.path);

        match session.aes_key() {
            Some(key) => {
                let iv = oo7::crypto::generate_iv().map_err(|err| {
                    custom_service_error(&format!("Failed to generate iv {err}."))
                })?;
                let encrypted = oo7::crypto::encrypt(secret, &key, &iv).map_err(|err| {
                    custom_service_error(&format!("Failed to encrypt secret {err}."))
                })?;

                Ok((DBusSecretInner(
                    session.path().clone().into(),
                    iv,
                    encrypted,
                    content_type,
                ),))
            }
            None => Ok((DBusSecretInner(
                session.path().clone().into(),
                Vec::new(),
                secret.to_vec(),
                content_type,
            ),)),
        }
    }

    pub async fn set_secret(&self, secret: DBusSecretInner) -> Result<(), ServiceError> {
        let DBusSecretInner(session, iv, secret, content_type) = secret;

        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        if self.is_locked().await {
            tracing::error!("Cannot set secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot set secret of a locked object `{}`.",
                self.path
            )));
        }

        let mut inner = self.inner.lock().await;

        match session.aes_key() {
            Some(key) => {
                let decrypted = oo7::crypto::decrypt(secret, &key, &iv).map_err(|err| {
                    custom_service_error(&format!("Failed to decrypt secret {err}."))
                })?;
                inner.set_secret(decrypted);
            }
            None => {
                inner.set_secret(secret);
            }
        }

        // Ensure content-type attribute is stored
        let mut attributes = inner.attributes().clone();
        if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
            attributes.insert(
                oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                content_type.as_str().into(),
            );
        } else {
            attributes
                .entry(oo7::CONTENT_TYPE_ATTRIBUTE.to_string())
                .and_modify(|v| *v = content_type.as_str().into());
        }
        inner.set_attributes(&attributes);

        drop(inner);

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        if let Ok(signal_emitter) = self.service.signal_emitter(&self.path) {
            if let Err(err) = self.modified_changed(&signal_emitter).await {
                tracing::error!(
                    "Failed to emit PropertiesChanged signal for Modified: {}",
                    err
                );
            }
        }

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Acquire)
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> HashMap<String, String> {
        self.inner
            .lock()
            .await
            .attributes()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect()
    }

    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set attributes of a locked object `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set attributes of a locked object `{}`.", self.path),
            ))));
        }

        self.inner.lock().await.set_attributes(&attributes);

        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.attributes_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;
        Ok(())
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.inner.lock().await.label().to_owned()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set label of a locked object `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set label of a locked object `{}`.", self.path),
            ))));
        }

        self.inner.lock().await.set_label(label);
        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        Ok(())
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> u64 {
        self.inner.lock().await.created().as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.inner.lock().await.modified().as_secs()
    }
}

impl Item {
    pub fn new(
        item: oo7::file::UnlockedItem,
        locked: bool,
        service: Service,
        collection_path: OwnedObjectPath,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            locked: Arc::new(AtomicBool::new(locked)),
            inner: Arc::new(Mutex::new(item)),
            path,
            collection_path,
            service,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn set_locked(&self, locked: bool) -> Result<(), ServiceError> {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Release);
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Item: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oo7::dbus;
    use tokio_stream::StreamExt;

    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret);

        let item = setup.collections[0]
            .create_item(
                "Original Label",
                &[("app", "test")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Get label
        let label = item.label().await?;
        assert_eq!(label, "Original Label");

        // Get initial modified timestamp
        let initial_modified = item.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Set label
        item.set_label("New Label").await?;

        // Verify new label
        let label = item.label().await?;
        assert_eq!(label, "New Label");

        // Verify modified timestamp was updated
        let new_modified = item.modified().await?;
        println!("New modified: {:?}", new_modified);
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after label change (initial: {:?}, new: {:?})",
            initial_modified,
            new_modified
        );

        Ok(())
    }

    #[tokio::test]
    async fn attributes_property() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret);

        let item = setup.collections[0]
            .create_item(
                "Test Item",
                &[("app", "firefox"), ("username", "user@example.com")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Get attributes
        let attrs = item.attributes().await?;
        assert_eq!(attrs.get("app").unwrap(), "firefox");
        assert_eq!(attrs.get("username").unwrap(), "user@example.com");

        // Get initial modified timestamp
        let initial_modified = item.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Set new attributes
        item.set_attributes(&[("app", "chrome"), ("username", "newuser@example.com")])
            .await?;

        // Verify new attributes
        let attrs = item.attributes().await?;
        assert_eq!(attrs.get("app").unwrap(), "chrome");
        assert_eq!(attrs.get("username").unwrap(), "newuser@example.com");

        // Verify modified timestamp was updated
        let new_modified = item.modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after attributes change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let collections = setup.service_api.collections().await?;
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret);

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Get created timestamp
        let created = item.created().await?;
        assert!(created.as_secs() > 0, "Created timestamp should be set");

        // Get modified timestamp
        let modified = item.modified().await?;
        assert!(modified.as_secs() > 0, "Modified timestamp should be set");

        // Created and modified should be close (within a second for new item)
        let diff = if created > modified {
            created.as_secs() - modified.as_secs()
        } else {
            modified.as_secs() - created.as_secs()
        };
        assert!(diff <= 1, "Created and modified should be within 1 second");
        Ok(())
    }

    #[tokio::test]
    async fn secret_retrieval_plain() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::blob(b"my-secret-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Retrieve secret
        let retrieved_secret = item.secret(&setup.session).await?;
        assert_eq!(retrieved_secret.value(), secret.as_bytes());

        // Verify content-type is preserved
        assert_eq!(
            retrieved_secret.content_type(),
            secret.content_type(),
            "Content-type should be preserved"
        );
        Ok(())
    }

    #[tokio::test]
    async fn secret_retrieval_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;

        let aes_key = setup.aes_key.as_ref().unwrap();
        let secret = oo7::Secret::text("my-encrypted-secret");
        let dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            secret.clone(),
            aes_key,
        )?;

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Retrieve secret
        let retrieved_secret = item.secret(&setup.session).await?;
        assert_eq!(
            retrieved_secret.decrypt(Some(&aes_key.clone()))?.as_bytes(),
            secret.as_bytes()
        );
        // Verify content-type is preserved
        assert_eq!(
            retrieved_secret
                .decrypt(Some(&aes_key.clone()))?
                .content_type(),
            secret.content_type(),
            "Content-type should be preserved"
        );

        Ok(())
    }

    #[tokio::test]
    async fn delete_item() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify item exists
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1);

        // Delete item
        item.delete(None).await?;

        // Verify item is deleted
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 0, "Item should be deleted from collection");
        Ok(())
    }

    #[tokio::test]
    async fn set_secret_plain() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let original_secret = oo7::Secret::text("original-password");
        let dbus_secret =
            dbus::api::DBusSecret::new(Arc::clone(&setup.session), original_secret.clone());

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify original secret
        let retrieved = item.secret(&setup.session).await?;
        assert_eq!(retrieved.value(), original_secret.as_bytes());
        assert_eq!(
            retrieved.content_type(),
            original_secret.content_type(),
            "Content-type should be preserved"
        );

        // Get initial modified timestamp
        let initial_modified = item.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Update the secret
        let new_secret = oo7::Secret::blob(b"new-password");
        let new_dbus_secret =
            dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret.clone());
        item.set_secret(&new_dbus_secret).await?;

        // Verify updated secret
        let retrieved = item.secret(&setup.session).await?;
        assert_eq!(retrieved.value(), new_secret.as_bytes());
        assert_eq!(
            retrieved.content_type(),
            new_secret.content_type(),
            "Content-type should be preserved"
        );

        // Verify modified timestamp was updated
        let new_modified = item.modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after secret change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_secret_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let aes_key = setup.aes_key.unwrap();

        let original_secret = oo7::Secret::text("original-encrypted-password");
        let dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            original_secret.clone(),
            &aes_key,
        )?;

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify original secret
        let retrieved = item.secret(&setup.session).await?;
        assert_eq!(
            retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
            original_secret.as_bytes()
        );

        // Get initial modified timestamp
        let initial_modified = item.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Update the secret
        let new_secret = oo7::Secret::text("new-encrypted-password");
        let new_dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&setup.session),
            new_secret.clone(),
            &aes_key,
        )?;
        item.set_secret(&new_dbus_secret).await?;

        // Verify updated secret
        let retrieved = item.secret(&setup.session).await?;
        assert_eq!(
            retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
            new_secret.as_bytes()
        );

        // Verify modified timestamp was updated
        let new_modified = item.modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after secret change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Try to get secret with invalid session path
        let invalid_session =
            oo7::dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?;
        let result = item.secret(&invalid_session).await;

        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::NoSession(_)
                ))
            ),
            "Should be NoSession error"
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_secret_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        let new_secret = oo7::Secret::text("new-secret");
        let invalid_dbus_secret = dbus::api::DBusSecret::new(
            Arc::new(dbus::api::Session::new(&setup.client_conn, "/invalid/session").await?),
            new_secret,
        );

        let result = item.set_secret(&invalid_dbus_secret).await;

        // Should return NoSession error
        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::NoSession(_)
                ))
            ),
            "Should be NoSession error"
        );

        Ok(())
    }

    #[tokio::test]
    async fn item_changed_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Subscribe to ItemChanged signal
        let signal_stream = setup.collections[0].receive_item_changed().await?;
        tokio::pin!(signal_stream);

        // Change the label
        item.set_label("Updated Label").await?;

        // Wait for signal
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive ItemChanged signal after label change"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_item = signal.unwrap();
        assert_eq!(
            signal_item.inner().path().as_str(),
            item.inner().path().as_str(),
            "Signal should contain the changed item path"
        );

        // Change attributes and verify signal again
        item.set_attributes(&[("app", "updated-app")]).await?;

        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive ItemChanged signal after attributes change"
        );

        // Change secret and verify signal again
        let new_secret = oo7::Secret::text("new-secret");
        let new_dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret);
        item.set_secret(&new_dbus_secret).await?;

        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive ItemChanged signal after secret change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn locked_item_operations() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item
        let secret = oo7::Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify item is unlocked initially
        assert!(!item.is_locked().await?, "Item should start unlocked");

        // Lock the collection (which locks the item)
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection.set_locked(true).await?;

        // Verify item is now locked
        assert!(
            item.is_locked().await?,
            "Item should be locked after locking collection"
        );

        // Test 1: get_secret should fail with IsLocked
        let result = item.secret(&setup.session).await;
        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::IsLocked(_)
                ))
            ),
            "get_secret should fail with IsLocked error, got: {:?}",
            result
        );

        // Test 2: set_secret should fail with IsLocked
        let new_secret = oo7::Secret::text("new-password");
        let new_dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), new_secret);
        let result = item.set_secret(&new_dbus_secret).await;
        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::IsLocked(_)
                ))
            ),
            "set_secret should fail with IsLocked error, got: {:?}",
            result
        );

        // Test 3: set_attributes should fail with IsLocked
        let result = item.set_attributes(&[("app", "new-app")]).await;
        assert!(
            matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
            "set_attributes should fail with IsLocked error, got: {:?}",
            result
        );

        // Test 4: set_label should fail with IsLocked
        let result = item.set_label("New Label").await;
        assert!(
            matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
            "set_label should fail with IsLocked error, got: {:?}",
            result
        );

        // Verify read-only operations still work on locked items
        let label = item.label().await?;
        assert_eq!(
            label, "Test Item",
            "Should be able to read label of locked item"
        );

        let attrs = item.attributes().await?;
        assert_eq!(
            attrs.get("app").unwrap(),
            "test",
            "Should be able to read attributes of locked item"
        );

        Ok(())
    }
}
