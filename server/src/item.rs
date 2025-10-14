// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
};

use oo7::{
    dbus::{ServiceError, api::DBusSecretInner},
    file,
};
use tokio::sync::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Service, collection::Collection, error::custom_service_error};

#[derive(Debug, Clone)]
pub struct Item {
    // Properties
    locked: Arc<AtomicBool>,
    inner: Arc<Mutex<oo7::file::Item>>,
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
        let DBusSecretInner(session, iv, secret, _content_type) = secret;

        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

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

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
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
    pub async fn set_attributes(&self, attributes: HashMap<String, String>) {
        self.inner.lock().await.set_attributes(&attributes);
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.inner.lock().await.label().to_owned()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) {
        self.inner.lock().await.set_label(label);
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
        item: file::Item,
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
            .store(locked, std::sync::atomic::Ordering::Relaxed);
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

    use super::*;

    #[tokio::test]
    async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(session, secret);

        let item = collections[0]
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

        // Set label
        item.set_label("New Label").await?;

        // Verify new label
        let label = item.label().await?;
        assert_eq!(label, "New Label");

        Ok(())
    }

    #[tokio::test]
    async fn attributes_property() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(session, secret);

        let item = collections[0]
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

        // Set new attributes
        item.set_attributes(&[("app", "chrome"), ("username", "newuser@example.com")])
            .await?;

        // Verify new attributes
        let attrs = item.attributes().await?;
        assert_eq!(attrs.get("app").unwrap(), "chrome");
        assert_eq!(attrs.get("username").unwrap(), "newuser@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(session, secret);

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
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("my-secret-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&session), secret.clone());

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Retrieve secret
        let retrieved_secret = item.secret(&session).await?;
        assert_eq!(retrieved_secret.value(), secret.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn secret_retrieval_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        // Open encrypted session
        let client_private_key = oo7::Key::generate_private_key()?;
        let client_public_key = oo7::Key::generate_public_key(&client_private_key)?;

        let (server_public_key_opt, session) =
            service_api.open_session(Some(client_public_key)).await?;

        let server_public_key = server_public_key_opt.unwrap();
        let aes_key = oo7::Key::generate_aes_key(&client_private_key, &server_public_key)?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("my-encrypted-secret");
        let dbus_secret =
            dbus::api::DBusSecret::new_encrypted(Arc::clone(&session), secret.clone(), &aes_key)?;

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Retrieve secret
        let retrieved_secret = item.secret(&session).await?;
        // TODO: ensure the server implementation stores the content-type attribute
        assert_eq!(
            retrieved_secret
                .decrypt(Some(&Arc::new(aes_key)))?
                .as_bytes(),
            secret.as_bytes()
        );

        Ok(())
    }

    #[tokio::test]
    async fn delete_item() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(session, secret);

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify item exists
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 1);

        // Delete item
        item.delete(None).await?;

        // Verify item is deleted
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 0, "Item should be deleted from collection");
        Ok(())
    }

    #[tokio::test]
    async fn set_secret_plain() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;
        let (_aes_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let original_secret = oo7::Secret::text("original-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&session), original_secret.clone());

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify original secret
        let retrieved = item.secret(&session).await?;
        assert_eq!(retrieved.value(), original_secret.as_bytes());

        // Update the secret
        let new_secret = oo7::Secret::text("new-password");
        let new_dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&session), new_secret.clone());
        item.set_secret(&new_dbus_secret).await?;

        // Verify updated secret
        let retrieved = item.secret(&session).await?;
        assert_eq!(retrieved.value(), new_secret.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn set_secret_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        // Open encrypted session
        let client_private_key = oo7::Key::generate_private_key()?;
        let client_public_key = oo7::Key::generate_public_key(&client_private_key)?;

        let (server_public_key_opt, session) =
            service_api.open_session(Some(client_public_key)).await?;

        let server_public_key = server_public_key_opt.unwrap();
        let aes_key = Arc::new(oo7::Key::generate_aes_key(
            &client_private_key,
            &server_public_key,
        )?);
        let session = Arc::new(session);

        let collections = service_api.collections().await?;
        let original_secret = oo7::Secret::text("original-encrypted-password");
        let dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&session),
            original_secret.clone(),
            &aes_key,
        )?;

        let item = collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify original secret
        let retrieved = item.secret(&session).await?;
        assert_eq!(
            retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
            original_secret.as_bytes()
        );

        // Update the secret
        let new_secret = oo7::Secret::text("new-encrypted-password");
        let new_dbus_secret = dbus::api::DBusSecret::new_encrypted(
            Arc::clone(&session),
            new_secret.clone(),
            &aes_key,
        )?;
        item.set_secret(&new_dbus_secret).await?;

        // Verify updated secret
        let retrieved = item.secret(&session).await?;
        assert_eq!(
            retrieved.decrypt(Some(&aes_key.clone()))?.as_bytes(),
            new_secret.as_bytes()
        );

        Ok(())
    }
}
