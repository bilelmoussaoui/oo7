// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

use oo7::{
    dbus::{
        ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::Keyring,
};
use tokio::sync::{Mutex, RwLock};
use zbus::{interface, object_server::SignalEmitter, proxy::Defaults, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::{
    Service,
    error::{Error, custom_service_error},
    item,
};

#[derive(Debug, Clone)]
pub struct Collection {
    // Properties
    items: Arc<Mutex<Vec<item::Item>>>,
    label: Arc<Mutex<String>>,
    locked: Arc<AtomicBool>,
    created: Duration,
    modified: Arc<Mutex<Duration>>,
    // Other attributes
    alias: Arc<Mutex<String>>,
    #[allow(unused)]
    keyring: Arc<Keyring>,
    service: Service,
    item_index: Arc<RwLock<u32>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath<'_>, ServiceError> {
        todo!()
    }

    #[zbus(out_args("results"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, ServiceError> {
        let results = self
            .search_inner_items(&attributes)
            .await
            .iter()
            .map(|item| item.path().clone().into())
            .collect::<Vec<OwnedObjectPath>>();

        if results.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in collection: {}.",
                attributes,
                self.path
            );
        } else {
            tracing::debug!(
                "Items with attributes {:?} found in collection: {}.",
                attributes,
                self.path
            );
        }

        Ok(results)
    }

    #[zbus(out_args("item", "prompt"))]
    pub async fn create_item(
        &self,
        properties: Properties,
        secret: DBusSecretInner,
        replace: bool,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_emitter)] signal_emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), ServiceError> {
        let DBusSecretInner(session, iv, secret, _content_type) = secret;
        let label = properties.label();
        // Safe to unwrap as an item always has attributes
        let attributes = properties.attributes().unwrap();

        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        let secret = match session.aes_key() {
            Some(key) => oo7::crypto::decrypt(secret, &key, &iv)
                .map_err(|err| custom_service_error(&format!("Failed to decrypt secret {err}.")))?,
            None => zeroize::Zeroizing::new(secret),
        };

        let item = self
            .keyring
            .create_item(label, &attributes, secret, replace)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create a new item {err}.")))?;

        let n_items = *self.item_index.read().await;
        let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();

        let item = item::Item::new(
            item,
            false,
            self.service.clone(),
            self.path.clone(),
            item_path.clone(),
        );
        *self.item_index.write().await = n_items + 1;

        // Remove any existing items with the same attributes
        if replace {
            let existing_items = self.search_inner_items(&attributes).await;
            if !existing_items.is_empty() {
                let mut items = self.items.lock().await;
                for existing in &existing_items {
                    let existing_path = existing.path();

                    items.retain(|i| i.path() != existing_path);
                    object_server.remove::<item::Item, _>(existing_path).await?;
                    Self::item_deleted(&signal_emitter, existing_path).await?;

                    tracing::debug!("Replaced item `{}`", existing_path);
                }
                drop(items);
            }
        }

        self.items.lock().await.push(item.clone());

        object_server.at(&item_path, item).await?;

        Self::item_created(&signal_emitter, &item_path).await?;
        self.items_changed(&signal_emitter).await?;

        tracing::info!("Item `{item_path}` created.");

        Ok((item_path, OwnedObjectPath::default()))
    }

    #[zbus(property, name = "Items")]
    pub async fn items(&self) -> Vec<OwnedObjectPath> {
        self.items
            .lock()
            .await
            .iter()
            .map(|i| i.path().to_owned().into())
            .collect()
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.label.lock().await.clone()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) {
        *self.label.lock().await = label.to_owned();
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[zbus(property, name = "Created")]
    pub fn created_at(&self) -> u64 {
        self.created.as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.modified.lock().await.as_secs()
    }

    #[zbus(signal, name = "ItemCreated")]
    async fn item_created(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemDeleted")]
    pub async fn item_deleted(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemChanged")]
    pub async fn item_changed(
        signal_emitter: &SignalEmitter<'_>,
        item: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Collection {
    pub fn new(
        label: &str,
        alias: &str,
        locked: bool,
        service: Service,
        keyring: Arc<Keyring>,
    ) -> Self {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        Self {
            items: Default::default(),
            label: Arc::new(Mutex::new(label.to_owned())),
            locked: Arc::new(AtomicBool::new(locked)),
            modified: Arc::new(Mutex::new(created)),
            alias: Arc::new(Mutex::new(alias.to_owned())),
            item_index: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{label}"))
                .unwrap(),
            created,
            service,
            keyring,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn set_alias(&self, alias: &str) {
        *self.alias.lock().await = alias.to_owned();
    }

    pub async fn alias(&self) -> String {
        self.alias.lock().await.clone()
    }

    pub async fn search_inner_items(
        &self,
        attributes: &HashMap<String, String>,
    ) -> Vec<item::Item> {
        let mut items = Vec::new();

        for item in self.items.lock().await.iter() {
            let item_attributes = item.attributes().await;

            // Check if the (key, value) pairs in the requested attributes are
            // a subset of the attributes in the item being checked for in the
            // collection.
            let attributes_are_subset = attributes
                .iter()
                .all(|(key, value)| item_attributes.get(key) == Some(value));

            if attributes_are_subset {
                items.push(item.clone());
            }
        }

        items
    }

    pub async fn item_from_path(&self, path: &ObjectPath<'_>) -> Option<item::Item> {
        let items = self.items.lock().await;

        items.iter().find(|i| i.path() == path).cloned()
    }

    pub async fn set_locked(&self, locked: bool) -> Result<(), ServiceError> {
        let items = self.items.lock().await;

        for item in items.iter() {
            item.set_locked(locked).await?;
        }

        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Collection: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    pub async fn dispatch_items(&self) -> Result<(), Error> {
        let keyring_items = self.keyring.items().await?;
        let mut items = self.items.lock().await;
        let object_server = self.service.object_server();
        let mut n_items = 1;

        for keyring_item in keyring_items {
            let item_path = OwnedObjectPath::try_from(format!("{}/{n_items}", self.path)).unwrap();
            let item = item::Item::new(
                keyring_item.map_err(Error::InvalidItem)?,
                self.is_locked().await,
                self.service.clone(),
                self.path.clone(),
                item_path.clone(),
            );
            n_items += 1;

            items.push(item.clone());
            object_server.at(item_path, item).await?;
        }

        *self.item_index.write().await = n_items;

        Ok(())
    }

    pub async fn delete_item(&self, path: &ObjectPath<'_>) -> Result<(), ServiceError> {
        let Some(item) = self.item_from_path(path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Item `{path}` does not exist."
            )));
        };

        if item.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete a locked item `{path}`"
            )));
        }

        let attributes = item.attributes().await;
        self.keyring
            .delete(&attributes)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to deleted item {err}.")))?;

        let mut items = self.items.lock().await;
        items.retain(|item| item.path() != path);
        drop(items);

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.items_changed(&signal_emitter).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use oo7::dbus;

    use super::*;

    #[tokio::test]
    async fn create_item_plain() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;

        let _server = Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        // Open plain session
        let (_aes_key, session) = service_api.open_session(None).await?;

        // Get default collection
        let collections = service_api.collections().await?;

        // Create an item using the proper API
        let secret = oo7::Secret::text("my-secret-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::new(session), secret.clone());

        let item = collections[0]
            .create_item(
                "Test Item",
                &[("application", "test-app"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists in collection
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        // Verify item label
        let label = item.label().await?;
        assert_eq!(label, "Test Item");

        Ok(())
    }

    #[tokio::test]
    async fn create_item_encrypted() -> Result<(), Box<dyn std::error::Error>> {
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

        // Get default collection
        let collections = service_api.collections().await?;

        // Create an encrypted item using the proper API
        let secret = oo7::Secret::text("my-encrypted-secret");
        let dbus_secret =
            dbus::api::DBusSecret::new_encrypted(Arc::new(session), secret, &aes_key)?;

        let item = collections[0]
            .create_item(
                "Test Encrypted Item",
                &[("application", "test-app"), ("type", "encrypted-password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        Ok(())
    }

    #[tokio::test]
    async fn search_items_after_creation() -> Result<(), Box<dyn std::error::Error>> {
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

        // Create two items with different attributes
        let secret1 = oo7::Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&session), secret1);

        collections[0]
            .create_item(
                "Firefox Password",
                &[("application", "firefox"), ("username", "user1")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        let secret2 = oo7::Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&session), secret2);

        collections[0]
            .create_item(
                "Chrome Password",
                &[("application", "chrome"), ("username", "user2")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Search for firefox item
        let firefox_attrs = &[("application", "firefox")];
        let firefox_items = collections[0].search_items(firefox_attrs).await?;

        assert_eq!(firefox_items.len(), 1, "Should find one firefox item");

        // Search for chrome item
        let chrome_items = collections[0]
            .search_items(&[("application", "chrome")])
            .await?;

        assert_eq!(chrome_items.len(), 1, "Should find one chrome item");

        // Search for non-existent item
        let nonexistent_items = collections[0]
            .search_items(&[("application", "nonexistent")])
            .await?;

        assert_eq!(
            nonexistent_items.len(),
            0,
            "Should find no nonexistent items"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_with_replace() -> Result<(), Box<dyn std::error::Error>> {
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

        // Create first item
        let secret1 = oo7::Secret::text("original-password");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&session), secret1.clone());

        let item1 = collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Verify one item exists
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should have one item");

        // Get the secret from first item
        let retrieved1 = item1.secret(&session).await?;
        assert_eq!(retrieved1.value(), secret1.as_bytes());

        // Create second item with same attributes and replace=true
        let secret2 = oo7::Secret::text("replaced-password");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&session), secret2.clone());

        let item2 = collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret2,
                true, // replace=true
                None,
            )
            .await?;

        // Should still have only one item (replaced)
        let items = collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should still have one item after replace");

        // Verify the new item has the updated secret
        let retrieved2 = item2.secret(&session).await?;
        assert_eq!(retrieved2.value(), secret2.as_bytes());

        Ok(())
    }
}
