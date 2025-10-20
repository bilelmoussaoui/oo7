// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use oo7::{
    Secret,
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
    created: Duration,
    modified: Arc<Mutex<Duration>>,
    // Other attributes
    alias: Arc<Mutex<String>>,
    pub(crate) keyring: Arc<RwLock<Option<Keyring>>>,
    service: Service,
    item_index: Arc<RwLock<u32>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath<'_>, ServiceError> {
        // Check if collection is locked
        if self.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete locked collection `{}`",
                self.path
            )));
        }

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let object_server = self.service.object_server();

        // Remove all items from the object server
        let items = self.items.lock().await;
        for item in items.iter() {
            object_server.remove::<item::Item, _>(item.path()).await?;
        }
        drop(items);

        // Delete the keyring file if it's persistent
        if let Some(path) = keyring.path() {
            tokio::fs::remove_file(&path).await.map_err(|err| {
                custom_service_error(&format!("Failed to delete keyring file: {err}"))
            })?;
            tracing::debug!("Deleted keyring file: {}", path.display());
        }

        // Emit CollectionDeleted signal before removing from object server
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_deleted(&signal_emitter, &self.path).await?;

        // Remove collection from object server
        object_server.remove::<Collection, _>(&self.path).await?;

        // Notify service to remove from collections list
        self.service.remove_collection(&self.path).await;

        tracing::info!("Collection `{}` deleted.", self.path);

        // Return empty prompt path (no prompt needed, per gnome-keyring behaviour)
        Ok(ObjectPath::default())
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
        if self.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot create item in locked collection `{}`",
                self.path
            )));
        }

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let DBusSecretInner(session, iv, secret, content_type) = secret;
        let label = properties.label();
        // Safe to unwrap as an item always has attributes
        let mut attributes = properties.attributes().unwrap().to_owned();

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

        // Ensure content-type attribute is stored
        if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
            attributes.insert(
                oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                content_type.as_str().to_owned(),
            );
        }

        let item = keyring
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

        self.update_modified().await?;

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
    pub async fn set_label(&self, label: &str) -> Result<(), zbus::Error> {
        if self.is_locked().await {
            tracing::error!("Cannot set label of a locked collection `{}`", self.path);
            return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                format!("Cannot set label of a locked collection `{}`.", self.path),
            ))));
        }

        *self.label.lock().await = label.to_owned();

        self.update_modified()
            .await
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self
            .service
            .signal_emitter(service_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.keyring
            .read()
            .await
            .as_ref()
            .map(|k| k.is_locked())
            .unwrap_or(true)
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
    pub fn new(label: &str, alias: &str, service: Service, keyring: Keyring) -> Self {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        Self {
            items: Default::default(),
            label: Arc::new(Mutex::new(label.to_owned())),
            modified: Arc::new(Mutex::new(created)),
            alias: Arc::new(Mutex::new(alias.to_owned())),
            item_index: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{label}"))
                .unwrap(),
            created,
            service,
            keyring: Arc::new(RwLock::new(Some(keyring))),
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

    pub async fn set_locked(
        &self,
        locked: bool,
        secret: Option<Secret>,
    ) -> Result<(), ServiceError> {
        let items = self.items.lock().await;
        for item in items.iter() {
            item.set_locked(locked).await?;
        }
        drop(items);

        let mut keyring_guard = self.keyring.write().await;

        if let Some(old_keyring) = keyring_guard.take() {
            let new_keyring = match (old_keyring, locked) {
                (Keyring::Unlocked(unlocked), true) => Keyring::Locked(unlocked.lock()),
                (Keyring::Locked(locked_kr), false) => {
                    let secret = secret.ok_or_else(|| {
                        custom_service_error("Cannot unlock collection without a secret")
                    })?;

                    let unlocked = locked_kr.unlock(secret).await.map_err(|err| {
                        custom_service_error(&format!("Failed to unlock keyring: {err}"))
                    })?;

                    Keyring::Unlocked(unlocked)
                }
                (other, _) => other,
            };
            *keyring_guard = Some(new_keyring);
        }

        drop(keyring_guard);

        // Emit signals
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
        if self.is_locked().await {
            return Ok(());
        }

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        let keyring_items = keyring.items().await?;
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

        if self.is_locked().await {
            return Err(ServiceError::IsLocked(format!(
                "Cannot delete an item `{path}`  in a locked collection "
            )));
        }

        let attributes = item.attributes().await;

        let keyring = self.keyring.read().await;
        let keyring = keyring.as_ref().unwrap().as_unlocked();

        keyring
            .delete(&attributes)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to deleted item {err}.")))?;

        let mut items = self.items.lock().await;
        items.retain(|item| item.path() != path);
        drop(items);

        self.update_modified().await?;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.items_changed(&signal_emitter).await?;

        Ok(())
    }

    /// Update the modified timestamp and emit the PropertiesChanged signal
    async fn update_modified(&self) -> Result<(), ServiceError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        *self.modified.lock().await = now;

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.modified_changed(&signal_emitter).await?;

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
    async fn create_item_plain() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get initial modified timestamp
        let initial_modified = setup.collections[0].modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Create an item using the proper API
        let secret = oo7::Secret::text("my-secret-password");
        let dbus_secret = dbus::api::DBusSecret::new(setup.session, secret.clone());

        let item = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "test-app"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists in collection
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        // Verify item label
        let label = item.label().await?;
        assert_eq!(label, "Test Item");

        // Verify modified timestamp was updated
        let new_modified = setup.collections[0].modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after creating item"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;
        let aes_key = setup.aes_key.unwrap();

        // Create an encrypted item using the proper API
        let secret = oo7::Secret::text("my-encrypted-secret");
        let dbus_secret = dbus::api::DBusSecret::new_encrypted(setup.session, secret, &aes_key)?;

        let item = setup.collections[0]
            .create_item(
                "Test Encrypted Item",
                &[("application", "test-app"), ("type", "encrypted-password")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item exists
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Collection should have one item");
        assert_eq!(items[0].inner().path(), item.inner().path());

        Ok(())
    }

    #[tokio::test]
    async fn search_items_after_creation() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create two items with different attributes
        let secret1 = oo7::Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item(
                "Firefox Password",
                &[("application", "firefox"), ("username", "user1")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        let secret2 = oo7::Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        setup.collections[0]
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
        let firefox_items = setup.collections[0].search_items(firefox_attrs).await?;

        assert_eq!(firefox_items.len(), 1, "Should find one firefox item");

        // Search for chrome item
        let chrome_items = setup.collections[0]
            .search_items(&[("application", "chrome")])
            .await?;

        assert_eq!(chrome_items.len(), 1, "Should find one chrome item");

        // Search for non-existent item
        let nonexistent_items = setup.collections[0]
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
    async fn search_items_subset_matching() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item with multiple attributes (url and username)
        let secret = oo7::Secret::text("my-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        setup.collections[0]
            .create_item(
                "Zed Login",
                &[("url", "https://zed.dev"), ("username", "alice")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Search with only the url attribute (subset of stored attributes)
        let results = setup.collections[0]
            .search_items(&[("url", "https://zed.dev")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with subset of its attributes"
        );

        // Search with only the username attribute (another subset)
        let results = setup.collections[0]
            .search_items(&[("username", "alice")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with different subset of its attributes"
        );

        // Search with both attributes (exact match)
        let results = setup.collections[0]
            .search_items(&[("url", "https://zed.dev"), ("username", "alice")])
            .await?;

        assert_eq!(
            results.len(),
            1,
            "Should find item when searching with all its attributes"
        );

        // Search with superset of attributes (should not match)
        let results = setup.collections[0]
            .search_items(&[
                ("url", "https://zed.dev"),
                ("username", "alice"),
                ("extra", "attribute"),
            ])
            .await?;

        assert_eq!(
            results.len(),
            0,
            "Should not find item when searching with superset of its attributes"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_item_with_replace() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create first item
        let secret1 = oo7::Secret::text("original-password");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1.clone());

        let item1 = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Verify one item exists
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should have one item");

        // Get the secret from first item
        let retrieved1 = item1.secret(&setup.session).await?;
        assert_eq!(retrieved1.value(), secret1.as_bytes());

        // Create second item with same attributes and replace=true
        let secret2 = oo7::Secret::text("replaced-password");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2.clone());

        let item2 = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "myapp"), ("username", "user")],
                &dbus_secret2,
                true, // replace=true
                None,
            )
            .await?;

        // Should still have only one item (replaced)
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 1, "Should still have one item after replace");

        // Verify the new item has the updated secret
        let retrieved2 = item2.secret(&setup.session).await?;
        assert_eq!(retrieved2.value(), secret2.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn label_property() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get the Login collection via alias (don't rely on collection ordering)
        let login_collection = setup
            .service_api
            .read_alias("default")
            .await?
            .expect("Default collection should exist");

        // Get initial label (should be "Login" for default collection)
        let label = login_collection.label().await?;
        assert_eq!(label, "Login");

        // Get initial modified timestamp
        let initial_modified = login_collection.modified().await?;

        // Wait to ensure timestamp will be different
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Set new label
        login_collection.set_label("My Custom Collection").await?;

        // Verify new label
        let label = login_collection.label().await?;
        assert_eq!(label, "My Custom Collection");

        // Verify modified timestamp was updated
        let new_modified = login_collection.modified().await?;
        assert!(
            new_modified > initial_modified,
            "Modified timestamp should be updated after label change"
        );

        Ok(())
    }

    #[tokio::test]
    async fn timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get created timestamp
        let created = setup.collections[0].created().await?;
        assert!(created.as_secs() > 0, "Created timestamp should be set");

        // Get modified timestamp
        let modified = setup.collections[0].modified().await?;
        assert!(modified.as_secs() > 0, "Modified timestamp should be set");

        // Created and modified should be close (within a second for new collection)
        let diff = if created > modified {
            created.as_secs() - modified.as_secs()
        } else {
            modified.as_secs() - created.as_secs()
        };
        assert!(diff <= 1, "Created and modified should be within 1 second");

        Ok(())
    }

    #[tokio::test]
    async fn create_item_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item using the proper API
        let secret = oo7::Secret::text("my-secret-password");
        let invalid_session =
            dbus::api::Session::new(&setup.client_conn, "/invalid/session/path").await?;
        let dbus_secret = dbus::api::DBusSecret::new(Arc::new(invalid_session), secret.clone());

        let result = setup.collections[0]
            .create_item(
                "Test Item",
                &[("application", "test-app"), ("type", "password")],
                &dbus_secret,
                false,
                None,
            )
            .await;

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
    async fn item_created_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to ItemCreated signal
        let signal_stream = setup.collections[0].receive_item_created().await?;
        tokio::pin!(signal_stream);

        // Create an item
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(signal_result.is_ok(), "Should receive ItemCreated signal");
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_item = signal.unwrap();
        assert_eq!(
            signal_item.inner().path().as_str(),
            item.inner().path().as_str(),
            "Signal should contain the created item path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn item_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item
        let secret = oo7::Secret::text("test-secret");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        let item_path = item.inner().path().to_owned();

        // Subscribe to ItemDeleted signal
        let signal_stream = setup.collections[0].receive_item_deleted().await?;
        tokio::pin!(signal_stream);

        // Delete the item
        item.delete(None).await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(signal_result.is_ok(), "Should receive ItemDeleted signal");
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_item = signal.unwrap();
        assert_eq!(
            signal_item.as_str(),
            item_path.as_str(),
            "Signal should contain the deleted item path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn collection_changed_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to CollectionChanged signal
        let signal_stream = setup.service_api.receive_collection_changed().await?;
        tokio::pin!(signal_stream);

        // Change the collection label
        setup.collections[0]
            .set_label("Updated Collection Label")
            .await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive CollectionChanged signal after label change"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_collection = signal.unwrap();
        assert_eq!(
            signal_collection.inner().path().as_str(),
            setup.collections[0].inner().path().as_str(),
            "Signal should contain the changed collection path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn delete_collection() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create some items in the collection
        let secret1 = oo7::Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item("Item 1", &[("app", "test")], &dbus_secret1, false, None)
            .await?;

        let secret2 = oo7::Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        setup.collections[0]
            .create_item("Item 2", &[("app", "test")], &dbus_secret2, false, None)
            .await?;

        // Verify items were created
        let items = setup.collections[0].items().await?;
        assert_eq!(items.len(), 2, "Should have 2 items before deletion");

        // Get collection path for later verification
        let collection_path = setup.collections[0].inner().path().to_owned();

        // Verify collection exists in service
        let collections_before = setup.service_api.collections().await?;
        let initial_count = collections_before.len();

        // Delete the collection
        setup.collections[0].delete(None).await?;

        // Give the system a moment to process the deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify collection is no longer in service's collection list
        let collections_after = setup.service_api.collections().await?;
        assert_eq!(
            collections_after.len(),
            initial_count - 1,
            "Service should have one less collection after deletion"
        );

        // Verify the specific collection is not in the list
        let collection_paths: Vec<_> = collections_after
            .iter()
            .map(|c| c.inner().path().as_str())
            .collect();
        assert!(
            !collection_paths.contains(&collection_path.as_str()),
            "Deleted collection should not be in service collections list"
        );

        Ok(())
    }

    #[tokio::test]
    async fn collection_deleted_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to CollectionDeleted signal
        let signal_stream = setup.service_api.receive_collection_deleted().await?;
        tokio::pin!(signal_stream);

        let collection_path = setup.collections[0].inner().path().to_owned();

        // Delete the collection
        setup.collections[0].delete(None).await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive CollectionDeleted signal"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_collection = signal.unwrap();
        assert_eq!(
            signal_collection.as_str(),
            collection_path.as_str(),
            "Signal should contain the deleted collection path"
        );

        Ok(())
    }

    #[tokio::test]
    async fn locked_collection_operations() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Verify collection is unlocked initially
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should start unlocked"
        );

        // Lock the collection
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        // Verify collection is now locked
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked"
        );

        // Test 1: delete should fail with IsLocked
        let result = setup.collections[0].delete(None).await;
        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::IsLocked(_)
                ))
            ),
            "delete should fail with IsLocked error, got: {:?}",
            result
        );

        // Test 2: create_item should fail with IsLocked
        let secret = oo7::Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);
        let result = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await;
        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::IsLocked(_)
                ))
            ),
            "create_item should fail with IsLocked error, got: {:?}",
            result
        );

        // Test 3: set_label should fail with IsLocked
        let result = setup.collections[0].set_label("New Label").await;
        assert!(
            matches!(result, Err(oo7::dbus::Error::ZBus(zbus::Error::FDO(_)))),
            "set_label should fail with IsLocked error, got: {:?}",
            result
        );

        // Verify read-only operations still work on locked collections
        assert!(
            setup.collections[0].label().await.is_ok(),
            "Should be able to read label of locked collection"
        );

        let items = setup.collections[0].items().await?;
        assert!(
            items.is_empty(),
            "Should be able to read items (empty) from locked collection"
        );

        Ok(())
    }
}
