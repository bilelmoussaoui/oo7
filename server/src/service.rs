// org.freedesktop.Secret.Service

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use oo7::{
    Key, Secret,
    dbus::{
        Algorithm, ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::Keyring,
};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::StreamExt;
use zbus::{
    names::{OwnedUniqueName, UniqueName},
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

use crate::{
    collection::Collection,
    error::{Error, custom_service_error},
    prompt::{Prompt, PromptRole},
    session::Session,
};

const DEFAULT_COLLECTION_ALIAS_PATH: ObjectPath<'static> =
    ObjectPath::from_static_str_unchecked("/org/freedesktop/secrets/aliases/default");

#[derive(Debug, Default, Clone)]
pub struct Service {
    // Properties
    collections: Arc<Mutex<Vec<Collection>>>,
    // Other attributes
    connection: Arc<OnceLock<zbus::Connection>>,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Session>>>,
    session_index: Arc<RwLock<u32>>,
    // prompts mapped to their corresponding object path on the bus
    prompts: Arc<Mutex<HashMap<OwnedObjectPath, Prompt>>>,
    prompt_index: Arc<RwLock<u32>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath), ServiceError> {
        let (public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted => {
                let client_public_key = Key::try_from(input).map_err(|err| {
                    custom_service_error(&format!(
                        "Input Value could not be converted into a Key {err}."
                    ))
                })?;
                let private_key = Key::generate_private_key().map_err(|err| {
                    custom_service_error(&format!("Failed to generate private key {err}."))
                })?;
                (
                    Some(Key::generate_public_key(&private_key).map_err(|err| {
                        custom_service_error(&format!("Failed to generate public key {err}."))
                    })?),
                    Some(
                        Key::generate_aes_key(&private_key, &client_public_key).map_err(|err| {
                            custom_service_error(&format!("Failed to generate aes key {err}."))
                        })?,
                    ),
                )
            }
        };

        let sender = if let Some(s) = header.sender() {
            s.to_owned()
        } else {
            #[cfg(test)]
            {
                // For p2p test connections, use a dummy sender since p2p connections
                // don't have a bus to assign unique names
                UniqueName::try_from(":p2p.test").unwrap().into()
            }
            #[cfg(not(test))]
            {
                return Err(custom_service_error("Failed to get sender from header."));
            }
        };

        tracing::info!("Client {} connected", sender);

        let session = Session::new(aes_key.map(Arc::new), self.clone(), sender).await;
        let path = OwnedObjectPath::from(session.path().clone());

        self.sessions
            .lock()
            .await
            .insert(path.clone(), session.clone());

        object_server.at(&path, session).await?;

        let service_key = public_key
            .map(OwnedValue::from)
            .unwrap_or_else(|| Value::new::<Vec<u8>>(vec![]).try_into_owned().unwrap());

        Ok((service_key, path))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        _properties: Properties,
        _alias: &str,
    ) -> Result<(OwnedObjectPath, ObjectPath<'_>), ServiceError> {
        todo!()
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        let collections = self.collections.lock().await;

        for collection in collections.iter() {
            let items = collection.search_inner_items(&attributes).await;
            for item in items {
                if item.is_locked().await {
                    locked.push(item.path().clone().into());
                } else {
                    unlocked.push(item.path().clone().into());
                }
            }
        }

        if unlocked.is_empty() && locked.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in any collection.",
                attributes
            );
        } else {
            tracing::debug!("Items with attributes {:?} found.", attributes);
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        let (unlocked, not_unlocked) = self.set_locked(false, &objects, false).await?;
        if !not_unlocked.is_empty() {
            let prompt = Prompt::new(self.clone(), not_unlocked, PromptRole::Unlock).await;
            let path = OwnedObjectPath::from(prompt.path().clone());
            self.prompts
                .lock()
                .await
                .insert(path.clone(), prompt.clone());

            self.object_server().at(&path, prompt).await?;
            return Ok((unlocked, path));
        }

        Ok((unlocked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("locked", "Prompt"))]
    pub async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        let (locked, not_locked) = self.set_locked(true, &objects, false).await?;
        if !not_locked.is_empty() {
            let prompt = Prompt::new(self.clone(), not_locked, PromptRole::Lock).await;
            let path = OwnedObjectPath::from(prompt.path().clone());
            self.prompts
                .lock()
                .await
                .insert(path.clone(), prompt.clone());

            self.object_server().at(&path, prompt).await?;
            return Ok((locked, path));
        }

        Ok((locked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, DBusSecretInner>, ServiceError> {
        let mut secrets = HashMap::new();
        let collections = self.collections.lock().await;

        'outer: for collection in collections.iter() {
            for item in &items {
                if let Some(item) = collection.item_from_path(item).await {
                    match item.get_secret(session.clone()).await {
                        Ok((secret,)) => {
                            secrets.insert(item.path().clone().into(), secret);
                            // To avoid iterating through all the remaining collections, if the
                            // items secrets are already retrieved.
                            if secrets.len() == items.len() {
                                break 'outer;
                            }
                        }
                        // Avoid erroring out if an item is locked.
                        Err(ServiceError::IsLocked(_)) => {
                            continue;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    };
                }
            }
        }

        Ok(secrets)
    }

    #[zbus(out_args("collection"))]
    pub async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath, ServiceError> {
        let collections = self.collections.lock().await;

        for collection in collections.iter() {
            if collection.alias().await == name {
                tracing::debug!(
                    "Collection: {} found for alias: {}.",
                    collection.path(),
                    name
                );
                return Ok(collection.path().clone().into());
            }
        }

        tracing::info!("Collection with alias {} does not exist.", name);

        Ok(OwnedObjectPath::default())
    }

    pub async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
    ) -> Result<(), ServiceError> {
        let collections = self.collections.lock().await;

        for other_collection in collections.iter() {
            if *other_collection.path() == *collection {
                other_collection.set_alias(name).await;

                tracing::info!("Collection: {} alias updated to {}.", collection, name);
                return Ok(());
            }
        }

        tracing::info!("Collection: {} does not exist.", collection);

        Err(ServiceError::NoSuchObject(format!(
            "The collection: {collection} does not exist.",
        )))
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections
            .lock()
            .await
            .iter()
            .map(|c| c.path().to_owned().into())
            .collect()
    }

    #[zbus(signal, name = "CollectionCreated")]
    async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionDeleted")]
    async fn collection_deleted(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionChanged")]
    pub async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Service {
    pub async fn run(secret: Option<Secret>, request_replacement: bool) -> Result<(), Error> {
        let service = Self {
            collections: Default::default(),
            connection: Default::default(),
            sessions: Default::default(),
            session_index: Default::default(),
            prompts: Default::default(),
            prompt_index: Default::default(),
        };

        let connection = zbus::connection::Builder::session()?
            .allow_name_replacements(true)
            .replace_existing_names(request_replacement)
            .name(oo7::dbus::api::Service::DESTINATION.as_deref().unwrap())?
            .serve_at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )?
            .build()
            .await?;

        let default_keyring = if let Some(secret) = secret {
            Some(Arc::new(Keyring::open("login", secret).await?))
        } else {
            None
        };

        service.initialize(connection, default_keyring).await?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn run_with_connection(
        connection: zbus::Connection,
        secret: Option<Secret>,
    ) -> Result<Self, Error> {
        let service = Self::default();

        // Serve the service at the standard path
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        let default_keyring = if let Some(secret) = secret {
            Some(Arc::new(Keyring::temporary(secret).await?))
        } else {
            None
        };

        service.initialize(connection, default_keyring).await?;
        Ok(service)
    }

    /// Initialize the service with collections and start client disconnect
    /// handler
    async fn initialize(
        &self,
        connection: zbus::Connection,
        default_keyring: Option<Arc<Keyring>>,
    ) -> Result<(), Error> {
        self.connection.set(connection.clone()).unwrap();

        let object_server = connection.object_server();
        let mut collections = self.collections.lock().await;

        // Set up default/login collection if keyring is provided
        if let Some(keyring) = default_keyring {
            let collection = Collection::new(
                "Login",
                oo7::dbus::Service::DEFAULT_COLLECTION,
                false,
                self.clone(),
                keyring,
            );
            collections.push(collection.clone());
            collection.dispatch_items().await?;
            object_server
                .at(collection.path(), collection.clone())
                .await?;
            object_server
                .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                .await?;
        }

        // Always create session collection (always temporary)
        let collection = Collection::new(
            "session",
            oo7::dbus::Service::SESSION_COLLECTION,
            false,
            self.clone(),
            Arc::new(Keyring::temporary(Secret::random().unwrap()).await?),
        );
        object_server
            .at(collection.path(), collection.clone())
            .await?;
        collections.push(collection);

        drop(collections); // Release the lock

        // Spawn client disconnect handler
        let service = self.clone();
        tokio::spawn(async move { service.on_client_disconnect().await });

        Ok(())
    }

    async fn on_client_disconnect(&self) -> zbus::Result<()> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .arg(2, "")?
            .build();
        let mut stream = zbus::MessageStream::for_match_rule(rule, self.connection(), None).await?;
        while let Some(message) = stream.try_next().await? {
            let Ok((_name, old_owner, new_owner)) =
                message
                    .body()
                    .deserialize::<(String, OwnedUniqueName, OwnedUniqueName)>()
            else {
                continue;
            };
            assert_eq!(new_owner, ""); // We enforce that in the matching rule
            if let Some(session) = self.session_from_sender(&old_owner).await {
                match session.close().await {
                    Ok(_) => tracing::info!(
                        "Client {} disconnected. Session: {} closed.",
                        old_owner,
                        session.path()
                    ),
                    Err(err) => tracing::error!("Failed to close session: {}", err),
                }
            }
        }
        Ok(())
    }

    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
        from_prompt: bool,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let collections = self.collections.lock().await;

        for object in objects {
            for collection in collections.iter() {
                let collection_locked = collection.is_locked().await;
                if **object == *collection.path() {
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    } else {
                        // TODO: get rid of from_prompt and use futures
                        if from_prompt {
                            collection.set_locked(locked).await?;
                        }
                        with_prompt.push(object.clone());
                    }
                    break;
                } else if let Some(item) = collection.item_from_path(object).await {
                    if locked == item.is_locked().await {
                        tracing::debug!(
                            "Item: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    // If the collection is in a similar state, update the Item
                    // without a prompt.
                    } else if collection_locked == locked {
                        item.set_locked(locked).await?;
                        without_prompt.push(object.clone());
                    } else {
                        // TODO: get rid of from_prompt and use futures
                        if from_prompt {
                            item.set_locked(locked).await?;
                        }
                        with_prompt.push(object.clone());
                    }
                    break;
                }
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub fn connection(&self) -> &zbus::Connection {
        self.connection.get().unwrap()
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection().object_server()
    }

    pub async fn collection_from_path(&self, path: &ObjectPath<'_>) -> Option<Collection> {
        let collections = self.collections.lock().await;

        collections.iter().find(|c| c.path() == path).cloned()
    }

    pub async fn session_index(&self) -> u32 {
        let n_sessions = *self.session_index.read().await + 1;
        *self.session_index.write().await = n_sessions;

        n_sessions
    }

    async fn session_from_sender(&self, sender: &UniqueName<'_>) -> Option<Session> {
        let sessions = self.sessions.lock().await;

        sessions.values().find(|s| s.sender() == sender).cloned()
    }

    pub async fn session(&self, path: &ObjectPath<'_>) -> Option<Session> {
        self.sessions.lock().await.get(path).cloned()
    }

    pub async fn remove_session(&self, path: &ObjectPath<'_>) {
        self.sessions.lock().await.remove(path);
    }

    pub async fn prompt_index(&self) -> u32 {
        let n_prompts = *self.prompt_index.read().await + 1;
        *self.prompt_index.write().await = n_prompts;

        n_prompts
    }

    pub async fn prompt(&self, path: &ObjectPath<'_>) -> Option<Prompt> {
        self.prompts.lock().await.get(path).cloned()
    }

    pub async fn remove_prompt(&self, path: &ObjectPath<'_>) {
        self.prompts.lock().await.remove(path);
    }

    pub fn signal_emitter<'a, P>(
        &self,
        path: P,
    ) -> Result<zbus::object_server::SignalEmitter<'a>, oo7::dbus::ServiceError>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let signal_emitter = zbus::object_server::SignalEmitter::new(self.connection(), path)?;

        Ok(signal_emitter)
    }
}

#[cfg(test)]
mod tests {
    use oo7::dbus;

    use super::*;
    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn open_session_plain() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        assert!(
            setup.aes_key.is_none(),
            "Plain session should not have AES key"
        );

        // Should have 2 collections: default + session
        assert_eq!(
            setup.collections.len(),
            2,
            "Expected default and session collections"
        );
        Ok(())
    }

    #[tokio::test]
    async fn open_session_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(false).await?;
        assert!(
            setup.server_public_key.is_some(),
            "Encrypted session should have server public key"
        );
        let key = setup.aes_key.unwrap().clone();
        assert_eq!((*key).as_ref().len(), 16, "AES key should be 16 bytes");
        Ok(())
    }

    #[tokio::test]
    async fn session_collection_only() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(false).await?;

        // Should have only session collection (no default)
        assert_eq!(
            setup.collections.len(),
            1,
            "Should have exactly one collection"
        );
        Ok(())
    }

    #[tokio::test]
    async fn search_items() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Search for items (should return empty initially)
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("application", "test-app")])
            .await?;

        assert!(
            unlocked.is_empty(),
            "Should have no unlocked items initially"
        );
        assert!(locked.is_empty(), "Should have no locked items initially");

        // Search with empty attributes - edge case
        let attributes: HashMap<&str, &str> = HashMap::default();
        let (unlocked, locked) = setup.service_api.search_items(&attributes).await?;

        assert!(
            locked.is_empty(),
            "Should have no locked items with empty search"
        );
        assert!(
            unlocked.is_empty(),
            "Should have no unlocked items with empty search"
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Test with empty items list - edge case
        let secrets = setup.service_api.secrets(&vec![], &setup.session).await?;
        assert!(
            secrets.is_empty(),
            "Should return empty secrets for empty items list"
        );

        // Create two items with different secrets
        let secret1 = Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1.clone());

        let item1 = setup.collections[0]
            .create_item("Item 1", &[("app", "test1")], &dbus_secret1, false, None)
            .await?;

        let secret2 = Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2.clone());

        let item2 = setup.collections[0]
            .create_item("Item 2", &[("app", "test2")], &dbus_secret2, false, None)
            .await?;

        // Get secrets for both items
        let item_paths = vec![item1.clone(), item2.clone()];
        let secrets = setup
            .service_api
            .secrets(&item_paths, &setup.session)
            .await?;

        // Should have both secrets
        assert_eq!(secrets.len(), 2, "Should retrieve both secrets");

        // Verify first secret
        let retrieved_secret1 = secrets.get(&item1).unwrap();
        assert_eq!(retrieved_secret1.value(), secret1.as_bytes());

        // Verify second secret
        let retrieved_secret2 = secrets.get(&item2).unwrap();
        assert_eq!(retrieved_secret2.value(), secret2.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn get_secrets_multiple_collections() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Should have 2 collections: default (Login) and session
        assert_eq!(setup.collections.len(), 2);

        // Create item in default collection (index 0)
        let secret1 = Secret::text("default-password");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1.clone());

        let item1 = setup.collections[0]
            .create_item(
                "Default Item",
                &[("app", "default-app")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Create item in session collection (index 1)
        let secret2 = Secret::text("session-password");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2.clone());

        let item2 = setup.collections[1]
            .create_item(
                "Session Item",
                &[("app", "session-app")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Get secrets for both items from different collections
        let item_paths = vec![item1.clone(), item2.clone()];
        let secrets = setup
            .service_api
            .secrets(&item_paths, &setup.session)
            .await?;

        // Should have both secrets
        assert_eq!(
            secrets.len(),
            2,
            "Should retrieve secrets from both collections"
        );

        // Verify default collection secret
        let retrieved_secret1 = secrets.get(&item1).unwrap();
        assert_eq!(retrieved_secret1.value(), secret1.as_bytes());

        // Verify session collection secret
        let retrieved_secret2 = secrets.get(&item2).unwrap();
        assert_eq!(retrieved_secret2.value(), secret2.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn read_alias() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Default collection should have "default" alias
        let default_collection = setup.service_api.read_alias("default").await?;
        assert!(
            default_collection.is_some(),
            "Default alias should return a collection"
        );
        assert_eq!(
            default_collection.unwrap().inner().path(),
            setup.collections[0].inner().path(),
            "Default alias should point to default collection"
        );

        // Non-existent alias should return None
        let nonexistent = setup.service_api.read_alias("nonexistent").await?;
        assert!(
            nonexistent.is_none(),
            "Non-existent alias should return None"
        );

        Ok(())
    }

    #[tokio::test]
    async fn set_alias() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Set alias for session collection
        setup
            .service_api
            .set_alias("my-alias", &setup.collections[1])
            .await?;

        // Read the alias back
        let alias_collection = setup.service_api.read_alias("my-alias").await?;
        assert!(
            alias_collection.is_some(),
            "Alias should return a collection"
        );
        assert_eq!(
            alias_collection.unwrap().inner().path(),
            setup.collections[1].inner().path(),
            "Alias should point to session collection"
        );

        Ok(())
    }

    #[tokio::test]
    async fn search_items_with_results() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create items in default collection
        let secret1 = Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item(
                "Firefox Login",
                &[("application", "firefox"), ("type", "login")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        let secret2 = Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        setup.collections[0]
            .create_item(
                "Chrome Login",
                &[("application", "chrome"), ("type", "login")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Create item in session collection
        let secret3 = Secret::text("password3");
        let dbus_secret3 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret3);

        setup.collections[1]
            .create_item(
                "Session Item",
                &[("application", "firefox"), ("type", "session")],
                &dbus_secret3,
                false,
                None,
            )
            .await?;

        // Search for all firefox items
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("application", "firefox")])
            .await?;

        assert_eq!(unlocked.len(), 2, "Should find 2 firefox items");
        assert!(locked.is_empty(), "Should have no locked items");

        // Search for login type items
        let (unlocked, locked) = setup.service_api.search_items(&[("type", "login")]).await?;

        assert_eq!(unlocked.len(), 2, "Should find 2 login items");
        assert!(locked.is_empty(), "Should have no locked items");

        // Search for chrome items
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("application", "chrome")])
            .await?;

        assert_eq!(unlocked.len(), 1, "Should find 1 chrome item");
        assert!(locked.is_empty(), "Should have no locked items");

        // Search for non-existent
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("application", "nonexistent")])
            .await?;

        assert!(unlocked.is_empty(), "Should find no items");
        assert!(locked.is_empty(), "Should have no locked items");

        Ok(())
    }

    #[tokio::test]
    async fn get_secrets_invalid_session() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item
        let secret = Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Try to get secrets with invalid session path
        let invalid_session =
            dbus::api::Session::new(&setup.client_conn, "/invalid/session/path").await?;
        let result = setup.service_api.secrets(&[item], &invalid_session).await;

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
    async fn set_alias_invalid_collection() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Try to set alias for non-existent collection
        let invalid_collection = dbus::api::Collection::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/nonexistent",
        )
        .await?;
        let result = setup
            .service_api
            .set_alias("test-alias", &invalid_collection)
            .await;

        assert!(
            matches!(
                result,
                Err(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::NoSuchObject(_)
                ))
            ),
            "Should be NoSuchObject error"
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_secrets_with_non_existent_items() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create one real item
        let secret = Secret::text("password1");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

        let item1 = setup.collections[0]
            .create_item("Item 1", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Create a fake item path that doesn't exist
        let fake_item = dbus::api::Item::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/Login/999",
        )
        .await?;

        // Request secrets for both real and fake items
        let item_paths = vec![item1.clone(), fake_item];
        let secrets = setup
            .service_api
            .secrets(&item_paths, &setup.session)
            .await?;

        // Should only get the secret for the real item
        assert_eq!(
            secrets.len(),
            1,
            "Should only retrieve secret for existing item"
        );
        assert!(secrets.contains_key(&item1), "Should have item1 secret");

        Ok(())
    }

    #[tokio::test]
    async fn search_items_across_collections() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        let collections = setup.service_api.collections().await?;
        assert_eq!(collections.len(), 2, "Should have 2 collections");

        // Create item in first collection
        let secret1 = Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        collections[0]
            .create_item(
                "Default Item",
                &[("shared", "attr")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Create item in second collection with same attributes
        let secret2 = Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        collections[1]
            .create_item(
                "Session Item",
                &[("shared", "attr")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Search should find items from both collections
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("shared", "attr")])
            .await?;

        assert_eq!(unlocked.len(), 2, "Should find items from both collections");
        assert!(locked.is_empty(), "Should have no locked items");

        Ok(())
    }

    #[tokio::test]
    async fn unlock_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Test 1: Empty object list
        let items: Vec<ObjectPath<'_>> = vec![];
        let unlocked = setup.service_api.unlock(&items, None).await?;
        assert!(unlocked.is_empty(), "Should return empty for empty input");

        // Test 2: Non-existent objects
        let fake_collection = dbus::api::Collection::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/NonExistent",
        )
        .await?;

        let fake_item = dbus::api::Item::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/Login/999",
        )
        .await?;

        let unlocked = setup
            .service_api
            .unlock(
                &[fake_collection.inner().path(), fake_item.inner().path()],
                None,
            )
            .await?;

        assert!(
            unlocked.is_empty(),
            "Should have no unlocked objects for non-existent paths"
        );

        // Test 3: Already unlocked objects
        let secret = Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);

        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Verify item is unlocked
        assert!(!item.is_locked().await?, "Item should be unlocked");

        // Try to unlock already unlocked item
        let unlocked = setup
            .service_api
            .unlock(&[item.inner().path()], None)
            .await?;

        assert_eq!(unlocked.len(), 1, "Should return the already-unlocked item");
        assert_eq!(
            unlocked[0].as_str(),
            item.inner().path().as_str(),
            "Should return the same item path"
        );

        // Also test with collection (starts unlocked by default)
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should be unlocked"
        );

        let unlocked = setup
            .service_api
            .unlock(&[setup.collections[0].inner().path()], None)
            .await?;

        assert_eq!(
            unlocked.len(),
            1,
            "Should return the already-unlocked collection"
        );

        Ok(())
    }

    #[tokio::test]
    async fn lock_non_existent_objects() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::encrypted_session(true).await?;

        // Test with empty object list
        let items: Vec<ObjectPath<'_>> = vec![];
        let locked = setup.service_api.lock(&items, None).await?;
        assert!(locked.is_empty(), "Should return empty for empty input");

        // Test locking non-existent objects
        let fake_collection = dbus::api::Collection::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/NonExistent",
        )
        .await?;

        let fake_item = dbus::api::Item::new(
            &setup.client_conn,
            "/org/freedesktop/secrets/collection/Login/999",
        )
        .await?;

        let locked = setup
            .service_api
            .lock(
                &[fake_collection.inner().path(), fake_item.inner().path()],
                None,
            )
            .await?;

        assert!(
            locked.is_empty(),
            "Should have no locked objects for non-existent paths"
        );

        Ok(())
    }
}
