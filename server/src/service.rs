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
    file::{Keyring, LockedKeyring, UnlockedKeyring},
};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::StreamExt;
use zbus::{
    names::UniqueName,
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue, Value},
};

use crate::{
    collection::Collection,
    error::{Error, custom_service_error},
    prompt::{Prompt, PromptAction, PromptRole},
    session::Session,
};

const DEFAULT_COLLECTION_ALIAS_PATH: ObjectPath<'static> =
    ObjectPath::from_static_str_unchecked("/org/freedesktop/secrets/aliases/default");

#[derive(Debug, Default, Clone)]
pub struct Service {
    // Properties
    pub(crate) collections: Arc<Mutex<HashMap<OwnedObjectPath, Collection>>>,
    // Other attributes
    connection: Arc<OnceLock<zbus::Connection>>,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Session>>>,
    session_index: Arc<RwLock<u32>>,
    // prompts mapped to their corresponding object path on the bus
    prompts: Arc<Mutex<HashMap<OwnedObjectPath, Prompt>>>,
    prompt_index: Arc<RwLock<u32>>,
    // pending collection creations: prompt_path -> (label, alias)
    pending_collections: Arc<Mutex<HashMap<OwnedObjectPath, (String, String)>>>,
    // pending v0 keyring migrations: name -> (path, label, alias)
    #[allow(clippy::type_complexity)]
    pub(crate) pending_migrations:
        Arc<Mutex<HashMap<String, (std::path::PathBuf, String, String)>>>,
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
        properties: Properties,
        alias: &str,
    ) -> Result<(OwnedObjectPath, ObjectPath<'_>), ServiceError> {
        let label = properties.label().to_owned();
        let alias = alias.to_owned();

        // Create a prompt to get the password for the new collection
        let prompt = Prompt::new(
            self.clone(),
            PromptRole::CreateCollection,
            label.clone(),
            None,
        )
        .await;
        let prompt_path = OwnedObjectPath::from(prompt.path().clone());

        // Store the collection metadata for later creation
        self.pending_collections
            .lock()
            .await
            .insert(prompt_path.clone(), (label, alias));

        // Create the collection creation action
        let service = self.clone();
        let creation_prompt_path = prompt_path.clone();
        let action = PromptAction::new(move |secret: Secret| async move {
            let collection_path = service
                .complete_collection_creation(&creation_prompt_path, secret)
                .await?;

            Ok(Value::new(collection_path).try_into_owned().unwrap())
        });

        prompt.set_action(action).await;

        // Register the prompt
        self.prompts
            .lock()
            .await
            .insert(prompt_path.clone(), prompt.clone());

        self.object_server().at(&prompt_path, prompt).await?;

        tracing::debug!("CreateCollection prompt created at `{}`", prompt_path);

        // Return empty collection path and the prompt path
        Ok((OwnedObjectPath::default(), prompt_path.into()))
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        let collections = self.collections.lock().await;

        for (_path, collection) in collections.iter() {
            let items = collection.search_inner_items(&attributes).await?;
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
        let (unlocked, not_unlocked) = self.set_locked(false, &objects).await?;
        if !not_unlocked.is_empty() {
            // Extract the label and collection before creating the prompt
            let label = self.extract_label_from_objects(&not_unlocked).await;
            let collection = self.extract_collection_from_objects(&not_unlocked).await;

            let prompt = Prompt::new(self.clone(), PromptRole::Unlock, label, collection).await;
            let path = OwnedObjectPath::from(prompt.path().clone());

            // Create the unlock action
            let service = self.clone();
            let action = PromptAction::new(move |secret: Secret| async move {
                // The prompter will handle secret validation
                // Here we just perform the unlock operation
                let collections = service.collections.lock().await;
                for object in &not_unlocked {
                    // Try to find as collection first
                    if let Some(collection) = collections.get(object) {
                        let _ = collection.set_locked(false, Some(secret.clone())).await;
                    } else {
                        // Try to find as item within collections
                        for (_path, collection) in collections.iter() {
                            if let Some(item) = collection.item_from_path(object).await {
                                // If the collection is locked, unlock it
                                if collection.is_locked().await {
                                    let _ =
                                        collection.set_locked(false, Some(secret.clone())).await;
                                } else {
                                    // Collection is already unlocked, just unlock the item
                                    let keyring = collection.keyring.read().await;
                                    let _ = item
                                        .set_locked(false, keyring.as_ref().unwrap().as_unlocked())
                                        .await;
                                }
                                break;
                            }
                        }
                    }
                }
                Ok(Value::new(not_unlocked).try_into_owned().unwrap())
            });

            prompt.set_action(action).await;

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
        // set_locked now handles locking directly (without prompts)
        let (locked, not_locked) = self.set_locked(true, &objects).await?;
        // Locking never requires prompts, so not_locked should always be empty
        debug_assert!(
            not_locked.is_empty(),
            "Lock operation should never require prompts"
        );
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

        'outer: for (_path, collection) in collections.iter() {
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
        // Map "login" alias to "default" for compatibility with gnome-keyring
        let alias_to_find = if name == Self::LOGIN_ALIAS {
            oo7::dbus::Service::DEFAULT_COLLECTION
        } else {
            name
        };

        let collections = self.collections.lock().await;

        for (path, collection) in collections.iter() {
            if collection.alias().await == alias_to_find {
                tracing::debug!("Collection: {} found for alias: {}.", path, name);
                return Ok(path.to_owned());
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

        for (path, other_collection) in collections.iter() {
            if *path == collection {
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
        self.collections.lock().await.keys().cloned().collect()
    }

    #[zbus(signal, name = "CollectionCreated")]
    pub async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionDeleted")]
    pub async fn collection_deleted(
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
    const LOGIN_ALIAS: &str = "login";

    pub async fn run(secret: Option<Secret>, request_replacement: bool) -> Result<(), Error> {
        let service = Self::default();

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

        // Discover existing keyrings
        let discovered_keyrings = service.discover_keyrings(secret).await?;

        service
            .initialize(connection, discovered_keyrings, true)
            .await?;

        // Start PAM listener
        tracing::info!("Starting PAM listener");
        let pam_listener = crate::pam_listener::PamListener::new(service.clone());
        tokio::spawn(async move {
            if let Err(e) = pam_listener.start().await {
                tracing::error!("PAM listener error: {}", e);
            }
        });

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
            vec![(
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                Keyring::Unlocked(UnlockedKeyring::temporary(secret).await?),
            )]
        } else {
            vec![]
        };

        service
            .initialize(connection, default_keyring, false)
            .await?;
        Ok(service)
    }

    /// Discover existing keyrings in the data directory
    /// Returns a vector of (label, alias, keyring) tuples
    async fn discover_keyrings(
        &self,
        secret: Option<Secret>,
    ) -> Result<Vec<(String, String, Keyring)>, Error> {
        let mut discovered = Vec::new();

        // Get data directory using the same logic as oo7::file::api::data_dir()
        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .and_then(|h| if h.is_empty() { None } else { Some(h) })
            .map(std::path::PathBuf::from)
            .and_then(|p| if p.is_absolute() { Some(p) } else { None })
            .or_else(|| {
                std::env::var_os("HOME")
                    .and_then(|h| if h.is_empty() { None } else { Some(h) })
                    .map(std::path::PathBuf::from)
                    .map(|p| p.join(".local/share"))
            });

        let Some(data_dir) = data_dir else {
            tracing::warn!("No data directory found, skipping keyring discovery");
            return Ok(discovered);
        };

        let keyrings_dir = data_dir.join("keyrings");

        // Scan for v1 keyrings first
        let v1_dir = keyrings_dir.join("v1");
        if v1_dir.exists() {
            tracing::debug!("Scanning for v1 keyrings in {}", v1_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&v1_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v1 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((label, alias, keyring)) => discovered.push((label, alias, keyring)),
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        // Scan for v0 keyrings
        if keyrings_dir.exists() {
            tracing::debug!("Scanning for v0 keyrings in {}", keyrings_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&keyrings_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v0 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((label, alias, keyring)) => discovered.push((label, alias, keyring)),
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        let pending_count = self.pending_migrations.lock().await.len();

        if discovered.is_empty() && pending_count == 0 {
            tracing::info!("No keyrings discovered in data directory");
        } else {
            tracing::info!(
                "Discovered {} keyring(s), {} pending v0 migration(s)",
                discovered.len(),
                pending_count
            );
        }

        Ok(discovered)
    }

    /// Load a single keyring from a file path
    /// Returns (label, alias, keyring)
    async fn load_keyring(
        &self,
        path: &std::path::Path,
        name: &str,
        secret: Option<&Secret>,
    ) -> Result<(String, String, Keyring), Error> {
        let alias = if name.eq_ignore_ascii_case(Self::LOGIN_ALIAS) {
            oo7::dbus::Service::DEFAULT_COLLECTION.to_owned()
        } else {
            name.to_owned().to_lowercase()
        };

        // Use name as label (capitalized for consistency with Login)
        let label = {
            let mut chars = name.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        // Try to load the keyring
        let keyring = match LockedKeyring::load(path).await {
            Ok(locked_keyring) => {
                // Successfully loaded as v1 keyring
                if let Some(secret) = secret {
                    match locked_keyring.unlock(secret.clone()).await {
                        Ok(unlocked) => {
                            tracing::info!("Unlocked keyring '{}' from {:?}", name, path);
                            Keyring::Unlocked(unlocked)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to unlock keyring '{}' with provided secret: {}. Keeping it locked.",
                                name,
                                e
                            );
                            // Reload as locked since unlock consumed it
                            Keyring::Locked(LockedKeyring::load(path).await?)
                        }
                    }
                } else {
                    tracing::debug!("No secret provided, keeping keyring '{}' locked", name);
                    Keyring::Locked(locked_keyring)
                }
            }
            Err(oo7::file::Error::VersionMismatch(Some(version)))
                if version.first() == Some(&0) =>
            // v0 is the legacy version
            {
                // This is a v0 keyring that needs migration
                tracing::info!(
                    "Found legacy v0 keyring '{name}' at {}, registering for migration",
                    path.display()
                );

                if let Some(secret) = secret {
                    tracing::debug!("Attempting immediate migration of v0 keyring '{name}'",);
                    match UnlockedKeyring::open(name, secret.clone()).await {
                        Ok(unlocked) => {
                            tracing::info!("Successfully migrated v0 keyring '{name}' to v1",);

                            // Write the migrated keyring to disk
                            unlocked.write().await?;
                            tracing::info!("Wrote migrated keyring '{name}' to disk");

                            // Remove the v0 keyring file after successful migration
                            if let Err(e) = tokio::fs::remove_file(path).await {
                                tracing::warn!(
                                    "Failed to remove v0 keyring at {}: {e}",
                                    path.display()
                                );
                            } else {
                                tracing::info!("Removed v0 keyring file at {}", path.display());
                            }

                            Keyring::Unlocked(unlocked)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to migrate v0 keyring '{name}': {e}. Will retry when secret is available.",
                            );
                            self.pending_migrations.lock().await.insert(
                                name.to_owned(),
                                (path.to_path_buf(), label.clone(), alias.clone()),
                            );
                            return Err(e.into());
                        }
                    }
                } else {
                    tracing::debug!(
                        "No secret available for v0 keyring '{}', registering for pending migration",
                        name
                    );
                    self.pending_migrations.lock().await.insert(
                        name.to_owned(),
                        (path.to_path_buf(), label.clone(), alias.clone()),
                    );
                    return Err(Error::IO(std::io::Error::other(
                        "v0 keyring requires migration, no secret available",
                    )));
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        Ok((label, alias, keyring))
    }

    /// Initialize the service with collections and start client disconnect
    /// handler
    async fn initialize(
        &self,
        connection: zbus::Connection,
        mut discovered_keyrings: Vec<(String, String, Keyring)>, // (name, alias, keyring)
        auto_create_default: bool,
    ) -> Result<(), Error> {
        self.connection.set(connection.clone()).unwrap();

        let object_server = connection.object_server();
        let mut collections = self.collections.lock().await;

        // Check if we have a default collection
        let has_default = discovered_keyrings.iter().any(|(_, alias, _)| {
            alias == oo7::dbus::Service::DEFAULT_COLLECTION || alias == Self::LOGIN_ALIAS
        });

        if !has_default && auto_create_default {
            tracing::info!("No default collection found, creating 'Login' keyring");

            let locked_keyring = LockedKeyring::open(Self::LOGIN_ALIAS)
                .await
                .inspect_err(|e| {
                    tracing::error!("Failed to create default Login keyring: {}", e);
                })?;

            discovered_keyrings.push((
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                Keyring::Locked(locked_keyring),
            ));

            tracing::info!("Created default 'Login' collection (locked)");
        }

        // Set up discovered collections
        for (label, alias, keyring) in discovered_keyrings {
            let collection = Collection::new(&label, &alias, self.clone(), keyring);
            collections.insert(collection.path().to_owned().into(), collection.clone());
            collection.dispatch_items().await?;
            object_server
                .at(collection.path(), collection.clone())
                .await?;

            // If this is the default collection, also register it at the alias path
            if alias == oo7::dbus::Service::DEFAULT_COLLECTION {
                object_server
                    .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                    .await?;
            }
        }

        // Always create session collection (always temporary)
        let collection = Collection::new(
            "session",
            oo7::dbus::Service::SESSION_COLLECTION,
            self.clone(),
            Keyring::Unlocked(UnlockedKeyring::temporary(Secret::random().unwrap()).await?),
        );
        object_server
            .at(collection.path(), collection.clone())
            .await?;
        collections.insert(collection.path().to_owned().into(), collection);

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
            let body = message.body();
            let Ok((_name, old_owner, new_owner)) =
                body.deserialize::<(String, Optional<UniqueName<'_>>, Optional<UniqueName<'_>>)>()
            else {
                continue;
            };
            debug_assert!(new_owner.is_none()); // We enforce that in the matching rule
            let old_owner = old_owner
                .as_ref()
                .expect("A disconnected client requires an old_owner");
            if let Some(session) = self.session_from_sender(old_owner).await {
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
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let collections = self.collections.lock().await;

        for object in objects {
            for (path, collection) in collections.iter() {
                let collection_locked = collection.is_locked().await;
                if *object == *path {
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    } else if locked {
                        // Locking never requires a prompt
                        collection.set_locked(true, None).await?;
                        without_prompt.push(object.clone());
                    } else {
                        // Unlocking may require a prompt
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
                    // If the collection is unlocked, we can lock/unlock the
                    // item directly
                    } else if !collection_locked {
                        let keyring = collection.keyring.read().await;
                        item.set_locked(locked, keyring.as_ref().unwrap().as_unlocked())
                            .await?;
                        without_prompt.push(object.clone());
                    } else {
                        // Collection is locked, unlocking the item requires unlocking the
                        // collection
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
        collections.get(path).cloned()
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

    pub async fn remove_collection(&self, path: &ObjectPath<'_>) {
        self.collections.lock().await.remove(path);

        if let Ok(signal_emitter) =
            self.signal_emitter(oo7::dbus::api::Service::PATH.as_deref().unwrap())
        {
            let _ = self.collections_changed(&signal_emitter).await;
        }
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
        // Also clean up pending collection if it exists
        self.pending_collections.lock().await.remove(path);
    }

    pub async fn register_prompt(&self, path: OwnedObjectPath, prompt: Prompt) {
        self.prompts.lock().await.insert(path, prompt);
    }

    pub async fn pending_collection(
        &self,
        prompt_path: &ObjectPath<'_>,
    ) -> Option<(String, String)> {
        self.pending_collections
            .lock()
            .await
            .get(prompt_path)
            .cloned()
    }

    pub async fn complete_collection_creation(
        &self,
        prompt_path: &ObjectPath<'_>,
        secret: Secret,
    ) -> Result<OwnedObjectPath, ServiceError> {
        // Retrieve the pending collection metadata
        let Some((label, alias)) = self.pending_collection(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "No pending collection for prompt `{prompt_path}`"
            )));
        };

        // Create a persistent keyring with the provided secret
        let keyring = UnlockedKeyring::open(&label.to_lowercase(), secret)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create keyring: {err}")))?;

        // Write the keyring file to disk immediately
        keyring
            .write()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to write keyring file: {err}")))?;

        let keyring = Keyring::Unlocked(keyring);

        // Create the collection
        let collection = Collection::new(&label, &alias, self.clone(), keyring);
        let collection_path: OwnedObjectPath = collection.path().to_owned().into();

        // Register with object server
        self.object_server()
            .at(collection.path(), collection.clone())
            .await?;

        // Add to collections
        self.collections
            .lock()
            .await
            .insert(collection_path.clone(), collection);

        // Clean up pending collection
        self.pending_collections.lock().await.remove(prompt_path);

        // Emit CollectionCreated signal
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.signal_emitter(service_path)?;
        Service::collection_created(&signal_emitter, &collection_path).await?;

        // Emit PropertiesChanged for Collections property to invalidate client cache
        self.collections_changed(&signal_emitter).await?;

        tracing::info!(
            "Collection `{}` created with label '{}'",
            collection_path,
            label
        );

        Ok(collection_path)
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

    /// Extract the collection label from a list of object paths
    /// The objects can be either collections or items
    async fn extract_label_from_objects(&self, objects: &[OwnedObjectPath]) -> String {
        if objects.is_empty() {
            return String::new();
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return collection.label().await;
            }
        }

        // Get the collection path from the first item
        // assumes all items are from the same collection
        if let Some(path_str) = objects.first().and_then(|p| p.as_str().rsplit_once('/')) {
            let collection_path = path_str.0;
            if let Ok(obj_path) = ObjectPath::try_from(collection_path) {
                if let Some(collection) = self.collection_from_path(&obj_path).await {
                    return collection.label().await;
                }
            }
        }

        String::new()
    }

    /// Extract the collection from a list of object paths
    /// The objects can be either collections or items
    async fn extract_collection_from_objects(
        &self,
        objects: &[OwnedObjectPath],
    ) -> Option<Collection> {
        if objects.is_empty() {
            return None;
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return Some(collection);
            }
        }

        // Get the collection path from the first item
        // (assumes all items are from the same collection)
        let path = objects
            .first()
            .unwrap()
            .as_str()
            .rsplit_once('/')
            .map(|(parent, _)| parent)?;
        self.collection_from_path(&ObjectPath::try_from(path).unwrap())
            .await
    }

    /// Attempt to migrate pending v0 keyrings with the provided secret
    /// Returns a list of successfully migrated keyring names
    pub async fn migrate_pending_keyrings(&self, secret: &Secret) -> Vec<String> {
        let mut migrated = Vec::new();
        let mut pending = self.pending_migrations.lock().await;
        let mut to_remove = Vec::new();

        for (name, (path, label, alias)) in pending.iter() {
            tracing::debug!("Attempting to migrate pending v0 keyring: {}", name);

            match UnlockedKeyring::open(name, secret.clone()).await {
                Ok(unlocked) => {
                    tracing::info!("Successfully migrated v0 keyring '{}' to v1", name);

                    // Write the migrated keyring to disk
                    match unlocked.write().await {
                        Ok(_) => {
                            tracing::info!("Wrote migrated keyring '{}' to disk", name);

                            // Remove the v0 keyring file after successful migration
                            if let Err(e) = tokio::fs::remove_file(path).await {
                                tracing::warn!("Failed to remove v0 keyring at {:?}: {}", path, e);
                            } else {
                                tracing::info!("Removed v0 keyring file at {:?}", path);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to write migrated keyring '{}' to disk: {}",
                                name,
                                e
                            );
                            continue;
                        }
                    }

                    // Create a collection for this migrated keyring
                    let keyring = Keyring::Unlocked(unlocked);
                    let collection = Collection::new(label, alias, self.clone(), keyring);
                    let collection_path: OwnedObjectPath = collection.path().to_owned().into();

                    // Dispatch items
                    if let Err(e) = collection.dispatch_items().await {
                        tracing::error!(
                            "Failed to dispatch items for migrated keyring '{}': {}",
                            name,
                            e
                        );
                        continue;
                    }

                    if let Err(e) = self
                        .object_server()
                        .at(collection.path(), collection.clone())
                        .await
                    {
                        tracing::error!(
                            "Failed to register migrated collection '{}' with object server: {}",
                            name,
                            e
                        );
                        continue;
                    }

                    self.collections
                        .lock()
                        .await
                        .insert(collection_path.clone(), collection.clone());

                    if alias == oo7::dbus::Service::DEFAULT_COLLECTION {
                        if let Err(e) = self
                            .object_server()
                            .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                            .await
                        {
                            tracing::error!(
                                "Failed to register default alias for migrated collection '{}': {}",
                                name,
                                e
                            );
                        }
                    }

                    if let Ok(signal_emitter) =
                        self.signal_emitter(oo7::dbus::api::Service::PATH.as_ref().unwrap())
                    {
                        let _ =
                            Service::collection_created(&signal_emitter, &collection_path).await;
                        let _ = self.collections_changed(&signal_emitter).await;
                    }

                    tracing::info!("Migrated keyring '{}' added as collection", name);
                    migrated.push(name.clone());
                    to_remove.push(name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate v0 keyring '{}' with provided secret: {}",
                        name,
                        e
                    );
                }
            }
        }

        for name in &to_remove {
            pending.remove(name);
        }

        migrated
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

        // Test with both locked and unlocked items
        // Create items in default collection (unlocked)
        let secret1 = Secret::text("password1");
        let dbus_secret1 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret1);

        setup.collections[0]
            .create_item(
                "Unlocked Item",
                &[("app", "testapp")],
                &dbus_secret1,
                false,
                None,
            )
            .await?;

        // Create item in default collection and lock it
        let secret2 = Secret::text("password2");
        let dbus_secret2 = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret2);

        let locked_item = setup.collections[0]
            .create_item(
                "Locked Item",
                &[("app", "testapp")],
                &dbus_secret2,
                false,
                None,
            )
            .await?;

        // Lock just this item (not the whole collection)
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");

        let keyring = collection.keyring.read().await;
        let unlocked_keyring = keyring.as_ref().unwrap().as_unlocked();

        let locked_item = collection
            .item_from_path(locked_item.inner().path())
            .await
            .unwrap();
        locked_item.set_locked(true, unlocked_keyring).await?;

        // Search for items with the shared attribute
        let (unlocked, locked) = setup
            .service_api
            .search_items(&[("app", "testapp")])
            .await?;

        assert_eq!(unlocked.len(), 1, "Should find 1 unlocked item");
        assert_eq!(locked.len(), 1, "Should find 1 locked item");

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

        // Verify it's the Login collection by checking its label
        let label = default_collection.as_ref().unwrap().label().await?;
        assert_eq!(
            label, "Login",
            "Default alias should point to Login collection"
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

    #[tokio::test]
    async fn unlock_collection_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Lock the collection using server-side API
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked"
        );

        // Test 1: Unlock with accept
        let unlocked = setup
            .service_api
            .unlock(&[setup.collections[0].inner().path()], None)
            .await?;

        assert_eq!(unlocked.len(), 1, "Should have unlocked 1 collection");
        assert_eq!(
            unlocked[0].as_str(),
            setup.collections[0].inner().path().as_str(),
            "Should return the collection path"
        );
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should be unlocked after accepting prompt"
        );

        // Lock the collection again for dismiss test
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked again"
        );

        // Test 2: Unlock with dismiss
        setup.mock_prompter.set_accept(false).await;
        let result = setup
            .service_api
            .unlock(&[setup.collections[0].inner().path()], None)
            .await;

        assert!(
            matches!(result, Err(oo7::dbus::Error::Dismissed)),
            "Should return Dismissed error when prompt dismissed"
        );
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should still be locked after dismissing prompt"
        );

        Ok(())
    }

    #[tokio::test]
    async fn unlock_item_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item
        let secret = Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);
        let default_collection = setup.service_api.read_alias("default").await?.unwrap();
        let item = default_collection
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        // Lock the collection (which locks the item)
        let collection = setup
            .server
            .collection_from_path(default_collection.inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;

        assert!(
            item.is_locked().await?,
            "Item should be locked when collection is locked"
        );

        // Test 1: Unlock with accept
        let unlocked = setup
            .service_api
            .unlock(&[item.inner().path()], None)
            .await?;

        assert_eq!(unlocked.len(), 1, "Should have unlocked 1 item");
        assert_eq!(
            unlocked[0].as_str(),
            item.inner().path().as_str(),
            "Should return the item path"
        );
        assert!(
            !item.is_locked().await?,
            "Item should be unlocked after accepting prompt"
        );

        // Lock the item again for dismiss test
        collection
            .set_locked(true, setup.keyring_secret.clone())
            .await?;
        assert!(item.is_locked().await?, "Item should be locked again");

        // Test 2: Unlock with dismiss
        setup.mock_prompter.set_accept(false).await;
        let result = setup.service_api.unlock(&[item.inner().path()], None).await;

        assert!(
            matches!(result, Err(oo7::dbus::Error::Dismissed)),
            "Should return Dismissed error when prompt dismissed"
        );
        assert!(
            item.is_locked().await?,
            "Item should still be locked after dismissing prompt"
        );

        Ok(())
    }

    #[tokio::test]
    async fn lock_item_in_unlocked_collection() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create an item (starts unlocked)
        let secret = Secret::text("test-password");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret);
        let item = setup.collections[0]
            .create_item("Test Item", &[("app", "test")], &dbus_secret, false, None)
            .await?;

        assert!(!item.is_locked().await?, "Item should start unlocked");
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should be unlocked"
        );

        // When collection is unlocked, locking an item should happen directly without a
        // prompt
        let locked = setup.service_api.lock(&[item.inner().path()], None).await?;

        assert_eq!(locked.len(), 1, "Should have locked 1 item");
        assert_eq!(
            locked[0].as_str(),
            item.inner().path().as_str(),
            "Should return the item path"
        );
        assert!(item.is_locked().await?, "Item should be locked directly");

        // Unlock the item again (using service API to unlock just the item)
        let unlocked = setup
            .service_api
            .unlock(&[item.inner().path()], None)
            .await?;
        assert_eq!(unlocked.len(), 1, "Should have unlocked 1 item");
        assert!(!item.is_locked().await?, "Item should be unlocked again");

        // Locking again should work the same way (no prompt)
        let locked = setup.service_api.lock(&[item.inner().path()], None).await?;
        assert_eq!(locked.len(), 1, "Should have locked 1 item again");
        assert!(item.is_locked().await?, "Item should be locked again");

        Ok(())
    }

    #[tokio::test]
    async fn lock_collection_no_prompt() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Collection starts unlocked
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should start unlocked"
        );

        // Lock the collection
        let locked = setup
            .service_api
            .lock(&[setup.collections[0].inner().path()], None)
            .await?;

        assert_eq!(locked.len(), 1, "Should have locked 1 collection");
        assert_eq!(
            locked[0].as_str(),
            setup.collections[0].inner().path().as_str(),
            "Should return the collection path"
        );
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked instantly"
        );

        // Unlock the collection
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection
            .set_locked(false, setup.keyring_secret.clone())
            .await?;
        assert!(
            !setup.collections[0].is_locked().await?,
            "Collection should be unlocked"
        );

        // Lock again to verify it works multiple times
        let locked = setup
            .service_api
            .lock(&[setup.collections[0].inner().path()], None)
            .await?;

        assert_eq!(locked.len(), 1, "Should have locked 1 collection again");
        assert!(
            setup.collections[0].is_locked().await?,
            "Collection should be locked again"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn create_collection_basic() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get initial collection count
        let initial_collections = setup.service_api.collections().await?;
        let initial_count = initial_collections.len();

        // Create a new collection
        let collection = setup
            .service_api
            .create_collection("MyNewKeyring", Some("my-custom-alias"), None)
            .await?;

        // Verify collection appears in collections list
        let collections = setup.service_api.collections().await?;
        assert_eq!(
            collections.len(),
            initial_count + 1,
            "Should have one more collection"
        );

        // Verify the collection label
        let label = collection.label().await?;
        assert_eq!(
            label, "MyNewKeyring",
            "Collection should have correct label"
        );

        // Verify the keyring file exists on disk
        let server_collection = setup
            .server
            .collection_from_path(collection.inner().path())
            .await
            .expect("Collection should exist on server");
        let keyring_guard = server_collection.keyring.read().await;
        let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();

        assert!(
            keyring_path.exists(),
            "Keyring file should exist on disk at {:?}",
            keyring_path
        );

        // Verify the alias was set
        let alias_collection = setup.service_api.read_alias("my-custom-alias").await?;
        assert!(
            alias_collection.is_some(),
            "Should be able to read collection by alias"
        );
        assert_eq!(
            alias_collection.unwrap().inner().path(),
            collection.inner().path(),
            "Alias should point to the new collection"
        );

        tokio::fs::remove_file(keyring_path).await?;

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn create_collection_signal() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Subscribe to CollectionCreated signal
        let signal_stream = setup.service_api.receive_collection_created().await?;
        tokio::pin!(signal_stream);

        // Create a new collection
        let collection = setup
            .service_api
            .create_collection("TestKeyring", None, None)
            .await?;

        // Wait for signal with timeout
        let signal_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), signal_stream.next()).await;

        assert!(
            signal_result.is_ok(),
            "Should receive CollectionCreated signal"
        );
        let signal = signal_result.unwrap();
        assert!(signal.is_some(), "Signal should not be None");

        let signal_collection = signal.unwrap();
        assert_eq!(
            signal_collection.inner().path().as_str(),
            collection.inner().path().as_str(),
            "Signal should contain the created collection path"
        );

        let server_collection = setup
            .server
            .collection_from_path(collection.inner().path())
            .await
            .expect("Collection should exist on server");
        let keyring_guard = server_collection.keyring.read().await;
        let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();
        tokio::fs::remove_file(keyring_path).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn create_collection_and_add_items() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Create a new collection
        let collection = setup
            .service_api
            .create_collection("ItemTestKeyring", None, None)
            .await?;

        // Verify collection is unlocked and ready for items
        assert!(
            !collection.is_locked().await?,
            "New collection should be unlocked"
        );

        // Create an item in the new collection
        let secret = oo7::Secret::text("hello-world-test");
        let dbus_secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), secret.clone());

        let item = collection
            .create_item(
                "Test Item",
                &[("app", "test-app")],
                &dbus_secret,
                false,
                None,
            )
            .await?;

        // Verify item was created
        let items = collection.items().await?;
        assert_eq!(items.len(), 1, "Should have one item in new collection");
        assert_eq!(
            items[0].inner().path(),
            item.inner().path(),
            "Item path should match"
        );

        // Verify we can retrieve the secret
        let retrieved_secret = item.secret(&setup.session).await?;
        assert_eq!(
            retrieved_secret.value(),
            secret.as_bytes(),
            "Should be able to retrieve secret from item in new collection"
        );

        let server_collection = setup
            .server
            .collection_from_path(collection.inner().path())
            .await
            .expect("Collection should exist on server");
        let keyring_guard = server_collection.keyring.read().await;
        let keyring_path = keyring_guard.as_ref().unwrap().path().unwrap();
        tokio::fs::remove_file(&keyring_path).await?;

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn create_collection_dismissed() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Get initial collection count
        let initial_collections = setup.service_api.collections().await?;
        let initial_count = initial_collections.len();

        // Set mock prompter to dismiss
        setup.mock_prompter.set_accept(false).await;

        // Try to create a collection
        let result = setup
            .service_api
            .create_collection("DismissedKeyring", None, None)
            .await;

        // Should get Dismissed error
        assert!(
            matches!(result, Err(oo7::dbus::Error::Dismissed)),
            "Should return Dismissed error when prompt dismissed"
        );

        // Verify collection was NOT created
        let collections = setup.service_api.collections().await?;
        assert_eq!(
            collections.len(),
            initial_count,
            "Should not have created a new collection after dismissal"
        );

        Ok(())
    }

    #[tokio::test]
    async fn complete_collection_creation_no_pending() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Try to complete collection creation with a prompt path that has no pending
        // collection
        let fake_prompt_path =
            ObjectPath::try_from("/org/freedesktop/secrets/prompt/p999").unwrap();
        let secret = Secret::from("test-password-long-enough");

        let result = setup
            .server
            .complete_collection_creation(&fake_prompt_path, secret)
            .await;

        // Should get NoSuchObject error
        assert!(
            matches!(result, Err(ServiceError::NoSuchObject(_))),
            "Should return NoSuchObject error when no pending collection exists"
        );
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn discover_v1_keyrings() -> Result<(), Box<dyn std::error::Error>> {
        let service = Service::default();

        // Set up a temporary data directory
        let temp_dir = tempfile::tempdir()?;
        unsafe { std::env::set_var("XDG_DATA_HOME", temp_dir.path()) };

        // Create v1 keyrings directory
        let v1_dir = temp_dir.path().join("keyrings/v1");
        tokio::fs::create_dir_all(&v1_dir).await?;

        // Test 1: Empty directory
        let discovered = service.discover_keyrings(None).await?;
        assert!(
            discovered.is_empty(),
            "Should discover no keyrings in empty directory"
        );

        // Create multiple keyrings with different passwords
        // Add items to each so password validation works
        let secret1 = Secret::from("password-for-work");
        let keyring1 = UnlockedKeyring::open("work", secret1.clone()).await?;
        keyring1
            .create_item(
                "Work Item",
                &[("type", "work")],
                Secret::text("work-secret"),
                false,
            )
            .await?;
        keyring1.write().await?;

        let secret2 = Secret::from("password-for-personal");
        let keyring2 = UnlockedKeyring::open("personal", secret2.clone()).await?;
        keyring2
            .create_item(
                "Personal Item",
                &[("type", "personal")],
                Secret::text("personal-secret"),
                false,
            )
            .await?;
        keyring2.write().await?;

        // Create a "login" keyring which should get the default alias
        let secret3 = Secret::from("password-for-login");
        let keyring3 = UnlockedKeyring::open("login", secret3.clone()).await?;
        keyring3
            .create_item(
                "Login Item",
                &[("type", "login")],
                Secret::text("login-secret"),
                false,
            )
            .await?;
        keyring3.write().await?;

        // Create some non-keyring files that should be skipped
        tokio::fs::write(v1_dir.join("README.txt"), b"This is a readme").await?;
        tokio::fs::write(v1_dir.join("config.json"), b"{}").await?;
        tokio::fs::create_dir(v1_dir.join("subdir")).await?;

        // Test 2: Discover without any password, all should be locked
        let discovered = service.discover_keyrings(None).await?;
        assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");
        for (_, _, keyring) in &discovered {
            assert!(
                matches!(keyring, Keyring::Locked(_)),
                "All keyrings should be locked without secret"
            );
        }

        // Test 3: Discover with one password, only that keyring should be unlocked
        let discovered = service.discover_keyrings(Some(secret1.clone())).await?;
        assert_eq!(discovered.len(), 3, "Should discover 3 keyrings");

        let work_keyring = discovered
            .iter()
            .find(|(label, _, _)| label == "Work")
            .unwrap();
        assert!(
            matches!(work_keyring.2, Keyring::Unlocked(_)),
            "Work keyring should be unlocked with correct password"
        );

        let personal_keyring = discovered
            .iter()
            .find(|(label, _, _)| label == "Personal")
            .unwrap();
        assert!(
            matches!(personal_keyring.2, Keyring::Locked(_)),
            "Personal keyring should be locked with wrong password"
        );

        // Test 4: Verify login keyring gets default alias
        let login_keyring = discovered
            .iter()
            .find(|(label, _, _)| label == "Login")
            .unwrap();
        assert_eq!(
            login_keyring.1,
            oo7::dbus::Service::DEFAULT_COLLECTION,
            "Login keyring should have default alias"
        );
        assert!(
            matches!(login_keyring.2, Keyring::Locked(_)),
            "Login keyring should be locked with wrong password"
        );

        // Test 5: Verify labels are properly capitalized
        let labels: Vec<_> = discovered
            .iter()
            .map(|(label, _, _)| label.as_str())
            .collect();
        assert!(labels.contains(&"Work"), "Should have Work with capital W");
        assert!(
            labels.contains(&"Personal"),
            "Should have Personal with capital P"
        );
        assert!(
            labels.contains(&"Login"),
            "Should have Login with capital L"
        );

        // Clean up
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(xdg_env)]
    async fn discover_v0_keyrings() -> Result<(), Box<dyn std::error::Error>> {
        let service = Service::default();
        let temp_dir = tempfile::tempdir()?;
        unsafe { std::env::set_var("XDG_DATA_HOME", temp_dir.path()) };

        let keyrings_dir = temp_dir.path().join("keyrings");
        let v1_dir = keyrings_dir.join("v1");
        tokio::fs::create_dir_all(&keyrings_dir).await?;
        tokio::fs::create_dir_all(&v1_dir).await?;

        // Copy the existing v0 keyring fixture
        let v0_secret = Secret::from("test");
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("client/fixtures/legacy.keyring");
        let v0_path = keyrings_dir.join("legacy.keyring");
        tokio::fs::copy(&fixture_path, &v0_path).await?;

        // Create a v1 keyring for mixed scenario
        let v1_secret = Secret::from("v1-password");
        let v1_keyring = UnlockedKeyring::open("modern", v1_secret.clone()).await?;
        v1_keyring
            .create_item(
                "V1 Item",
                &[("type", "v1")],
                Secret::text("v1-secret"),
                false,
            )
            .await?;
        v1_keyring.write().await?;

        // Test 1: Discover without secret, v0 marked for migration, v1 locked
        let discovered = service.discover_keyrings(None).await?;
        assert_eq!(discovered.len(), 1, "Should discover v1 keyring only");
        assert!(
            matches!(discovered[0].2, Keyring::Locked(_)),
            "V1 should be locked"
        );

        let pending = service.pending_migrations.lock().await;
        assert_eq!(pending.len(), 1, "V0 should be pending migration");
        assert!(pending.contains_key("legacy"));
        drop(pending);

        // Test 2: Discover with v0 secret, v0 migrated, v1 locked
        service.pending_migrations.lock().await.clear();
        let discovered = service.discover_keyrings(Some(v0_secret.clone())).await?;
        assert_eq!(discovered.len(), 2, "Should discover both keyrings");

        let legacy = discovered.iter().find(|(l, _, _)| l == "Legacy").unwrap();
        assert!(
            matches!(legacy.2, Keyring::Unlocked(_)),
            "V0 should be migrated and unlocked"
        );
        assert_eq!(
            service.pending_migrations.lock().await.len(),
            0,
            "No pending after successful migration"
        );

        // Verify v1 file was created
        let v1_migrated = temp_dir.path().join("keyrings/v1/legacy.keyring");
        assert!(v1_migrated.exists(), "V1 file should exist after migration");

        // Test 3: Discover with wrong v0 secret,  marked for pending migration
        tokio::fs::remove_file(&v1_migrated).await?;
        service.pending_migrations.lock().await.clear();

        // Restore the v0 file for this test
        tokio::fs::copy(&fixture_path, &v0_path).await?;

        let wrong_secret = Secret::from("wrong-password");
        let discovered = service.discover_keyrings(Some(wrong_secret)).await?;
        assert_eq!(
            discovered.len(),
            1,
            "Only v1 should be discovered with wrong v0 password"
        );
        assert_eq!(
            service.pending_migrations.lock().await.len(),
            1,
            "V0 should be pending with wrong password"
        );

        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        Ok(())
    }
}
