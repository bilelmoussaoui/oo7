// org.freedesktop.Secret.Service

use std::{collections::HashMap, sync::Arc};

use enumflags2::BitFlags;
use oo7::{
    dbus::{
        api::{Properties, SecretInner},
        Algorithm, ServiceError,
    },
    portal::{Keyring, Secret},
    Key,
};
use tokio::sync::{Mutex, RwLock};
use zbus::{
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

use crate::{collection::Collection, error::Error, session::Session};

#[derive(Debug, Clone)]
pub struct Service {
    // Properties
    collections: Arc<Mutex<Vec<Collection>>>,
    // Other attributes
    connection: zbus::Connection,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Arc<Session>>>>,
    session_index: Arc<RwLock<u32>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath), ServiceError> {
        let (public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted => {
                let client_public_key = Key::from(input);
                let private_key = Key::generate_private_key();
                (
                    Some(Key::generate_public_key(&private_key)),
                    Some(Key::generate_aes_key(&private_key, &client_public_key)),
                )
            }
        };

        let session = Session::new(aes_key.map(Arc::new), self.clone()).await;
        let path = session.path().clone();

        {
            let session = Arc::new(session.clone());
            self.sessions
                .lock()
                .await
                .insert(path.clone(), Arc::clone(&session));
        }

        object_server.at(&path, session).await?;

        let service_key = public_key
            .map(|k| OwnedValue::from(&k))
            .unwrap_or_else(|| Value::new::<Vec<u8>>(vec![]).try_to_owned().unwrap());

        Ok((service_key, path))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        _properties: Properties,
        _alias: &str,
    ) -> Result<(OwnedObjectPath, ObjectPath), ServiceError> {
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
                    locked.push(item.path().clone());
                } else {
                    unlocked.push(item.path().clone());
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
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        let (unlocked, _not_unlocked) = self.set_locked(false, &objects).await?;

        Ok((unlocked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        let (locked, _not_locked) = self.set_locked(true, &objects).await?;

        Ok((locked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, SecretInner>, ServiceError> {
        let mut secrets = HashMap::new();
        let collections = self.collections.lock().await;

        'outer: for collection in collections.iter() {
            for item in &items {
                if let Some(item) = collection.item_from_path(item).await {
                    match item.get_secret(session.clone()).await {
                        Ok((secret,)) => {
                            secrets.insert(item.path().clone(), secret);
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
                tracing::info!(
                    "Collection: {} found for alias: {}.",
                    collection.path(),
                    name
                );
                return Ok(collection.path().clone());
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
            if other_collection.path() == &collection {
                other_collection.set_alias(name).await;

                tracing::info!("Collection: {} alias updated to {}.", collection, name);
                return Ok(());
            }
        }

        tracing::info!("Collection: {} does not exist.", collection);

        Err(ServiceError::NoSuchObject(format!(
            "The collection: {} does not exist.",
            collection,
        )))
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections
            .lock()
            .await
            .iter()
            .map(|c| c.path().to_owned())
            .collect()
    }

    #[zbus(signal, name = "CollectionCreated")]
    async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionDeleted")]
    async fn collection_deleted(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionChanged")]
    pub async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: &OwnedObjectPath,
    ) -> zbus::Result<()>;
}

impl Service {
    pub async fn run(
        secret: Option<Secret>,
        flags: BitFlags<zbus::fdo::RequestNameFlags>,
    ) -> Result<(), Error> {
        let connection = zbus::Connection::session().await?;
        connection
            .request_name_with_flags(
                oo7::dbus::api::Service::DESTINATION.as_deref().unwrap(),
                flags,
            )
            .await?;
        let object_server = connection.object_server();
        let service = Self {
            collections: Default::default(),
            connection: connection.clone(),
            sessions: Default::default(),
            session_index: Default::default(),
        };

        object_server
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        let mut collections = service.collections.lock().await;

        if let Some(secret) = secret {
            let collection = Collection::new(
                "login",
                "default",
                false,
                service.clone(),
                Arc::new(Keyring::open("login", secret).await?),
            );
            collections.push(collection.clone());
            collection.dispatch_items().await?;
            object_server
                .at(collection.path().clone(), collection)
                .await?;
        }

        let collection = Collection::new(
            "session",
            "session",
            false,
            service.clone(),
            Arc::new(Keyring::temporary(Secret::random()).await?),
        );
        collections.push(collection.clone());
        object_server
            .at(collection.path().clone(), collection)
            .await?;

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
            for collection in collections.iter() {
                let collection_locked = collection.is_locked().await;
                if object == collection.path() {
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            object,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(object.clone());
                    } else {
                        // TODO: remove this once the prompt implementation is complete.
                        collection.set_locked(locked).await?;
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
                        // TODO: remove this once the prompt implementation is complete.
                        item.set_locked(locked).await?;
                        with_prompt.push(object.clone());
                    }
                    break;
                }
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection.object_server()
    }

    pub async fn collection_from_path(&self, path: &OwnedObjectPath) -> Option<Collection> {
        let collections = self.collections.lock().await;

        for collection in collections.iter() {
            if collection.path() == path {
                return Some(collection.clone());
            }
        }

        None
    }

    pub async fn session(&self, path: &OwnedObjectPath) -> Option<Arc<Session>> {
        self.sessions.lock().await.get(path).map(Arc::clone)
    }

    pub async fn remove_session(&self, path: &OwnedObjectPath) {
        self.sessions.lock().await.remove(path);
    }

    pub fn signal_emitter<'a, P>(
        &self,
        path: P,
    ) -> Result<zbus::object_server::SignalEmitter<'a>, oo7::dbus::ServiceError>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let signal_emitter = zbus::object_server::SignalEmitter::new(&self.connection, path)?;

        Ok(signal_emitter)
    }

    pub async fn session_index(&self) -> u32 {
        let n_sessions = *self.session_index.read().await + 1;
        *self.session_index.write().await = n_sessions;

        n_sessions
    }
}
