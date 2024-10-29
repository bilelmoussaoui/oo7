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
use tokio::sync::Mutex;
use zbus::{
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

use crate::{
    collection::Collection, error::Error, service_manager::ServiceManager, session::Session,
};

#[derive(Debug, Clone)]
pub struct Service {
    // Properties
    collections: Arc<Mutex<Vec<Collection>>>,
    // Other attributes
    manager: Arc<Mutex<ServiceManager>>,
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

        let session = Session::new(aes_key.map(Arc::new), Arc::clone(&self.manager)).await;
        let path = session.path().clone();

        {
            let session = Arc::new(session.clone());
            self.manager
                .lock()
                .await
                .insert_session(path.clone(), Arc::clone(&session));
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
        _attributes: HashMap<&str, &str>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        todo!()
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &mut self,
        _objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath), ServiceError> {
        todo!()
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &mut self,
        _objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath), ServiceError> {
        todo!()
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        _items: Vec<OwnedObjectPath>,
        _session: ObjectPath<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretInner>, ServiceError> {
        todo!()
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
    async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
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
            manager: Arc::new(Mutex::new(ServiceManager::new(connection.clone()))),
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
                Arc::clone(&service.manager),
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
            Arc::clone(&service.manager),
            Arc::new(Keyring::temporary(Secret::random()).await?),
        );
        collections.push(collection.clone());
        object_server
            .at(collection.path().clone(), collection)
            .await?;

        Ok(())
    }
}
