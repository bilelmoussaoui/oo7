// org.freedesktop.Secret.Service

use std::{collections::HashMap, sync::Arc};

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
    collections: Arc<Mutex<Vec<OwnedObjectPath>>>,
    // Other attributes
    manager: Arc<Mutex<ServiceManager>>,
    #[allow(unused)]
    connection: zbus::Connection,
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
    pub async fn read_alias(&self, _name: &str) -> Result<ObjectPath, ServiceError> {
        todo!()
    }

    pub async fn set_alias(
        &self,
        _name: &str,
        _collection: ObjectPath<'_>,
    ) -> Result<(), ServiceError> {
        todo!()
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections.lock().await.clone()
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
    pub async fn run(secret: Option<Secret>) -> Result<(), Error> {
        let connection = zbus::connection::Builder::session()?
            .name(oo7::dbus::api::Service::DESTINATION.as_deref().unwrap())?
            .build()
            .await?;
        let object_server = connection.object_server();
        let service = Self {
            collections: Default::default(),
            manager: Default::default(),
            connection: connection.clone(),
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
                Arc::clone(&service.manager),
                Arc::new(Keyring::open("login", secret).await?),
            );
            collections.push(collection.path().clone());
            object_server
                .at(collection.path().clone(), collection)
                .await?;
        }

        let collection = Collection::new(
            "session",
            "session",
            Arc::clone(&service.manager),
            Arc::new(Keyring::temporary(Secret::random()).await?),
        );
        collections.push(collection.path().clone());
        object_server
            .at(collection.path().clone(), collection)
            .await?;

        drop(collections);

        Ok(())
    }
}
