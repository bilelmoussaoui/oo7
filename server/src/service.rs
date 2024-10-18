// org.freedesktop.Secret.Service

use std::{collections::HashMap, sync::Arc};

use oo7::{
    dbus::{
        api::{Properties, SecretInner},
        Algorithm, ServiceError,
    },
    Key,
};
use tokio::sync::Mutex;
use zbus::{
    proxy::Defaults,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

use crate::{service_manager::ServiceManager, session::Session};

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug)]
pub struct Service {
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
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
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
    ) -> Result<(OwnedObjectPath, ObjectPath)> {
        todo!()
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        _attributes: HashMap<&str, &str>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        todo!()
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &mut self,
        _objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath)> {
        todo!()
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &mut self,
        _objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath)> {
        todo!()
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        _items: Vec<OwnedObjectPath>,
        _session: ObjectPath<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretInner>> {
        todo!()
    }

    #[zbus(out_args("collection"))]
    pub async fn read_alias(&self, _name: &str) -> Result<ObjectPath> {
        todo!()
    }

    pub async fn set_alias(&self, _name: &str, _collection: ObjectPath<'_>) -> Result<()> {
        todo!()
    }
}

impl Service {
    pub async fn run() -> Result<()> {
        let connection = zbus::connection::Builder::session()?
            .name(oo7::dbus::api::Service::DESTINATION.as_deref().unwrap())?
            .build()
            .await?;
        let service = Self {
            manager: Default::default(),
            connection: connection.clone(),
        };

        connection
            .object_server()
            .at(oo7::dbus::api::Service::PATH.as_deref().unwrap(), service)
            .await?;
        Ok(())
    }
}
