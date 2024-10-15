// org.freedesktop.Secret.Service

use std::collections::HashMap;

use oo7::dbus::{
    api::{Properties, SecretInner},
    Algorithm, ServiceError,
};
use zbus::{
    proxy::ProxyDefault,
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value},
};

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Debug, Default)]
pub struct Service {}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        _algorithm: Algorithm,
        _input: Value<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        todo!()
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
            .name(oo7::dbus::api::Service::DESTINATION.unwrap())?
            .build()
            .await?;
        connection
            .object_server()
            .at(oo7::dbus::api::Service::PATH.unwrap(), Self::default())
            .await?;
        Ok(())
    }
}
