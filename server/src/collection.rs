// org.freedesktop.Secret.Collection

use std::collections::HashMap;

use oo7::dbus::api::{Properties, SecretInner};
use zbus::{interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::Result;

#[derive(Debug)]
pub struct Collection {}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath> {
        todo!()
    }

    #[zbus(out_args("results"))]
    pub async fn search_items(&self, _attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        todo!()
    }

    #[zbus(out_args("item", "prompt"))]
    pub async fn create_item(
        &self,
        _properties: Properties,
        _secret: SecretInner,
        _replace: bool,
    ) -> Result<(OwnedObjectPath, ObjectPath)> {
        todo!()
    }
}
