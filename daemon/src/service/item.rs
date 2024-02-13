// org.freedesktop.Secret.Item

use std::collections::HashMap;

use oo7::portal;
use portal::api::AttributeValue;
use zbus::{dbus_interface, fdo, zvariant, ObjectServer};
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::KEYRING;

#[derive(Debug)]
pub struct Item {
    inner: portal::Item,
    path: OwnedObjectPath,
}

#[dbus_interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    pub async fn delete(
        &mut self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<ObjectPath> {
        let attributes = self.inner().attributes();
        let _ = KEYRING.get().unwrap().delete(attributes).await;
        let _ = object_server.remove::<Item, _>(self.path()).await;
        Ok(ObjectPath::default().into())
    }

    pub async fn secret(&mut self /* session: Session */) -> fdo::Result<Vec<u8>> {
        let secret = self.inner().secret();
        Ok(secret.to_vec())
    }

    pub async fn set_secret(&mut self, secret: Vec<u8>) {
        self.inner().set_secret(secret);
    }

    // pub fn locked(&self) -> bool {
    // self.locked
    // }

    pub fn attributes(&mut self) -> &HashMap<String, AttributeValue> {
        self.inner().attributes()
    }

    pub fn label(&mut self) -> &str {
        self.inner().label()
    }

    pub fn created(&mut self) -> u64 {
        self.inner().created().as_secs()
    }

    pub fn modified(&mut self) -> u64 {
        self.inner().modified().as_secs()
    }

    pub fn path(&self) -> ObjectPath {
        self.path.to_owned().into()
    }
}

impl Item {
    pub async fn new(item: portal::Item, collection_path: OwnedObjectPath) -> Self {
        // maps oo7::portal::Item to crate::service::Item
        Self {
            inner: item.to_owned(),
            path: OwnedObjectPath::try_from(format!(
                "{}/items/{}",
                collection_path.as_str(),
                item.label(),
            ))
            .unwrap(),
        }
    }

    pub fn inner(&mut self) -> &mut portal::Item {
        &mut self.inner
    }
}
