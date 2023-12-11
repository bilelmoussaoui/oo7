// org.freedesktop.Secret.Item

use std::collections::HashMap;

use oo7::dbus::api::Properties;
use zbus::{dbus_interface, fdo, zvariant, ObjectServer};
use zeroize::Zeroize;
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::KEYRING;

#[derive(Debug, Zeroize)]
pub struct Item {
    #[zeroize(skip)]
    locked: bool,
    #[zeroize(skip)]
    properties: Properties,
    #[zeroize(skip)]
    created: u64,
    #[zeroize(skip)]
    modified: u64,
    secret: Vec<u8>,
    #[zeroize(skip)]
    path: OwnedObjectPath,
}

#[dbus_interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    pub async fn delete(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<ObjectPath> {
        let mut properties: HashMap<&str, &str> = Default::default();

        for (key, value) in self.properties().attributes().unwrap().into_iter() {
            properties.insert(key.as_str(), value.as_str());
        }

        let _ = KEYRING.get().unwrap().delete(&properties).await;
        let _ = object_server.remove::<Item, _>(self.path()).await;
        Ok(ObjectPath::default().into())
    }

    pub async fn get_secret(&self /* session: Session */) -> fdo::Result<Vec<u8>> {
        let item = KEYRING
            .get()
            .unwrap()
            .lookup_item(&self.lookup_item_attributes().await)
            .await
            .unwrap()
            .unwrap();
        // do something with session parameter
        Ok(item.secret().to_vec())
    }

    pub async fn set_secret(&self, secret: Vec<u8>) {
        let mut item = KEYRING
            .get()
            .unwrap()
            .lookup_item(&self.lookup_item_attributes().await)
            .await
            .unwrap()
            .unwrap();

        item.set_secret(secret)
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn properties(&self) -> &Properties {
        &self.properties
    }

    pub fn label(&self) -> &str {
        let attributes = self.properties();
        attributes.label()
    }

    pub fn created(&self) -> u64 {
        self.created
    }

    pub fn modified(&self) -> u64 {
        self.created
    }

    pub fn path(&self) -> ObjectPath {
        self.path.to_owned().into()
    }
}

impl Item {
    pub async fn new(
        attributes: &HashMap<&str, &str>,
        secret: Vec<u8>,
        label: &str,
        created: u64,
        modified: u64,
        collection_path: OwnedObjectPath,
    ) -> Self {
        // maps oo7::portal::Item to crate Item
        let properties = Properties::for_item(label, attributes);
        Self {
            locked: true,
            properties: properties,
            created: created,
            modified: modified,
            secret: secret,
            path: OwnedObjectPath::try_from(format!(
                "{}/items/{}",
                collection_path.as_str(),
                label
            ))
            .unwrap(),
        }
    }

    pub async fn lookup_item_attributes(&self) -> HashMap<&str, &str> {
        let mut attributes: HashMap<&str, &str> = Default::default();

        for (key, value) in self.properties().attributes().unwrap().into_iter() {
            attributes.insert(key.as_str(), value.as_str());
        }

        attributes
    }
}
