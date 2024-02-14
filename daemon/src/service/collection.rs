// org.freedesktop.Secret.Collection

use std::collections::HashMap;

use oo7::{dbus::api::Properties, portal::Item};
use serde::{Serialize, Serializer};
use zbus::{interface, zvariant, Error, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath, Type};

use crate::{service::item, KEYRING};

#[derive(Default, Debug, Type)]
#[zvariant(signature = "o")]
pub struct Collection {
    pub items: Vec<item::Item>,
    label: String,
    locked: bool,
    created: u64,
    modified: u64,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    pub async fn delete(&self, #[zbus(object_server)] object_server: &ObjectServer) -> ObjectPath {
        let _ = object_server.remove::<Collection, _>(&self.path).await;
        ObjectPath::default().into() // returning '/' until we figure out Prompt
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Vec<Item> {
        let items = match KEYRING.get().unwrap().search_items(&attributes).await {
            Ok(i) => i,
            Err(_) => todo!(),
        };

        items // currently returns Vec<oo7::portal::Item>, this should be a path
    }

    pub async fn create_item(
        &mut self,
        properties: Properties,
        secret: &str,
        replace: bool,
    ) -> (ObjectPath, ObjectPath) {
        let label = properties.label();
        let attributes = properties.attributes().unwrap();

        let item = KEYRING
            .get()
            .unwrap()
            .create_item(label, &attributes, secret, replace)
            .await
            .unwrap();

        // make prompt to get the secret and set it with set_secret()

        let created_item_path = ObjectPath::default().into(); // how to get path from _collection
        let prompt = ObjectPath::default().into(); // temp Prompt

        // portal::Item mapping
        let item = item::Item::new(item, self.path().into()).await;
        self.items.push(item);

        (created_item_path, prompt)
    }

    #[zbus(property, name = "Items")]
    pub fn items(&self) -> Vec<ObjectPath> {
        self.items.iter().map(|item| item.path()).collect()
    }

    #[zbus(property, name = "Label")]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[zbus(property, name = "Locked")]
    pub fn locked(&self) -> bool {
        self.locked
    }

    #[zbus(property, name = "Created")]
    pub fn created(&self) -> u64 {
        self.created
    }

    #[zbus(property, name = "Modified")]
    pub fn modified(&self) -> u64 {
        self.modified
    }

    #[zbus(signal)]
    pub async fn item_created(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[zbus(signal)]
    pub async fn item_deleted(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[zbus(signal)]
    pub async fn item_changed(ctxt: &SignalContext<'_>) -> Result<(), Error>;
}

impl Serialize for Collection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OwnedObjectPath::serialize(&self.path, serializer)
    }
}

impl Collection {
    // temporarily creates a generic Collection object
    pub fn new(label: &str) -> Self {
        Self {
            items: Vec::new(),
            label: label.to_owned(),
            locked: false,
            created: 23123,
            modified: 23123,
            path: OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}",
                label
            ))
            .unwrap(),
        }
    }

    pub fn path(&self) -> ObjectPath {
        self.path.to_owned().into()
    }

    pub async fn set_label(&mut self, label: String) {
        self.label = label;
    }

    pub async fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }
}
