// org.freedesktop.Secret.Collection

use std::collections::HashMap;

use oo7::{dbus::api::Properties, portal::Item};
use serde::{Serialize, Serializer};
use zbus::{dbus_interface, zvariant, Error, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath, Type};

use crate::{service::item, KEYRING};

#[derive(Default, Debug, Type)]
#[zvariant(signature = "o")]
pub struct Collection {
    pub items: Vec<item::Item>,
    label: String,
    locked: bool,
    created: u64, // how to represent date
    modified: u64,
    path: OwnedObjectPath,
}

#[dbus_interface(name = "org.freedesktop.Secret.Collection")]
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
        let mut attributes: HashMap<&str, &str> = Default::default();

        for (key, value) in properties.attributes().unwrap().into_iter() {
            attributes.insert(key.as_str(), value.as_str());
        }

        match KEYRING
            .get()
            .unwrap()
            .create_item(label, attributes.clone(), secret, replace)
            .await
        {
            Ok(_) => (),
            Err(_) => (), // best approach to handle this error?
        }

        // lookup just created item
        let lookup_item = KEYRING
            .get()
            .unwrap()
            .lookup_item(&attributes)
            .await
            .unwrap()
            .unwrap();
        // make prompt to get the secret and set it with set_secret()

        let created_item_path = ObjectPath::default().into(); // how to get path from _collection
        let prompt = ObjectPath::default().into(); // temp Prompt

        let mut attributes_for_new: HashMap<&str, &str> = Default::default();
        for (key, value) in lookup_item.attributes() {
            attributes_for_new.insert(key.as_str(), value);
        }

        // TODO map portal::Item to crate::Item and push it to items attribute
        let item = item::Item::new(
            &attributes_for_new,
            lookup_item.secret().to_vec(),
            lookup_item.label(),
            lookup_item.created().as_secs(),
            lookup_item.modified().as_secs(),
            self.path().to_owned().into(),
        )
        .await;
        self.items.push(item);

        (created_item_path, prompt)
    }

    #[dbus_interface(property, name = "Items")]
    pub fn items(&self) -> Vec<ObjectPath> {
        self.items.iter().map(|item| item.path()).collect()
    }

    #[dbus_interface(property, name = "Label")]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[dbus_interface(property, name = "Locked")]
    pub fn locked(&self) -> bool {
        self.locked
    }

    #[dbus_interface(property, name = "Created")]
    pub fn created(&self) -> u64 {
        self.created
    }

    #[dbus_interface(property, name = "Modified")]
    pub fn modified(&self) -> u64 {
        self.modified
    }

    #[dbus_interface(signal)]
    pub async fn item_created(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[dbus_interface(signal)]
    pub async fn item_deleted(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[dbus_interface(signal)]
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
