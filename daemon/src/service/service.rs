//  org.freedesOnceCellktop.Secret.Service

use std::{collections::HashMap, sync::Arc};

use oo7::{
    dbus::api::Properties,
    portal::{Item, Keyring},
};
use serde::Serialize;
use zbus::{fdo, interface, zvariant, Error, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use crate::{
    service::{collection::Collection, session::Session},
    KEYRING,
};

#[derive(Serialize, Debug)]
pub struct Service {
    collections: Vec<Collection>,
    #[serde(skip_serializing)]
    keyring: Arc<Keyring>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    pub async fn open_session(
        &self,
        // algorithm: &str,
        input: Value<'_>,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        // WIP: not complete
        let session = Session::new(ObjectPath::try_from("/s1").unwrap().into()).await;
        Ok((
            OwnedValue::try_from(input).unwrap(), // avoid using unwrap
            ObjectPath::try_from(session.path().await).unwrap().into(),
        ))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        properties: Properties,
        alias: String,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<(ObjectPath, ObjectPath)> {
        let _attributes = properties.attributes(); // expand and pass these to Collection:new
        let collection = Collection::new("temp"); // temporarily
        let path = format!("/org/freedesktop/secrets_/collection/{}", &alias);

        let _ = object_server.at(path.clone(), collection).await;
        let new_collection_path = ObjectPath::try_from(path).unwrap(); // temporarily
        let prompt = ObjectPath::default().into(); // temp Prompt

        Ok((new_collection_path, prompt))
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> fdo::Result<(Vec<Item>, Vec<Item>)> {
        let items = match KEYRING.get().unwrap().search_items(&attributes).await {
            Ok(i) => i,
            Err(_) => todo!(),
        };

        let mut unlocked: Vec<Item> = Vec::new();
        let mut locked: Vec<Item> = Vec::new();

        for item in items {
            let attributes = item.attributes();
            if attributes.get("locked").is_some() {
                // this if condition is probably wrong
                // how to access &AttributeValue value
                locked.push(item)
            } else {
                unlocked.push(item)
            }
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        // manage unlock state in memory
        // when do we need to prompt?
        let mut unlocked: Vec<OwnedObjectPath> = Vec::new();

        'main: for object in objects {
            for collection in &mut self.collections {
                if collection.path().as_str() == object.as_str() {
                    if collection.locked() {
                        collection.set_locked(false).await;
                        unlocked.push(object.clone());
                    } else {
                        break 'main;
                    }
                }
            }
        }

        if unlocked.len() == 0 {
            unlocked.push(ObjectPath::default().into());
        }

        let prompt = ObjectPath::default().into(); // temporarily

        Ok((unlocked, prompt))
    }

    #[zbus(out_args("locked", "prompt"))]
    pub async fn lock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        // manage lock state in memory
        // when do we need to prompt?
        let mut locked: Vec<OwnedObjectPath> = Vec::new();

        for object in objects {
            for collection in &mut self.collections {
                if collection.path().as_str() == object.as_str() {
                    if !collection.locked() {
                        collection.set_locked(true).await;
                        locked.push(object.clone());
                    }
                }
            }
        }

        if locked.len() == 0 {
            locked.push(ObjectPath::default().into());
        }

        let prompt = ObjectPath::default().into(); // temporarily

        Ok((locked, prompt))
    }

    pub async fn get_secrets(&self, items: Vec<OwnedObjectPath>) {
        // WIP: not complete
        if KEYRING.get().unwrap().n_items().await == 0 {
            return;
        }

        // call item iface get_secret multiple times ?

        for in_collection in &self.collections {
            for item in &items {
                if in_collection.path().as_str() == item.as_str() {}
            }
        }
    }

    pub async fn read_alias(&self, name: &str) -> ObjectPath {
        let mut ret = ObjectPath::default();
        for collection in &self.collections {
            if collection.label() == name {
                ret = collection.path().into();
            }
        }

        ret
    }

    pub async fn set_alias(&mut self, name: String, collection: OwnedObjectPath) {
        // WIP: not complete:: handle alias
        for in_collection in &mut self.collections {
            if in_collection.path().as_str() == collection.as_str() {
                in_collection.set_label(name.clone()).await;
            }
        }
    }

    #[zbus(property, name = "Collections")]
    pub fn collections(&self) -> Vec<ObjectPath> {
        self.collections
            .iter()
            .map(|collection| collection.path())
            .collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[zbus(signal)]
    pub async fn collection_deleted(ctxt: &SignalContext<'_>) -> Result<(), Error>;

    #[zbus(signal)]
    pub async fn collection_changed(ctxt: &SignalContext<'_>) -> Result<(), Error>;
}

impl Service {
    pub async fn new() -> Self {
        Self {
            collections: Vec::new(),
            keyring: Arc::new(Keyring::load_default().await.unwrap()),
        }
    }

    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }
}
