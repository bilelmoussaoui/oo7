// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime},
};

use oo7::dbus::api::{Properties, SecretInner};
use tokio::sync::{Mutex, RwLock};
use zbus::{interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::Result;
use crate::{item, service_manager::ServiceManager};

#[derive(Debug)]
#[allow(unused)]
pub struct Collection {
    // Properties
    items: Mutex<Vec<item::Item>>,
    label: Mutex<String>,
    locked: AtomicBool,
    created: Duration,
    modified: Mutex<Duration>,
    // Other attributes
    alias: Mutex<String>,
    manager: Arc<Mutex<ServiceManager>>,
    n_items: RwLock<i32>,
    path: OwnedObjectPath,
}

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

impl Collection {
    pub fn new(label: &str, alias: &str, manager: Arc<Mutex<ServiceManager>>) -> Self {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        Self {
            items: Default::default(),
            label: Mutex::new(label.to_owned()),
            locked: AtomicBool::new(true),
            modified: Mutex::new(created),
            alias: Mutex::new(alias.to_owned()),
            n_items: RwLock::new(0),
            path: OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}",
                label
            ))
            .unwrap(),
            created,
            manager,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}