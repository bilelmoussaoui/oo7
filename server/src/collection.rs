// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime},
};

use oo7::{
    dbus::{
        api::{Properties, SecretInner},
        ServiceError,
    },
    portal::Keyring,
};
use tokio::sync::{Mutex, RwLock};
use zbus::{interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

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
    #[allow(unused)]
    keyring: Arc<Keyring>,
    manager: Arc<Mutex<ServiceManager>>,
    n_items: RwLock<i32>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath, ServiceError> {
        todo!()
    }

    #[zbus(out_args("results"))]
    pub async fn search_items(
        &self,
        _attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, ServiceError> {
        todo!()
    }

    #[zbus(out_args("item", "prompt"))]
    pub async fn create_item(
        &self,
        _properties: Properties,
        _secret: SecretInner,
        _replace: bool,
    ) -> Result<(OwnedObjectPath, ObjectPath), ServiceError> {
        todo!()
    }

    #[zbus(property, name = "Items")]
    pub async fn items(&self) -> Vec<OwnedObjectPath> {
        self.items
            .lock()
            .await
            .iter()
            .map(|item| OwnedObjectPath::from(item.path()))
            .collect()
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.label.lock().await.clone()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) {
        *self.label.lock().await = label.to_owned();
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[zbus(property, name = "Created")]
    pub fn created_at(&self) -> u64 {
        self.created.as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.modified.lock().await.as_secs()
    }
}

impl Collection {
    pub fn new(
        label: &str,
        alias: &str,
        manager: Arc<Mutex<ServiceManager>>,
        keyring: Arc<Keyring>,
    ) -> Self {
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
            keyring,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
