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
use zbus::{interface, object_server::SignalEmitter, proxy::Defaults, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::{error::Error, item, Service};

#[derive(Debug, Clone)]
pub struct Collection {
    // Properties
    items: Arc<Mutex<Vec<item::Item>>>,
    label: Arc<Mutex<String>>,
    locked: Arc<AtomicBool>,
    created: Duration,
    modified: Arc<Mutex<Duration>>,
    // Other attributes
    alias: Arc<Mutex<String>>,
    #[allow(unused)]
    keyring: Arc<Keyring>,
    service: Service,
    item_index: Arc<RwLock<u32>>,
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
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, ServiceError> {
        let results = self
            .search_inner_items(&attributes)
            .await
            .iter()
            .map(|item| item.path().clone())
            .collect::<Vec<_>>();

        if results.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in collection: {}.",
                attributes,
                self.path
            );
        } else {
            tracing::debug!(
                "Items with attributes {:?} found in collection: {}.",
                attributes,
                self.path
            );
        }

        Ok(results)
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
            .map(|i| i.path().to_owned())
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

    #[zbus(signal, name = "ItemCreated")]
    async fn item_created(
        signal_emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemDeleted")]
    async fn item_deleted(
        signal_emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemChanged")]
    pub async fn item_changed(
        signal_emitter: &SignalEmitter<'_>,
        item: &OwnedObjectPath,
    ) -> zbus::Result<()>;
}

impl Collection {
    pub fn new(
        label: &str,
        alias: &str,
        locked: bool,
        service: Service,
        keyring: Arc<Keyring>,
    ) -> Self {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        Self {
            items: Default::default(),
            label: Arc::new(Mutex::new(label.to_owned())),
            locked: Arc::new(AtomicBool::new(locked)),
            modified: Arc::new(Mutex::new(created)),
            alias: Arc::new(Mutex::new(alias.to_owned())),
            item_index: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}",
                label
            ))
            .unwrap(),
            created,
            service,
            keyring,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }

    pub async fn set_alias(&self, alias: &str) {
        *self.alias.lock().await = alias.to_owned();
    }

    pub async fn alias(&self) -> String {
        self.alias.lock().await.clone()
    }

    pub async fn search_inner_items(
        &self,
        attributes: &HashMap<String, String>,
    ) -> Vec<item::Item> {
        let mut items = Vec::new();

        for item in self.items.lock().await.iter() {
            if item.attributes().await == *attributes {
                items.push(item.clone());
            }
        }

        items
    }

    pub async fn item_from_path(&self, path: &OwnedObjectPath) -> Option<item::Item> {
        let items = self.items.lock().await;

        for item in items.iter() {
            if item.path() == path {
                return Some(item.clone());
            }
        }

        None
    }

    pub async fn set_locked(&self, locked: bool) -> Result<(), ServiceError> {
        let items = self.items.lock().await;

        for item in items.iter() {
            item.set_locked(locked).await?;
        }

        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.service.signal_emitter(service_path)?;
        Service::collection_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Collection: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    pub async fn dispatch_items(&self) -> Result<(), Error> {
        let keyring_items = self.keyring.items().await;
        let mut items = self.items.lock().await;
        let object_server = self.service.object_server();
        let mut n_items = 1;

        for keyring_item in keyring_items {
            let item = item::Item::new(
                keyring_item.map_err(Error::InvalidItem)?,
                self.is_locked().await,
                self.service.clone(),
                &self.path,
                n_items,
            );
            n_items += 1;

            items.push(item.clone());
            object_server.at(item.path().clone(), item).await?;
        }

        *self.item_index.write().await = n_items;

        Ok(())
    }
}
