// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};

use oo7::{
    dbus::api::{Properties, SecretInner},
    portal::{self, Keyring},
};
use tokio::sync::RwLock;
use zbus::{interface, message::Header, zvariant, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::{error::ServiceError, item, service_manager::ServiceManager, Result, Service};
use crate::SECRET_COLLECTION_PREFIX;

#[derive(Clone, Debug)]
pub struct Collection {
    keyring: Arc<Keyring>,
    items: Arc<RwLock<Vec<item::Item>>>,
    alias: Arc<RwLock<String>>,
    label: Arc<RwLock<String>>,
    locked: Arc<AtomicBool>,
    created: Duration,
    modified: Duration,
    manager: Arc<Mutex<ServiceManager>>,
    item_counter: Arc<RwLock<i32>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    pub async fn delete(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath> {
        let _ = object_server.remove::<Self, _>(&self.path).await;
        // send signal
        Service::collection_deleted(&ctxt, self.path.as_ref()).await?;
        let label = self.label().await;
        self.manager.lock().unwrap().remove_collection(&label);

        tracing::info!("Collection deleted: {}", self.path);

        // gnome-keyring-daemon returns an empty objectpath: '/' here
        Ok(ObjectPath::default())
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<portal::Item>> {
        self.keyring
            .search_items(&attributes)
            .await
            .map_err(From::from)
    }

    pub async fn create_item(
        &self,
        properties: Properties,
        secret: SecretInner,
        replace: bool,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> Result<(OwnedObjectPath, ObjectPath)> {
        let label = properties.label();
        let attributes = properties.attributes().unwrap();

        let session = secret.0;
        let parameters = secret.1;
        let value = secret.2;
        let content_type = secret.3;

        let item = self
            .keyring
            .create_item(label, &attributes, value, replace)
            .await
            .map_err::<ServiceError, _>(From::from)?;
        *self.item_counter.write().await += 1;

        let item = item::Item::new(
            item,
            parameters,
            content_type,
            *self.item_counter.read().await,
            self.path(),
            Arc::clone(&self.keyring),
            Arc::clone(&self.manager),
        )
        .await;
        let path = OwnedObjectPath::from(item.path());
        tracing::info!("Item: created: {}", path);

        object_server.at(&path, item.clone()).await.unwrap();

        let connection_out = Arc::new(connection.to_owned());
        let collection_path = header.path().unwrap().to_owned();

        // to update the items property and send out the PropertiesChanged signal
        tokio::spawn(async move {
            let connection = Arc::clone(&connection_out);

            let interface_ref = connection
                .object_server()
                .interface::<_, Collection>(collection_path)
                .await
                .unwrap();
            let interface = interface_ref.get_mut().await;

            interface.set_items(item).await;
            interface
                .items_changed(interface_ref.signal_context())
                .await
                .unwrap();
        });

        // no prompt required here (client side handles this) so returning an empty
        // objectpath: '/' is enough.
        let prompt = ObjectPath::default();

        // signal
        Self::item_created(&ctxt, path.as_ref()).await?;

        Ok((path, prompt))
    }

    #[zbus(property, name = "Items")]
    pub async fn items(&self) -> Vec<OwnedObjectPath> {
        self.items
            .read()
            .await
            .iter()
            .map(|item| OwnedObjectPath::from(item.path()))
            .collect()
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.label.read().await.clone()
    }

    #[zbus(property)]
    pub async fn set_label(&self, label: &str) {
        *self.label.write().await = label.to_owned();
    }

    #[zbus(property, name = "Locked")]
    pub fn locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[zbus(property, name = "Created")]
    pub fn created_as_secs(&self) -> u64 {
        self.created.as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub fn modified_as_secs(&self) -> u64 {
        self.modified.as_secs()
    }

    #[zbus(signal)]
    pub async fn item_created(ctxt: &SignalContext<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_deleted(ctxt: &SignalContext<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_changed(ctxt: &SignalContext<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

impl Collection {
    pub fn new(
        label: &str,
        alias: &str,
        created: Duration,
        keyring: Arc<Keyring>,
        manager: Arc<Mutex<ServiceManager>>,
    ) -> Self {
        Self {
            items: Default::default(),
            label: Arc::new(RwLock::new(label.to_owned())),
            alias: Arc::new(RwLock::new(alias.to_owned())),
            locked: Arc::new(AtomicBool::new(true)),
            modified: created,
            item_counter: Arc::new(RwLock::new(0)),
            path: OwnedObjectPath::try_from(format!("{}{}", SECRET_COLLECTION_PREFIX, label))
                .unwrap(),
            created,
            keyring,
            manager,
        }
    }

    pub fn path(&self) -> ObjectPath {
        self.path.as_ref()
    }

    pub async fn items_read(&self) -> Vec<item::Item> {
        self.items.read().await.clone()
    }

    pub async fn set_items(&self, item: item::Item) {
        self.items.write().await.push(item);
    }

    pub async fn drop_item(&self, path: ObjectPath<'_>) {
        let mut index = 0;
        for item in self.items.read().await.iter() {
            if item.path() == path {
                break;
            }
            index += 1;
        }

        self.items.write().await.remove(index);
    }

    pub async fn alias(&self) -> String {
        self.alias.read().await.clone()
    }

    pub async fn set_alias(&self, alias: &str) {
        *self.alias.write().await = alias.to_string();
    }

    pub async fn set_locked(&self, locked: bool) {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
    }
}
