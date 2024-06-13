// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};

use oo7::{
    dbus::api::{Properties, SecretInner},
    portal::{Item, Keyring},
};
use tokio::sync::RwLock;
use zbus::{interface, zvariant, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::{
    error::ServiceError, prompt::Prompt, secret::Secret, service_manager::ServiceManager, Result,
    Service,
};
use crate::SECRET_COLLECTION_PREFIX;

#[derive(Clone, Debug)]
pub struct Collection {
    keyring: Arc<Keyring>,
    pub(crate) items: Arc<RwLock<Vec<super::item::Item>>>,
    alias: Arc<RwLock<String>>,
    label: String,
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
    ) -> Result<Prompt> {
        let _ = object_server.remove::<Self, _>(&self.path).await;
        Service::collection_deleted(&ctxt, self.path.as_ref()).await?;
        tracing::info!("Collection deleted: {}", self.path);

        Ok(Prompt::default())
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
        self.keyring
            .search_items(&attributes)
            .await
            .map_err(From::from)
    }

    pub async fn create_item(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        properties: Properties,
        secret: SecretInner,
        replace: bool,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, ObjectPath)> {
        let label = properties.label();
        let attributes = properties.attributes().unwrap();

        let session = secret.0;
        let parameters = secret.1;
        let value = secret.2;
        let content_type = secret.3;

        let session = self
            .manager
            .lock()
            .unwrap()
            .session(session.into())
            .unwrap();
        let aes_key = session.aes_key();

        let secret = if aes_key.is_none() {
            Secret::new(session.clone(), value, content_type.as_str())
        } else {
            Secret::new_encrypted(
                session.clone(),
                value,
                content_type.as_str(),
                aes_key.as_ref().unwrap(),
            )
        };

        let item = self
            .keyring
            .create_item(label, &attributes, secret.value(), replace)
            .await
            .map_err::<ServiceError, _>(From::from)?;
        *self.item_counter.write().await += 1;

        let item = super::item::Item::new(
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
        self.items.write().await.push(item.clone());
        object_server.at(&path, item).await.unwrap();

        // perform prompt
        let prompt = Prompt::new(Arc::clone(&self.manager), None);
        object_server
            .at(prompt.path().to_owned(), prompt.to_owned())
            .await?;

        // signal
        Self::item_created(&ctxt, path.as_ref()).await?;

        Ok((path, prompt.path().to_owned()))
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
    pub fn label(&self) -> &str {
        &self.label
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
            label: label.to_owned(),
            alias: Arc::new(RwLock::new(alias.to_owned())),
            locked: Arc::new(AtomicBool::new(false)),
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

    pub async fn set_alias(&self, ctxt: &zbus::SignalContext<'_>, alias: &str) -> Result<()> {
        *self.alias.write().await = alias.to_string();
        Service::collection_changed(ctxt, self.path.as_ref()).await?;
        Ok(())
    }

    pub async fn set_locked(&self, ctxt: &zbus::SignalContext<'_>, locked: bool) {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
        Service::collection_changed(ctxt, self.path.as_ref())
            .await
            .unwrap();
    }

    pub async fn item_counter(&self) -> i32 {
        *self.item_counter.read().await
    }

    pub async fn incr_item_counter(&self) {
        *self.item_counter.write().await += 1;
    }
}
