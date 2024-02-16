// org.freedesktop.Secret.Collection

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use oo7::{
    dbus::api::{Properties, SecretInner},
    portal::{Item, Keyring},
};
use tokio::sync::RwLock;
use zbus::{interface, zvariant, ObjectServer, SignalContext};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::{error::ServiceError, prompt::Prompt, Result, Service};

const SECRET_COLLECTION_OBJECTPATH: &str = "/org/freedesktop/secrets.Devel/collection/";

#[derive(Debug)]
pub struct Collection {
    keyring: Arc<Keyring>,
    pub(crate) items: RwLock<Vec<super::item::Item>>,
    alias: RwLock<String>,
    label: String,
    locked: AtomicBool,
    created: Duration,
    modified: Duration,
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
        Ok(Prompt::default())
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
        // TODO currently returns Vec<oo7::portal::Item>, this should be a path
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
    ) -> Result<(OwnedObjectPath, Prompt)> {
        let label = properties.label();
        let attributes = properties.attributes().unwrap();

        let session = secret.0;
        let parameters = secret.1;
        let value = secret.2;
        let content_type = secret.3;

        // TODO: Use the session to encrypt the data
        // TODO: figure out what should be done regarding the content type

        let item = self
            .keyring
            .create_item(label, &attributes, value, replace)
            .await
            .map_err::<ServiceError, _>(From::from)?;

        let prompt = Prompt::default(); // temp Prompt

        let item = super::item::Item::new(item, self.path(), Arc::clone(&self.keyring)).await;
        let path = OwnedObjectPath::from(item.path());
        self.items.write().await.push(item);

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
    pub fn new(label: &str, alias: &str, created: Duration, keyring: Arc<Keyring>) -> Self {
        Self {
            items: Default::default(),
            label: label.to_owned(),
            alias: RwLock::new(alias.to_owned()),
            locked: AtomicBool::new(false),
            created: created,
            modified: created,
            path: OwnedObjectPath::try_from(format!("{}{}", SECRET_COLLECTION_OBJECTPATH, alias))
                .unwrap(),
            keyring,
        }
    }

    pub fn path(&self) -> ObjectPath {
        self.path.as_ref()
    }

    pub async fn set_alias(&self, ctxt: &zbus::SignalContext<'_>, alias: &str) -> Result<()> {
        *self.alias.write().await = alias.to_owned();
        Service::collection_changed(ctxt, self.path.as_ref()).await?;
        Ok(())
    }

    pub async fn set_locked(&self, locked: bool) {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn created(&self) -> &Duration {
        &self.created
    }

    pub fn modified(&self) -> &Duration {
        &self.modified
    }
}
