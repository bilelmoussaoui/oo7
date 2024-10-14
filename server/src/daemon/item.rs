// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use oo7::{
    crypto,
    dbus::api::SecretInner,
    portal::{self, Keyring},
};
use tokio::{self, sync::RwLock};
use zbus::{
    zvariant::{ObjectPath, OwnedObjectPath},
    ObjectServer,
};

use super::{collection::Collection, error::ServiceError, service_manager::ServiceManager, Result};

#[derive(Clone, Debug)]
pub struct Item {
    inner: Arc<RwLock<portal::Item>>,
    content_type: String,
    path: OwnedObjectPath,
    collection: OwnedObjectPath,
    keyring: Arc<Keyring>,
    locked: Arc<AtomicBool>,
    manager: Arc<Mutex<ServiceManager>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    pub async fn delete(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath> {
        let inner = self.inner.read().await;
        let attributes = inner.attributes();
        self.keyring
            .delete(attributes)
            .await
            .map_err::<ServiceError, _>(From::from)?;

        let interface_ref = object_server
            .interface::<_, Collection>(self.collection())
            .await
            .unwrap();
        let interface = interface_ref.get_mut().await;

        // update Collection.Items property
        interface.drop_item(self.path()).await;
        interface
            .items_changed(interface_ref.signal_context())
            .await
            .unwrap();

        object_server.remove::<Item, _>(self.path()).await?;
        // send ItemDeleted signal
        Collection::item_deleted(interface_ref.signal_context(), self.path()).await?;

        tracing::info!("Item: deleted: {}", self.path());

        // a prompt isn't required here. returning an empty objectpath: '/' is enough
        Ok(ObjectPath::default())
    }

    #[zbus(name = "GetSecret")]
    pub async fn secret(&self, session: ObjectPath<'_>) -> Result<(SecretInner,)> {
        let inner = self.inner.read().await;
        let secret = inner.secret();
        let content_type = self.content_type();

        let session = self.manager.lock().unwrap().session(session);
        if session.is_none() {
            tracing::error!("The session does not exist");
            return Err(ServiceError::NoSession);
        }

        let session = session.unwrap();
        let iv = crypto::generate_iv();
        let key = session.aes_key();

        let secret = &crypto::encrypt(secret, key, iv.clone());

        tracing::info!("GetSecret called for item: {}", self.path);

        Ok((SecretInner(
            session.path().into(),
            iv,
            secret.to_vec(),
            content_type.to_owned(),
        ),))
    }

    pub async fn set_secret(&self, secret: SecretInner) -> Result<()> {
        let session = secret.0;
        let iv = secret.1;
        let value = secret.2;

        let session = self.manager.lock().unwrap().session(session.into());
        if session.is_none() {
            tracing::info!("The session does not exist");
            return Err(ServiceError::NoSession);
        }

        let session = session.unwrap();
        let key = session.aes_key();
        let secret = crypto::decrypt(value, key, iv);

        let mut inner = self.inner.write().await;
        inner.set_secret(secret);

        tracing::info!("SetSecret called for item: {}. secret updated", self.path);

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub fn locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> HashMap<String, String> {
        let inner = self.inner.read().await;
        let inner_attributes = inner.attributes().clone();

        let mut attributes: HashMap<String, String> =
            HashMap::with_capacity(inner_attributes.len());

        for (key, value) in inner_attributes.iter() {
            attributes.insert(key.to_owned(), value.to_string());
        }

        attributes
    }

    #[zbus(property)]
    pub async fn set_attributes(&self, attributes: HashMap<String, String>) -> zbus::Result<()> {
        let mut inner = self.inner.write().await;
        inner.set_attributes(&attributes);
        Ok(())
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        let inner = self.inner.read().await;
        inner.label().to_owned()
    }

    #[zbus(property)]
    pub async fn set_label(&self, label: &str) -> zbus::Result<()> {
        let mut inner = self.inner.write().await;
        inner.set_label(label);
        Ok(())
    }

    #[zbus(property, name = "Created")]
    pub async fn created(&self) -> u64 {
        self.inner.read().await.created().as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified(&self) -> u64 {
        self.inner.read().await.modified().as_secs()
    }
}

impl Item {
    pub async fn new(
        item: portal::Item,
        content_type: String,
        item_counter: i32,
        collection_path: ObjectPath<'_>,
        keyring: Arc<Keyring>,
        manager: Arc<Mutex<ServiceManager>>,
    ) -> Self {
        Self {
            path: OwnedObjectPath::try_from(format!("{}/{}", collection_path, item_counter))
                .unwrap(),
            inner: Arc::new(RwLock::new(item)),
            collection: collection_path.into(),
            locked: Arc::new(AtomicBool::new(false)),
            content_type,
            keyring,
            manager,
        }
    }

    pub(crate) fn path(&self) -> ObjectPath {
        self.path.as_ref()
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
    }

    pub(crate) fn collection(&self) -> ObjectPath {
        self.collection.as_ref()
    }

    pub async fn set_locked(&self, locked: bool) {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
    }
}
