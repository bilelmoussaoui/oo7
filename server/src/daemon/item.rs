// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oo7::{
    dbus::api::SecretInner,
    portal::{self, Keyring},
};
use tokio::sync::RwLock;
use zbus::{
    object_server::SignalContext,
    zvariant::{ObjectPath, OwnedObjectPath},
    ObjectServer,
};

use super::{collection::Collection, error::ServiceError, service_manager::ServiceManager, Result};

#[derive(Clone, Debug)]
pub struct Item {
    inner: Arc<RwLock<portal::Item>>,
    parameters: Vec<u8>,
    content_type: String,
    path: OwnedObjectPath,
    keyring: Arc<Keyring>,
    locked: bool,
    manager: Arc<Mutex<ServiceManager>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    pub async fn delete(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> Result<ObjectPath> {
        let inner = self.inner.read().await;
        let attributes = inner.attributes();
        self.keyring
            .delete(attributes)
            .await
            .map_err::<ServiceError, _>(From::from)?;
        object_server.remove::<Item, _>(self.path()).await?;
        Collection::item_deleted(&ctxt, self.path()).await?;
        tracing::info!("Item: deleted: {}", self.path());

        // gnome-keyring-daemon returns an empty objectpath: '/' here
        Ok(ObjectPath::default())
    }

    #[zbus(name = "GetSecret")]
    pub async fn secret(&self, session: ObjectPath<'_>) -> Result<SecretInner> {
        let inner = self.inner.read().await;
        let secret = inner.secret();
        let parameters = self.parameters();
        let content_type = self.content_type();
        match self.manager.lock().unwrap().session(session.clone()) {
            Some(session) => Ok(SecretInner(
                session.path().into(),
                parameters.to_vec(),
                secret.to_vec(),
                content_type.to_owned(),
            )),
            None => {
                tracing::error!("Session {session} not found");
                Err(ServiceError::NoSession)
            }
        }
    }

    pub async fn set_secret(&self, secret: Vec<u8>) {
        let mut inner = self.inner.write().await;
        inner.set_secret(secret);
    }

    #[zbus(property, name = "Locked")]
    pub fn locked(&self) -> bool {
        self.locked
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
        parameters: Vec<u8>,
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
            parameters,
            content_type,
            keyring,
            manager,
            locked: true,
        }
    }

    pub(crate) fn path(&self) -> ObjectPath {
        self.path.as_ref()
    }

    pub(crate) fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
    }
}
