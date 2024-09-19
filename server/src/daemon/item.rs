// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oo7::{
    dbus::api::SecretInner,
    portal::{self, api::AttributeValue, Keyring},
};
use tokio::sync::RwLock;
use zbus::{
    object_server::SignalContext,
    zvariant::{ObjectPath, OwnedObjectPath},
    ObjectServer,
};

use super::{
    collection::Collection, error::ServiceError, prompt::Prompt, service_manager::ServiceManager,
    Result,
};

#[derive(Debug)]
pub struct Item {
    inner: RwLock<portal::Item>,
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
    ) -> Result<Prompt> {
        let inner = self.inner.read().await;
        let attributes = inner.attributes();
        self.keyring
            .delete(attributes)
            .await
            .map_err::<ServiceError, _>(From::from)?;
        object_server.remove::<Item, _>(self.path()).await?;
        Collection::item_deleted(&ctxt, self.path()).await?;
        Ok(Prompt::default())
    }

    #[zbus(name = "GetSecret")]
    pub async fn secret(&self, session: ObjectPath<'_>) -> Result<SecretInner> {
        let inner = self.inner.read().await;
        let secret = inner.secret();
        // TODO: get the session based on it object path and figure out the parameters
        // to pass, also, what we should do about the content-type?
        // Ok(SecretInner(session, parameters, secret.to_vec(), content_type))
        todo!()
    }

    pub async fn set_secret(&self, secret: Vec<u8>) {
        let mut inner = self.inner.write().await;
        inner.set_secret(secret);
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub async fn attributes(&self) -> HashMap<String, AttributeValue> {
        let inner = self.inner.read().await;
        inner.attributes().clone()
    }

    pub async fn set_attributes(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        attributes: HashMap<&str, &str>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.set_attributes(&attributes);
        Collection::item_changed(&ctxt, self.path()).await?;
        Ok(())
    }

    pub async fn label(&self) -> String {
        let inner = self.inner.read().await;
        inner.label().to_owned()
    }

    pub async fn set_label(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        label: &str,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.set_label(label);
        Collection::item_changed(&ctxt, self.path()).await?;
        Ok(())
    }

    pub async fn created(&self) -> u64 {
        self.inner.read().await.created().as_secs()
    }

    pub async fn modified(&self) -> u64 {
        self.inner.read().await.modified().as_secs()
    }
}

impl Item {
    pub async fn new(
        item: portal::Item,
        parameters: Vec<u8>,
        content_type: String,
        collection_path: ObjectPath<'_>,
        keyring: Arc<Keyring>,
        manager: Arc<Mutex<ServiceManager>>,
    ) -> Self {
        Self {
            path: OwnedObjectPath::try_from(format!("{}/items/{}", collection_path, item.label(),))
                .unwrap(),
            inner: RwLock::new(item),
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
