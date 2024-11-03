// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use oo7::{
    dbus::{api::SecretInner, ServiceError},
    portal,
};
use tokio::sync::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::service_manager::ServiceManager;

#[derive(Debug, Clone)]
pub struct Item {
    // Properties
    locked: Arc<AtomicBool>,
    inner: Arc<Mutex<oo7::portal::Item>>,
    // Other attributes
    manager: Arc<Mutex<ServiceManager>>,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath, ServiceError> {
        todo!()
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(SecretInner,), ServiceError> {
        let manager = self.manager.lock().await;

        let Some(session) = manager.session(&session) else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{}` does not exist.",
                session
            )));
        };

        if self.is_locked().await {
            tracing::error!("Cannot get secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot get secret of a locked object `{}`.",
                self.path
            )));
        }

        let inner = self.inner.lock().await;
        let secret = inner.secret();

        tracing::debug!("Secret retrieved from the item: {}.", self.path);

        match session.aes_key() {
            Some(key) => {
                let iv = oo7::crypto::generate_iv();
                let encrypted = oo7::crypto::encrypt(secret, &key, &iv);

                Ok((SecretInner(
                    session.path().clone(),
                    iv,
                    encrypted,
                    "text/plain".to_owned(),
                ),))
            }
            None => Ok((SecretInner(
                session.path().clone(),
                Vec::new(),
                secret.to_vec(),
                "text/plain".to_owned(),
            ),)),
        }
    }

    pub async fn set_secret(&self, secret: SecretInner) -> Result<(), ServiceError> {
        let SecretInner(session, iv, secret, _content_type) = secret;
        let manager = self.manager.lock().await;

        let Some(session) = manager.session(&session) else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{}` does not exist.",
                session
            )));
        };

        let mut inner = self.inner.lock().await;

        match session.aes_key() {
            Some(key) => {
                let decrypted = oo7::crypto::decrypt(secret, &key, &iv);
                inner.set_secret(decrypted);
            }
            None => {
                inner.set_secret(secret);
            }
        }

        Ok(())
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        self.locked.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> HashMap<String, String> {
        self.inner
            .lock()
            .await
            .attributes()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect()
    }

    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(&self, attributes: HashMap<String, String>) {
        self.inner.lock().await.set_attributes(&attributes);
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        self.inner.lock().await.label().to_owned()
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) {
        self.inner.lock().await.set_label(label);
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> u64 {
        self.inner.lock().await.created().as_secs()
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        self.inner.lock().await.modified().as_secs()
    }
}

impl Item {
    pub fn new(
        item: portal::Item,
        locked: bool,
        manager: Arc<Mutex<ServiceManager>>,
        collection_path: &OwnedObjectPath,
        item_index: u32,
    ) -> Self {
        Self {
            locked: Arc::new(AtomicBool::new(locked)),
            inner: Arc::new(Mutex::new(item)),
            path: OwnedObjectPath::try_from(format!("{}/{}", collection_path, item_index)).unwrap(),
            manager,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
