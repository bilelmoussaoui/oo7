// org.freedesktop.Secret.Item

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
};

use oo7::{
    dbus::{ServiceError, api::DBusSecretInner},
    file,
};
use tokio::sync::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Service, collection::Collection, error::custom_service_error};

#[derive(Debug, Clone)]
enum InnerItem {
    Locked(file::LockedItem),
    Unlocked(file::UnlockedItem),
}

#[derive(Debug, Clone)]
pub struct Item {
    // Properties
    locked: Arc<AtomicBool>,
    inner: Arc<Mutex<InnerItem>>,
    // Other attributes
    service: Service,
    collection_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    pub async fn delete(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let Some(collection) = self
            .service
            .collection_from_path(&self.collection_path)
            .await
        else {
            return Err(ServiceError::NoSuchObject(format!(
                "Collection `{}` does not exist.",
                &self.collection_path
            )));
        };

        collection.delete_item(&self.path).await?;
        object_server.remove::<Self, _>(&self.path).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_deleted(&signal_emitter, &self.path).await?;

        tracing::info!("Item `{}` deleted.", &self.path);

        Ok(OwnedObjectPath::default())
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(DBusSecretInner,), ServiceError> {
        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        match &*self.inner.lock().await {
            InnerItem::Locked(_inner) => {
                tracing::error!("Cannot get secret of a locked object `{}`", self.path);
                Err(ServiceError::IsLocked(format!(
                    "Cannot get secret of a locked object `{}`.",
                    self.path
                )))
            }
            InnerItem::Unlocked(inner) => {
                let secret = inner.secret();
                let content_type = secret.content_type();

                tracing::debug!("Secret retrieved from the item: {}.", self.path);

                match session.aes_key() {
                    Some(key) => {
                        let iv = oo7::crypto::generate_iv().map_err(|err| {
                            custom_service_error(&format!("Failed to generate iv {err}."))
                        })?;
                        let encrypted = oo7::crypto::encrypt(secret, &key, &iv).map_err(|err| {
                            custom_service_error(&format!("Failed to encrypt secret {err}."))
                        })?;

                        Ok((DBusSecretInner(
                            session.path().clone().into(),
                            iv,
                            encrypted,
                            content_type,
                        ),))
                    }
                    None => Ok((DBusSecretInner(
                        session.path().clone().into(),
                        Vec::new(),
                        secret.to_vec(),
                        content_type,
                    ),)),
                }
            }
        }
    }

    pub async fn set_secret(&self, secret: DBusSecretInner) -> Result<(), ServiceError> {
        let DBusSecretInner(session, iv, secret, _content_type) = secret;

        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => {
                tracing::error!("Cannot set secret of a locked object `{}`", self.path);
                Err(ServiceError::IsLocked(format!(
                    "Cannot set secret of a locked object `{}`.",
                    self.path
                )))
            }
            InnerItem::Unlocked(inner) => {
                match session.aes_key() {
                    Some(key) => {
                        let decrypted = oo7::crypto::decrypt(secret, &key, &iv).map_err(|err| {
                            custom_service_error(&format!("Failed to decrypt secret {err}."))
                        })?;
                        inner.set_secret(decrypted);
                    }
                    None => {
                        inner.set_secret(secret);
                    }
                }

                Ok(())
            }
        }
    }

    #[zbus(property, name = "Locked")]
    pub async fn is_locked(&self) -> bool {
        matches!(&*self.inner.lock().await, InnerItem::Locked(_))
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> HashMap<String, String> {
        match &*self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => inner
                .attributes()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect(),
        }
    }

    // TODO This should return an error if the item is locked.
    // gnome-keyring would return, e.g. by running:
    //
    // busctl --user call org.freedesktop.secrets
    // /org/freedesktop/secrets/collection/test/1 org.freedesktop.DBus.Properties
    //
    // Secret.Error.IsLocked ("Cannot set property on a locked object",)
    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(), zbus::Error> {
        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => {
                inner.set_attributes(&attributes);
                Ok(())
            }
        }
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> String {
        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => inner.label().to_string(),
        }
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(&self, label: &str) {
        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => inner.set_label(label),
        }
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> u64 {
        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => inner.created().as_secs(),
        }
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> u64 {
        match &mut *self.inner.lock().await {
            InnerItem::Locked(_inner) => todo!(),
            InnerItem::Unlocked(inner) => inner.modified().as_secs(),
        }
    }
}

impl Item {
    pub fn new(
        item: file::UnlockedItem,
        locked: bool,
        service: Service,
        collection_path: OwnedObjectPath,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            locked: Arc::new(AtomicBool::new(locked)),
            inner: Arc::new(Mutex::new(InnerItem::Unlocked(item))),
            path,
            collection_path,
            service,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub async fn set_locked(&self, locked: bool) -> Result<(), ServiceError> {
        self.locked
            .store(locked, std::sync::atomic::Ordering::Relaxed);
        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Item: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }
}
