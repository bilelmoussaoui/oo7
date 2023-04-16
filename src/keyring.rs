use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "async-std")]
use async_std::sync::RwLock;
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::{
    dbus::{self, Algorithm, DEFAULT_COLLECTION},
    portal, Result,
};

/// A [Secret Service](crate::dbus) or [file](crate::portal) backed keyring
/// implementation.
///
/// It will automatically use the file backend if the application is sandboxed
/// and otherwise falls back to the DBus service.
///
/// The File backend requires a [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) implementation
/// to retrieve the key that will be used to encrypt the backend file.
#[derive(Debug)]
pub enum Keyring {
    #[doc(hidden)]
    File(Arc<portal::Keyring>),
    #[doc(hidden)]
    DBus(dbus::Collection<'static>),
}

impl Keyring {
    /// Create a new instance of the Keyring.
    pub async fn new() -> Result<Self> {
        let is_sandboxed = crate::is_sandboxed().await;
        if is_sandboxed {
            #[cfg(feature = "tracing")]
            tracing::debug!("Application is sandboxed, using the file backend");

            match portal::Keyring::load_default().await {
                Ok(portal) => return Ok(Self::File(Arc::new(portal))),
                // Do nothing in this case, we are supposed to fallback to the host keyring
                Err(portal::Error::PortalNotAvailable) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        "org.freedesktop.portal.Secrets is not available, falling back to the Sercret Service backend"
                    );
                }
                Err(e) => return Err(crate::Error::Portal(e)),
            };
        } else {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Application is not sandboxed, falling back to the Sercret Service backend"
            );
        }
        let service = match dbus::Service::new(Algorithm::Encrypted).await {
            Ok(service) => Ok(service),
            Err(dbus::Error::Zbus(zbus::Error::Unsupported)) => {
                dbus::Service::new(Algorithm::Plain).await
            }
            Err(e) => Err(e),
        }?;
        let collection = match service.default_collection().await {
            Ok(c) => Ok(c),
            Err(dbus::Error::NotFound(_)) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Default collection doesn't exists, trying to create it");
                service
                    .create_collection("Login", Some(DEFAULT_COLLECTION))
                    .await
            }
            Err(e) => Err(e),
        }?;
        Ok(Self::DBus(collection))
    }

    /// Unlock the used collection if using the Secret service.
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn unlock(&self) -> Result<()> {
        // No unlocking is needed for the file backend
        if let Self::DBus(backend) = self {
            backend.unlock().await?;
        };
        Ok(())
    }

    /// Lock the used collection if using the Secret service.
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn lock(&self) -> Result<()> {
        // No locking is needed for the file backend
        if let Self::DBus(backend) = self {
            backend.lock().await?;
        };
        Ok(())
    }

    /// Remove items that matches the attributes.
    pub async fn delete(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                let items = backend.search_items(attributes).await?;
                for item in items {
                    item.delete().await?;
                }
            }
            Self::File(backend) => {
                backend.delete(attributes).await?;
            }
        };
        Ok(())
    }

    /// Retrieve all the items.
    ///
    /// If using the Secret Service, it will retrieve all the items in the
    /// [`DEFAULT_COLLECTION`].
    pub async fn items(&self) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.items().await;
                items
                    .into_iter()
                    // Ignore invalid items
                    .flatten()
                    .map(|i| Item::for_file(i, Arc::clone(backend)))
                    .collect::<Vec<_>>()
            }
        };
        Ok(items)
    }

    /// Create a new item.
    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: impl AsRef<[u8]>,
        replace: bool,
    ) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                backend
                    .create_item(label, attributes, secret, replace, "text/plain")
                    .await?;
            }
            Self::File(backend) => {
                backend
                    .create_item(label, attributes, secret, replace)
                    .await?;
            }
        };
        Ok(())
    }

    /// Find items based on their attributes.
    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.search_items(attributes).await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.search_items(attributes).await?;
                items
                    .into_iter()
                    .map(|i| Item::for_file(i, Arc::clone(backend)))
                    .collect::<Vec<_>>()
            }
        };
        Ok(items)
    }
}

/// A generic secret with a label and attributes.
#[derive(Debug)]
pub enum Item {
    #[doc(hidden)]
    File(RwLock<portal::Item>, Arc<portal::Keyring>),
    #[doc(hidden)]
    DBus(dbus::Item<'static>),
}

impl Item {
    fn for_file(item: portal::Item, backend: Arc<portal::Keyring>) -> Self {
        Self::File(RwLock::new(item), backend)
    }

    fn for_dbus(item: dbus::Item<'static>) -> Self {
        Self::DBus(item)
    }

    /// The item label.
    pub async fn label(&self) -> Result<String> {
        let label = match self {
            Self::File(item, _) => item.read().await.label().to_owned(),
            Self::DBus(item) => item.label().await?,
        };
        Ok(label)
    }

    /// Sets the item label.
    pub async fn set_label(&self, label: &str) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                item.write().await.set_label(label);

                let item_guard = item.read().await;
                let attributes = item_guard
                    .attributes()
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_string()))
                    .collect::<HashMap<_, _>>();
                backend
                    .create_item(
                        item_guard.label(),
                        attributes
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<HashMap<_, _>>(),
                        &*item_guard.secret(),
                        true,
                    )
                    .await?;
            }
            Self::DBus(item) => item.set_label(label).await?,
        };
        Ok(())
    }

    /// Retrieve the item attributes.
    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        let attributes = match self {
            Self::File(item, _) => item
                .read()
                .await
                .attributes()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            Self::DBus(item) => item.attributes().await?,
        };
        Ok(attributes)
    }

    /// Sets the item attributes.
    pub async fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                item.write().await.set_attributes(attributes.clone());
                let item_guard = item.read().await;
                backend
                    .create_item(item_guard.label(), attributes, &*item_guard.secret(), true)
                    .await?;
            }
            Self::DBus(item) => item.set_attributes(attributes).await?,
        };
        Ok(())
    }

    /// Sets a new secret.
    pub async fn set_secret(&self, secret: impl AsRef<[u8]>) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                item.write().await.set_secret(secret);
                let item_guard = item.read().await;
                let attributes = item_guard
                    .attributes()
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_string()))
                    .collect::<HashMap<_, _>>();

                backend
                    .create_item(
                        item_guard.label(),
                        attributes
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<HashMap<_, _>>(),
                        &*item_guard.secret(),
                        true,
                    )
                    .await?;
            }
            Self::DBus(item) => item.set_secret(secret, "text/plain").await?,
        };
        Ok(())
    }

    /// Retrieves the stored secret.
    pub async fn secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        let secret = match self {
            Self::File(item, _) => item.read().await.secret(),
            Self::DBus(item) => item.secret().await?,
        };
        Ok(secret)
    }

    /// Delete the item.
    pub async fn delete(&self) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                let attributes = item
                    .read()
                    .await
                    .attributes()
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_string()))
                    .collect::<HashMap<_, _>>();

                backend
                    .delete(
                        attributes
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<HashMap<_, _>>(),
                    )
                    .await?;
            }
            Self::DBus(item) => {
                item.delete().await?;
            }
        };
        Ok(())
    }
}
