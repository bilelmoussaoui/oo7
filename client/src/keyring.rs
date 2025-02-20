use std::{collections::HashMap, sync::Arc, time::Duration};

#[cfg(feature = "async-std")]
use async_lock::RwLock;
#[cfg(feature = "tokio")]
use tokio::sync::RwLock;

use crate::{AsAttributes, Result, Secret, dbus, file};

/// A [Secret Service](crate::dbus) or [file](crate::file) backed keyring
/// implementation.
///
/// It will automatically use the file backend if the application is sandboxed
/// and otherwise falls back to the DBus service using it [default
/// collection](crate::dbus::Service::default_collection).
///
/// The File backend requires a [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html) implementation
/// to retrieve the key that will be used to encrypt the backend file.
#[derive(Debug)]
pub enum Keyring {
    #[doc(hidden)]
    File(Arc<file::Keyring>),
    #[doc(hidden)]
    DBus(dbus::Collection<'static>),
}

impl Keyring {
    /// Create a new instance of the Keyring that automatically removes the
    /// broken items from the file backend keyring.
    ///
    /// This method will probably be removed in future versions if the
    /// misbehaviour is tracked and fixed.
    #[deprecated = "The method is no longer useful as the user can fix the keyring using oo7-cli"]
    pub async fn with_broken_item_cleanup() -> Result<Self> {
        Self::new_inner(true).await
    }

    /// Create a new instance of the Keyring.
    pub async fn new() -> Result<Self> {
        Self::new_inner(false).await
    }

    async fn new_inner(auto_delete_broken_items: bool) -> Result<Self> {
        let is_sandboxed = ashpd::is_sandboxed().await;
        if is_sandboxed {
            #[cfg(feature = "tracing")]
            tracing::debug!("Application is sandboxed, using the file backend");

            match file::Keyring::load_default().await {
                Ok(file) => return Ok(Self::File(Arc::new(file))),
                // Do nothing in this case, we are supposed to fallback to the host keyring
                Err(super::file::Error::Portal(ashpd::Error::PortalNotFound(_))) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        "org.freedesktop.portal.Secrets is not available, falling back to the Secret Service backend"
                    );
                }
                Err(e) => {
                    if matches!(e, file::Error::IncorrectSecret) && auto_delete_broken_items {
                        let keyring = unsafe { file::Keyring::load_default_unchecked().await? };
                        let deleted_items = keyring.delete_broken_items().await?;
                        debug_assert!(deleted_items > 0);
                        return Ok(Self::File(Arc::new(keyring)));
                    }
                    return Err(crate::Error::File(e));
                }
            };
        } else {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Application is not sandboxed, falling back to the Secret Service backend"
            );
        }
        let service = dbus::Service::new().await?;
        let collection = service.default_collection().await?;
        Ok(Self::DBus(collection))
    }

    /// Unlock the used collection if using the Secret service.
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn unlock(&self) -> Result<()> {
        // No unlocking is needed for the file backend
        if let Self::DBus(backend) = self {
            backend.unlock(None).await?;
        };
        Ok(())
    }

    /// Lock the used collection if using the Secret service.
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn lock(&self) -> Result<()> {
        // No locking is needed for the file backend
        if let Self::DBus(backend) = self {
            backend.lock(None).await?;
        };
        Ok(())
    }

    /// Remove items that matches the attributes.
    pub async fn delete(&self, attributes: &impl AsAttributes) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                let items = backend.search_items(attributes).await?;
                for item in items {
                    item.delete(None).await?;
                }
            }
            Self::File(backend) => {
                backend.delete(attributes).await?;
            }
        };
        Ok(())
    }

    /// Retrieve all the items.
    pub async fn items(&self) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.items().await?;
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
        attributes: &impl AsAttributes,
        secret: impl Into<Secret>,
        replace: bool,
    ) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                backend
                    .create_item(label, attributes, secret, replace, None)
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
    pub async fn search_items(&self, attributes: &impl AsAttributes) -> Result<Vec<Item>> {
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

    /// Get the inner file backend if the keyring is backed by one.
    pub fn as_file(&self) -> Arc<file::Keyring> {
        match self {
            Self::File(keyring) => keyring.clone(),
            _ => unreachable!(),
        }
    }

    /// Get the inner DBus backend if the keyring is backed by one.
    pub fn as_dbus(&self) -> &dbus::Collection {
        match self {
            Self::DBus(collection) => collection,
            _ => unreachable!(),
        }
    }
}

/// A generic secret with a label and attributes.
#[derive(Debug)]
pub enum Item {
    #[doc(hidden)]
    File(RwLock<file::Item>, Arc<file::Keyring>),
    #[doc(hidden)]
    DBus(dbus::Item<'static>),
}

impl Item {
    fn for_file(item: file::Item, backend: Arc<file::Keyring>) -> Self {
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

                backend
                    .create_item(
                        item_guard.label(),
                        &item_guard.attributes(),
                        item_guard.secret(),
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
    pub async fn set_attributes(&self, attributes: &impl AsAttributes) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                let index = backend
                    .lookup_item_index(item.read().await.attributes())
                    .await?;

                item.write().await.set_attributes(attributes);
                let item_guard = item.read().await;

                if let Some(index) = index {
                    backend.replace_item_index(index, &item_guard).await?;
                } else {
                    backend
                        .create_item(item_guard.label(), attributes, item_guard.secret(), true)
                        .await?;
                }
            }
            Self::DBus(item) => item.set_attributes(attributes).await?,
        };
        Ok(())
    }

    /// Sets a new secret.
    pub async fn set_secret(&self, secret: impl Into<Secret>) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                item.write().await.set_secret(secret);
                let item_guard = item.read().await;

                backend
                    .create_item(
                        item_guard.label(),
                        &item_guard.attributes(),
                        item_guard.secret(),
                        true,
                    )
                    .await?;
            }
            Self::DBus(item) => item.set_secret(secret).await?,
        };
        Ok(())
    }

    /// Retrieves the stored secret.
    pub async fn secret(&self) -> Result<Secret> {
        let secret = match self {
            Self::File(item, _) => item.read().await.secret(),
            Self::DBus(item) => item.secret().await?,
        };
        Ok(secret)
    }

    /// Whether the item is locked or not
    ///
    /// The method always returns `false` if keyring is backed by a file
    /// backend.
    pub async fn is_locked(&self) -> Result<bool> {
        if let Self::DBus(item) = self {
            item.is_locked().await.map_err(From::from)
        } else {
            Ok(false)
        }
    }

    /// Lock the item
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn lock(&self) -> Result<()> {
        if let Self::DBus(item) = self {
            item.lock(None).await?;
        }
        Ok(())
    }

    /// Unlock the item
    ///
    /// The method does nothing if keyring is backed by a file backend.
    pub async fn unlock(&self) -> Result<()> {
        if let Self::DBus(item) = self {
            item.unlock(None).await?;
        }
        Ok(())
    }

    /// Delete the item.
    pub async fn delete(&self) -> Result<()> {
        match self {
            Self::File(item, backend) => {
                let item_guard = item.read().await;

                backend.delete(&item_guard.attributes()).await?;
            }
            Self::DBus(item) => {
                item.delete(None).await?;
            }
        };
        Ok(())
    }

    /// The UNIX time when the item was created.
    pub async fn created(&self) -> Result<Duration> {
        match self {
            Self::DBus(item) => Ok(item.created().await?),
            Self::File(item, _) => Ok(item.read().await.created()),
        }
    }

    /// The UNIX time when the item was modified.
    pub async fn modified(&self) -> Result<Duration> {
        match self {
            Self::DBus(item) => Ok(item.modified().await?),
            Self::File(item, _) => Ok(item.read().await.modified()),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use tempfile::tempdir;
    use tokio::fs;

    use super::*;

    #[tokio::test]
    async fn portal_set_attributes() -> Result<()> {
        let data_dir = tempdir().unwrap();
        let dir = data_dir.path().join("keyrings");
        fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("default.keyring");

        let secret = crate::Secret::text("test");
        let keyring = Keyring::File(file::Keyring::load(&path, secret).await?.into());

        let items = keyring.items().await?;
        assert_eq!(items.len(), 0);

        keyring
            .create_item("my item", &vec![("key", "value")], "my_secret", false)
            .await?;

        let mut items = keyring.items().await?;
        assert_eq!(items.len(), 1);
        let item = items.remove(0);
        assert_eq!(item.label().await?, "my item");
        assert_eq!(item.secret().await?, Secret::text("my_secret"));
        let attrs = item.attributes().await?;
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs.get("key").unwrap(), "value");

        item.set_attributes(&vec![("key", "changed_value"), ("new_key", "new_value")])
            .await?;

        let mut items = keyring.items().await?;
        assert_eq!(items.len(), 1);
        let item = items.remove(0);
        assert_eq!(item.label().await?, "my item");
        assert_eq!(item.secret().await?, Secret::text("my_secret"));
        let attrs = item.attributes().await?;
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs.get("key").unwrap(), "changed_value");
        assert_eq!(attrs.get("new_key").unwrap(), "new_value");

        Ok(())
    }
}
