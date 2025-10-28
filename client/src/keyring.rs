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
    File(Arc<RwLock<Option<file::Keyring>>>),
    #[doc(hidden)]
    DBus(dbus::Collection<'static>),
}

impl Keyring {
    /// Create a new instance of the Keyring.
    pub async fn new() -> Result<Self> {
        let is_sandboxed = ashpd::is_sandboxed().await;
        if is_sandboxed {
            #[cfg(feature = "tracing")]
            tracing::debug!("Application is sandboxed, using the file backend");

            let secret = Secret::from(
                ashpd::desktop::secret::retrieve()
                    .await
                    .map_err(crate::file::Error::from)?,
            );
            match file::UnlockedKeyring::load(
                crate::file::api::Keyring::default_path()?,
                secret.clone(),
            )
            .await
            {
                Ok(file) => {
                    return Ok(Self::File(Arc::new(RwLock::new(Some(
                        file::Keyring::Unlocked(file),
                    )))));
                }
                // Do nothing in this case, we are supposed to fallback to the host keyring
                Err(super::file::Error::Portal(ashpd::Error::PortalNotFound(_))) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        "org.freedesktop.portal.Secrets is not available, falling back to the Secret Service backend"
                    );
                }
                Err(e) => {
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

    /// Unlock the used collection.
    pub async fn unlock(&self) -> Result<()> {
        match self {
            Self::DBus(backend) => backend.unlock(None).await?,
            Self::File(keyring) => {
                let mut kg = keyring.write().await;
                let kg_value = kg.take();
                if let Some(file::Keyring::Locked(locked)) = kg_value {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Unlocking file backend keyring");

                    // Retrieve secret from portal
                    let secret = Secret::from(
                        ashpd::desktop::secret::retrieve()
                            .await
                            .map_err(crate::file::Error::from)?,
                    );

                    let unlocked = locked.unlock(secret).await.map_err(crate::Error::File)?;
                    *kg = Some(file::Keyring::Unlocked(unlocked));
                } else {
                    *kg = kg_value;
                }
            }
        };
        Ok(())
    }

    /// Lock the used collection.
    pub async fn lock(&self) -> Result<()> {
        match self {
            Self::DBus(backend) => backend.lock(None).await?,
            Self::File(keyring) => {
                let mut kg = keyring.write().await;
                let kg_value = kg.take();
                if let Some(file::Keyring::Unlocked(unlocked)) = kg_value {
                    #[cfg(feature = "tracing")]
                    tracing::debug!("Locking file backend keyring");

                    let locked = unlocked.lock();
                    *kg = Some(file::Keyring::Locked(locked));
                } else {
                    *kg = kg_value;
                }
            }
        };
        Ok(())
    }

    /// Whether the keyring is locked or not.
    pub async fn is_locked(&self) -> Result<bool> {
        match self {
            Self::DBus(collection) => collection.is_locked().await.map_err(From::from),
            Self::File(keyring) => {
                let keyring_guard = keyring.read().await;
                Ok(keyring_guard.as_ref().expect("Keyring must exist").is_locked())
            }
        }
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
            Self::File(keyring) => {
                let kg = keyring.read().await;
                match kg.as_ref() {
                    Some(file::Keyring::Unlocked(backend)) => {
                        backend
                            .delete(attributes)
                            .await
                            .map_err(crate::Error::File)?;
                    }
                    Some(file::Keyring::Locked(_)) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                    _ => unreachable!("A keyring must exist"),
                }
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
            Self::File(keyring) => {
                let kg = keyring.read().await;
                match kg.as_ref() {
                    Some(file::Keyring::Unlocked(backend)) => {
                        let items = backend.items().await.map_err(crate::Error::File)?;
                        items
                            .into_iter()
                            // Ignore invalid items
                            .flatten()
                            .map(|i| Item::for_file(i, Arc::clone(keyring)))
                            .collect::<Vec<_>>()
                    }
                    Some(file::Keyring::Locked(_)) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                    _ => unreachable!("A keyring must exist"),
                }
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
            Self::File(keyring) => {
                let kg = keyring.read().await;
                match kg.as_ref() {
                    Some(file::Keyring::Unlocked(backend)) => {
                        backend
                            .create_item(label, attributes, secret, replace)
                            .await
                            .map_err(crate::Error::File)?;
                    }
                    Some(file::Keyring::Locked(_)) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                    _ => unreachable!("A keyring must exist"),
                }
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
            Self::File(keyring) => {
                let kg = keyring.read().await;
                match kg.as_ref() {
                    Some(file::Keyring::Unlocked(backend)) => {
                        let items = backend
                            .search_items(attributes)
                            .await
                            .map_err(crate::Error::File)?;
                        items
                            .into_iter()
                            .map(|i| Item::for_file(i, Arc::clone(keyring)))
                            .collect::<Vec<_>>()
                    }
                    Some(file::Keyring::Locked(_)) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                    _ => unreachable!("A keyring must exist"),
                }
            }
        };
        Ok(items)
    }
}

/// A generic secret with a label and attributes.
#[derive(Debug)]
pub enum Item {
    #[doc(hidden)]
    File(
        RwLock<Option<file::Item>>,
        Arc<RwLock<Option<file::Keyring>>>,
    ),
    #[doc(hidden)]
    DBus(dbus::Item<'static>),
}

impl Item {
    fn for_file(item: file::Item, backend: Arc<RwLock<Option<file::Keyring>>>) -> Self {
        Self::File(RwLock::new(Some(item)), backend)
    }

    fn for_dbus(item: dbus::Item<'static>) -> Self {
        Self::DBus(item)
    }

    /// The item label.
    pub async fn label(&self) -> Result<String> {
        let label = match self {
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                match file_item {
                    file::Item::Unlocked(unlocked) => unlocked.label().to_owned(),
                    file::Item::Locked(_) => return Err(crate::file::Error::Locked.into()),
                }
            }
            Self::DBus(item) => item.label().await?,
        };
        Ok(label)
    }

    /// Sets the item label.
    pub async fn set_label(&self, label: &str) -> Result<()> {
        match self {
            Self::File(item, keyring) => {
                let mut item_guard = item.write().await;
                let file_item = item_guard.as_mut().expect("Item must exist");

                match file_item {
                    file::Item::Unlocked(unlocked) => {
                        unlocked.set_label(label);

                        let kg = keyring.read().await;
                        match kg.as_ref() {
                            Some(file::Keyring::Unlocked(backend)) => {
                                backend
                                    .create_item(
                                        unlocked.label(),
                                        &unlocked.attributes(),
                                        unlocked.secret(),
                                        true,
                                    )
                                    .await
                                    .map_err(crate::Error::File)?;
                            }
                            Some(file::Keyring::Locked(_)) => {
                                return Err(crate::file::Error::Locked.into());
                            }
                            None => unreachable!("A keyring must exist"),
                        }
                    }
                    file::Item::Locked(_) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                }
            }
            Self::DBus(item) => item.set_label(label).await?,
        };
        Ok(())
    }

    /// Retrieve the item attributes.
    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        let attributes = match self {
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                match file_item {
                    file::Item::Unlocked(unlocked) => unlocked
                        .attributes()
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_string()))
                        .collect::<HashMap<_, _>>(),
                    file::Item::Locked(_) => return Err(crate::file::Error::Locked.into()),
                }
            }
            Self::DBus(item) => item.attributes().await?,
        };
        Ok(attributes)
    }

    /// Sets the item attributes.
    pub async fn set_attributes(&self, attributes: &impl AsAttributes) -> Result<()> {
        match self {
            Self::File(item, keyring) => {
                let kg = keyring.read().await;

                match kg.as_ref() {
                    Some(file::Keyring::Unlocked(backend)) => {
                        let mut item_guard = item.write().await;
                        let file_item = item_guard.as_mut().expect("Item must exist");

                        match file_item {
                            file::Item::Unlocked(unlocked) => {
                                let index = backend
                                    .lookup_item_index(&unlocked.attributes())
                                    .await
                                    .map_err(crate::Error::File)?;

                                unlocked.set_attributes(attributes);

                                if let Some(index) = index {
                                    backend
                                        .replace_item_index(index, unlocked)
                                        .await
                                        .map_err(crate::Error::File)?;
                                } else {
                                    backend
                                        .create_item(
                                            unlocked.label(),
                                            attributes,
                                            unlocked.secret(),
                                            true,
                                        )
                                        .await
                                        .map_err(crate::Error::File)?;
                                }
                            }
                            file::Item::Locked(_) => {
                                return Err(crate::file::Error::Locked.into());
                            }
                        }
                    }
                    Some(file::Keyring::Locked(_)) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                    None => unreachable!("A keyring must exist"),
                }
            }
            Self::DBus(item) => item.set_attributes(attributes).await?,
        };
        Ok(())
    }

    /// Sets a new secret.
    pub async fn set_secret(&self, secret: impl Into<Secret>) -> Result<()> {
        match self {
            Self::File(item, keyring) => {
                let mut item_guard = item.write().await;
                let file_item = item_guard.as_mut().expect("Item must exist");

                match file_item {
                    file::Item::Unlocked(unlocked) => {
                        unlocked.set_secret(secret);

                        let kg = keyring.read().await;
                        match kg.as_ref() {
                            Some(file::Keyring::Unlocked(backend)) => {
                                backend
                                    .create_item(
                                        unlocked.label(),
                                        &unlocked.attributes(),
                                        unlocked.secret(),
                                        true,
                                    )
                                    .await
                                    .map_err(crate::Error::File)?;
                            }
                            Some(file::Keyring::Locked(_)) => {
                                return Err(crate::file::Error::Locked.into());
                            }
                            None => unreachable!("A keyring must exist"),
                        }
                    }
                    file::Item::Locked(_) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                }
            }
            Self::DBus(item) => item.set_secret(secret).await?,
        };
        Ok(())
    }

    /// Retrieves the stored secret.
    pub async fn secret(&self) -> Result<Secret> {
        let secret = match self {
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                match file_item {
                    file::Item::Unlocked(unlocked) => unlocked.secret(),
                    file::Item::Locked(_) => return Err(crate::file::Error::Locked.into()),
                }
            }
            Self::DBus(item) => item.secret().await?,
        };
        Ok(secret)
    }

    /// Whether the item is locked or not
    pub async fn is_locked(&self) -> Result<bool> {
        match self {
            Self::DBus(item) => item.is_locked().await.map_err(From::from),
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                Ok(file_item.is_locked())
            }
        }
    }

    /// Lock the item
    pub async fn lock(&self) -> Result<()> {
        match self {
            Self::DBus(item) => item.lock(None).await?,
            Self::File(item, keyring) => {
                let mut item_guard = item.write().await;
                let item_value = item_guard.take();
                if let Some(file::Item::Unlocked(unlocked)) = item_value {
                    let kg = keyring.read().await;
                    match kg.as_ref() {
                        Some(file::Keyring::Unlocked(backend)) => {
                            let locked = backend
                                .lock_item(unlocked)
                                .await
                                .map_err(crate::Error::File)?;
                            *item_guard = Some(file::Item::Locked(locked));
                        }
                        Some(file::Keyring::Locked(_)) => {
                            *item_guard = Some(file::Item::Unlocked(unlocked));
                            return Err(crate::file::Error::Locked.into());
                        }
                        None => unreachable!("A keyring must exist"),
                    }
                } else {
                    *item_guard = item_value;
                }
            }
        }
        Ok(())
    }

    /// Unlock the item
    pub async fn unlock(&self) -> Result<()> {
        match self {
            Self::DBus(item) => item.unlock(None).await?,
            Self::File(item, keyring) => {
                let mut item_guard = item.write().await;
                let item_value = item_guard.take();
                if let Some(file::Item::Locked(locked)) = item_value {
                    let kg = keyring.read().await;
                    match kg.as_ref() {
                        Some(file::Keyring::Unlocked(backend)) => {
                            let unlocked = backend
                                .unlock_item(locked)
                                .await
                                .map_err(crate::Error::File)?;
                            *item_guard = Some(file::Item::Unlocked(unlocked));
                        }
                        Some(file::Keyring::Locked(_)) => {
                            *item_guard = Some(file::Item::Locked(locked));
                            return Err(crate::file::Error::Locked.into());
                        }
                        None => unreachable!("A keyring must exist"),
                    }
                } else {
                    *item_guard = item_value;
                }
            }
        }
        Ok(())
    }

    /// Delete the item.
    pub async fn delete(&self) -> Result<()> {
        match self {
            Self::File(item, keyring) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");

                match file_item {
                    file::Item::Unlocked(unlocked) => {
                        let kg = keyring.read().await;
                        match kg.as_ref() {
                            Some(file::Keyring::Unlocked(backend)) => {
                                backend
                                    .delete(&unlocked.attributes())
                                    .await
                                    .map_err(crate::Error::File)?;
                            }
                            Some(file::Keyring::Locked(_)) => {
                                return Err(crate::file::Error::Locked.into());
                            }
                            None => unreachable!("A keyring must exist"),
                        }
                    }
                    file::Item::Locked(_) => {
                        return Err(crate::file::Error::Locked.into());
                    }
                }
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
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                match file_item {
                    file::Item::Unlocked(unlocked) => Ok(unlocked.created()),
                    file::Item::Locked(_) => Err(crate::file::Error::Locked.into()),
                }
            }
        }
    }

    /// The UNIX time when the item was modified.
    pub async fn modified(&self) -> Result<Duration> {
        match self {
            Self::DBus(item) => Ok(item.modified().await?),
            Self::File(item, _) => {
                let item_guard = item.read().await;
                let file_item = item_guard.as_ref().expect("Item must exist");
                match file_item {
                    file::Item::Unlocked(unlocked) => Ok(unlocked.modified()),
                    file::Item::Locked(_) => Err(crate::file::Error::Locked.into()),
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use tempfile::tempdir;

    use super::*;

    async fn all_backends(temp_dir: tempfile::TempDir) -> Vec<Keyring> {
        let mut backends = Vec::new();

        let keyring_path = temp_dir.path().join("test.keyring");
        let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());
        let unlocked = file::UnlockedKeyring::load(&keyring_path, secret)
            .await
            .unwrap();
        let keyring = Keyring::File(Arc::new(RwLock::new(Some(file::Keyring::Unlocked(
            unlocked,
        )))));

        backends.push(keyring);

        let service = dbus::Service::new().await.unwrap();
        if let Ok(collection) = service.default_collection().await {
            backends.push(Keyring::DBus(collection));
        }

        backends
    }

    #[tokio::test]
    async fn create_and_retrieve_items() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Item 1",
                    &[
                        ("test-name", "create_and_retrieve_items"),
                        ("user", "alice"),
                    ],
                    "secret1",
                    false,
                )
                .await
                .unwrap();
            keyring
                .create_item(
                    "Item 2",
                    &[("test-name", "create_and_retrieve_items"), ("user", "bob")],
                    "secret2",
                    false,
                )
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "create_and_retrieve_items")])
                .await
                .unwrap();
            assert_eq!(items.len(), 2);

            let alice_items = keyring
                .search_items(&[
                    ("test-name", "create_and_retrieve_items"),
                    ("user", "alice"),
                ])
                .await
                .unwrap();
            assert_eq!(alice_items.len(), 1);
            assert_eq!(alice_items[0].label().await.unwrap(), "Item 1");

            keyring
                .delete(&[("test-name", "create_and_retrieve_items")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn delete_items() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Item 1",
                    &[("test-name", "delete_items"), ("app", "test")],
                    "secret1",
                    false,
                )
                .await
                .unwrap();
            keyring
                .create_item(
                    "Item 2",
                    &[("test-name", "delete_items"), ("app", "other")],
                    "secret2",
                    false,
                )
                .await
                .unwrap();

            keyring
                .delete(&[("test-name", "delete_items"), ("app", "test")])
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "delete_items")])
                .await
                .unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].label().await.unwrap(), "Item 2");

            keyring
                .delete(&[("test-name", "delete_items")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_update_label() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Original Label",
                    &[("test-name", "item_update_label")],
                    "secret",
                    false,
                )
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_update_label")])
                .await
                .unwrap();
            let item = &items[0];

            assert_eq!(item.label().await.unwrap(), "Original Label");

            item.set_label("New Label").await.unwrap();
            assert_eq!(item.label().await.unwrap(), "New Label");

            let items = keyring
                .search_items(&[("test-name", "item_update_label")])
                .await
                .unwrap();
            assert_eq!(items[0].label().await.unwrap(), "New Label");

            keyring
                .delete(&[("test-name", "item_update_label")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_update_attributes() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Test",
                    &[("test-name", "item_update_attributes"), ("version", "1.0")],
                    "secret",
                    false,
                )
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_update_attributes")])
                .await
                .unwrap();
            let item = &items[0];

            item.set_attributes(&[("test-name", "item_update_attributes"), ("version", "2.0")])
                .await
                .unwrap();

            let attrs = item.attributes().await.unwrap();
            assert_eq!(attrs.get("version").unwrap(), "2.0");

            // Test edge case: set_attributes when item doesn't exist in keyring
            if idx == 0 {
                keyring
                    .delete(&[("test-name", "item_update_attributes")])
                    .await
                    .unwrap();

                item.set_attributes(&[("test-name", "item_update_attributes"), ("version", "3.0")])
                    .await
                    .unwrap();

                let new_items = keyring
                    .search_items(&[("test-name", "item_update_attributes")])
                    .await
                    .unwrap();
                assert_eq!(new_items.len(), 1);
            }

            keyring
                .delete(&[("test-name", "item_update_attributes")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_update_secret() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Test",
                    &[("test-name", "item_update_secret")],
                    "old_secret",
                    false,
                )
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_update_secret")])
                .await
                .unwrap();
            let item = &items[0];

            assert_eq!(item.secret().await.unwrap(), Secret::text("old_secret"));

            item.set_secret("new_secret").await.unwrap();
            assert_eq!(item.secret().await.unwrap(), Secret::text("new_secret"));

            keyring
                .delete(&[("test-name", "item_update_secret")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_delete() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item(
                    "Item 1",
                    &[("test-name", "item_delete"), ("id", "1")],
                    "secret1",
                    false,
                )
                .await
                .unwrap();
            keyring
                .create_item(
                    "Item 2",
                    &[("test-name", "item_delete"), ("id", "2")],
                    "secret2",
                    false,
                )
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_delete")])
                .await
                .unwrap();
            assert_eq!(items.len(), 2);

            items[0].delete().await.unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_delete")])
                .await
                .unwrap();
            assert_eq!(items.len(), 1);

            keyring
                .delete(&[("test-name", "item_delete")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_replace() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item("Item 1", &[("test-name", "item_replace")], "secret1", false)
                .await
                .unwrap();

            keyring
                .create_item("Item 2", &[("test-name", "item_replace")], "secret2", true)
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_replace")])
                .await
                .unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].label().await.unwrap(), "Item 2");
            assert_eq!(items[0].secret().await.unwrap(), Secret::text("secret2"));

            // Cleanup
            keyring
                .delete(&[("test-name", "item_replace")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_timestamps() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item("Test", &[("test-name", "item_timestamps")], "secret", false)
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_timestamps")])
                .await
                .unwrap();
            let item = &items[0];

            let created = item.created().await.unwrap();
            let modified = item.modified().await.unwrap();

            assert!(created.as_secs() > 0);
            assert!(modified.as_secs() > 0);

            assert!(modified >= created);

            // Cleanup
            keyring
                .delete(&[("test-name", "item_timestamps")])
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn item_is_locked() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;

        for (idx, keyring) in backends.iter().enumerate() {
            println!("Running test on backend {}", idx);

            keyring
                .create_item("Test", &[("test-name", "item_is_locked")], "secret", false)
                .await
                .unwrap();

            let items = keyring
                .search_items(&[("test-name", "item_is_locked")])
                .await
                .unwrap();
            let item = &items[0];

            assert!(!item.is_locked().await.unwrap());

            let all_items = keyring.items().await.unwrap();
            assert!(!all_items.is_empty());

            keyring
                .delete(&[("test-name", "item_is_locked")])
                .await
                .unwrap();
        }
    }

    // File-backend specific tests, as the DBus one require prompting
    #[tokio::test]
    async fn file_keyring_lock_unlock() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;
        let keyring = &backends[0];

        assert!(!keyring.is_locked().await.unwrap());

        keyring.lock().await.unwrap();
        assert!(keyring.is_locked().await.unwrap());

        // Test edge case: locking an already locked keyring
        keyring.lock().await.unwrap();
        assert!(keyring.is_locked().await.unwrap());

        let result = keyring
            .create_item("test", &[("app", "test")], "secret", false)
            .await;
        assert!(matches!(
            result,
            Err(crate::Error::File(file::Error::Locked))
        ));

        if let Keyring::File(kg) = &keyring {
            let mut kg_guard = kg.write().await;
            if let Some(file::Keyring::Locked(locked)) = kg_guard.take() {
                let secret = Secret::from([1, 2].into_iter().cycle().take(64).collect::<Vec<_>>());

                let unlocked = unsafe { locked.unlock_unchecked(secret).await.unwrap() };
                *kg_guard = Some(file::Keyring::Unlocked(unlocked));
            }
        }

        assert!(!keyring.is_locked().await.unwrap());
    }

    #[tokio::test]
    async fn file_item_lock_unlock() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;
        let keyring = &backends[0];

        keyring
            .create_item("Test Item", &[("app", "test")], "secret", false)
            .await
            .unwrap();

        let items = keyring.items().await.unwrap();
        let item = &items[0];

        assert!(!item.is_locked().await.unwrap());
        assert_eq!(item.secret().await.unwrap(), Secret::text("secret"));

        // Test edge case: unlocking an already unlocked item
        item.unlock().await.unwrap();
        assert!(!item.is_locked().await.unwrap());

        item.lock().await.unwrap();
        assert!(item.is_locked().await.unwrap());

        // Test edge case: locking an already locked item
        item.lock().await.unwrap();
        assert!(item.is_locked().await.unwrap());

        let result = item.secret().await;
        assert!(matches!(
            result,
            Err(crate::Error::File(file::Error::Locked))
        ));

        // Unlock the item
        item.unlock().await.unwrap();
        assert!(!item.is_locked().await.unwrap());
        assert_eq!(item.secret().await.unwrap(), Secret::text("secret"));
    }

    #[tokio::test]
    async fn file_locked_item_operations_fail() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;
        let keyring = &backends[0];

        keyring
            .create_item("Test", &[("app", "test")], "secret", false)
            .await
            .unwrap();

        let items = keyring.items().await.unwrap();
        let item = &items[0];

        item.lock().await.unwrap();

        assert!(matches!(
            item.label().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.attributes().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.secret().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.set_label("new").await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.set_attributes(&[("app", "test")]).await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.set_secret("new").await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.delete().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.created().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.modified().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
    }

    #[tokio::test]
    async fn file_locked_keyring_operations_fail() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;
        let keyring = &backends[0];

        keyring
            .create_item("Test", &[("app", "test")], "secret", false)
            .await
            .unwrap();

        let items = keyring.items().await.unwrap();
        let item = &items[0];

        keyring.lock().await.unwrap();

        assert!(matches!(
            keyring
                .create_item("test", &[("app", "test")], "secret", false)
                .await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            keyring.items().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            keyring.search_items(&[("app", "test")]).await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            keyring.delete(&[("app", "test")]).await,
            Err(crate::Error::File(file::Error::Locked))
        ));

        assert!(matches!(
            item.set_label("new label").await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.set_attributes(&[("app", "new")]).await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.set_secret("new secret").await,
            Err(crate::Error::File(file::Error::Locked))
        ));
        assert!(matches!(
            item.delete().await,
            Err(crate::Error::File(file::Error::Locked))
        ));
    }

    #[tokio::test]
    async fn file_item_lock_with_locked_keyring_fails() {
        let temp_dir = tempdir().unwrap();
        let backends = all_backends(temp_dir).await;
        let keyring = &backends[0];

        keyring
            .create_item("Test", &[("app", "test")], "secret", false)
            .await
            .unwrap();

        let items = keyring.items().await.unwrap();
        let item = &items[0];

        keyring.lock().await.unwrap();

        let result = item.lock().await;
        assert!(matches!(
            result,
            Err(crate::Error::File(file::Error::Locked))
        ));
    }
}
