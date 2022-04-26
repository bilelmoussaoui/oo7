use std::collections::HashMap;

use async_std::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    dbus::{self, Algorithm, DEFAULT_COLLECTION},
    portal, Result,
};

/// A generic implementation of Keyring.
///
/// It would automatically use the file backend if the application is sandboxed
/// and otherwise falls back to the DBus service.
pub enum Keyring {
    File(portal::Keyring),
    DBus(dbus::Collection<'static>),
}

impl Keyring {
    pub async fn new() -> Result<Self> {
        let is_sandboxed = crate::is_sandboxed();
        if is_sandboxed {
            Ok(Self::File(portal::Keyring::load_default().await?))
        } else {
            let service = dbus::Service::new(Algorithm::Encrypted).await?;
            let collection = match service.default_collection().await {
                Ok(Some(c)) => Ok(c),
                Ok(None) => {
                    service
                        .create_collection("Login", Some(DEFAULT_COLLECTION))
                        .await
                }
                Err(e) => Err(e),
            }?;
            Ok(Self::DBus(collection))
        }
    }

    pub async fn items(&self) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_file).collect::<Vec<_>>()
            }
        };
        Ok(items)
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        password: &[u8],
        replace: bool,
    ) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                backend
                    .create_item(label, attributes, password, replace, "text/plain")
                    .await?;
            }
            Self::File(backend) => {
                backend
                    .create_item(label, attributes, password, replace)
                    .await?;
            }
        };
        Ok(())
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.search_items(attributes).await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.search_items(attributes).await?;
                items.into_iter().map(Item::for_file).collect::<Vec<_>>()
            }
        };
        Ok(items)
    }
}

pub enum Item {
    File(Mutex<crate::portal::Item>),
    DBus(dbus::Item<'static>),
}

impl Item {
    fn for_file(item: portal::Item) -> Self {
        Self::File(Mutex::new(item))
    }

    fn for_dbus(item: dbus::Item<'static>) -> Self {
        Self::DBus(item)
    }

    pub async fn label(&self) -> Result<String> {
        let label = match self {
            Self::File(item) => item.lock().await.label().to_owned(),
            Self::DBus(item) => item.label().await?,
        };
        Ok(label)
    }

    pub async fn set_label(&self, label: &str) -> Result<()> {
        match self {
            Self::File(item) => item.lock().await.set_label(label),
            Self::DBus(item) => item.set_label(label).await?,
        };
        Ok(())
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        let attributes = match self {
            Self::File(item) => item
                .lock()
                .await
                .attributes()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            Self::DBus(item) => item.attributes().await?,
        };
        Ok(attributes)
    }

    pub async fn set_password<P: AsRef<[u8]>>(&self, password: P) -> Result<()> {
        match self {
            Self::File(item) => {
                item.lock().await.set_password(password);
            }
            Self::DBus(item) => item.set_secret(password, "text/plain").await?,
        };
        Ok(())
    }

    pub async fn password(&self) -> Result<Zeroizing<Vec<u8>>> {
        let password = match self {
            Self::File(item) => item.lock().await.password(),
            Self::DBus(item) => item.secret().await?,
        };
        Ok(password)
    }
}
