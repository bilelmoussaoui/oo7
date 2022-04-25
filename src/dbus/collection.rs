use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::lock::Mutex;

use crate::{Algorithm, Error, Result};

use super::{api, Item};

pub struct Collection<'a> {
    inner: Arc<api::Collection<'a>>,
    service: Arc<api::Service<'a>>,
    session: Arc<api::Session<'a>>,
    algorithm: Algorithm,
    /// Defines whether the Collection has been deleted or not
    available: Mutex<bool>,
}

impl<'a> Collection<'a> {
    pub(crate) fn new(
        service: Arc<api::Service<'a>>,
        session: Arc<api::Session<'a>>,
        algorithm: Algorithm,
        collection: api::Collection<'a>,
    ) -> Collection<'a> {
        Self {
            inner: Arc::new(collection),
            session,
            service,
            algorithm,
            available: Mutex::new(true),
        }
    }

    pub(crate) async fn is_available(&self) -> bool {
        *self.available.lock().await
    }

    pub async fn items(&self) -> Result<Vec<Item<'_>>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            Ok(self
                .inner
                .items()
                .await?
                .into_iter()
                .map(|item| {
                    Item::new(
                        Arc::clone(&self.service),
                        Arc::clone(&self.session),
                        self.algorithm,
                        item,
                    )
                })
                .collect::<Vec<_>>())
        }
    }

    pub async fn label(&self) -> Result<String> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.label().await
        }
    }

    pub async fn set_label(&self, label: &str) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.set_label(label).await
        }
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.is_locked().await
        }
    }

    pub async fn created(&self) -> Result<Duration> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.created().await
        }
    }

    pub async fn modified(&self) -> Result<Duration> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.modified().await
        }
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let items = self.inner.search_items(attributes).await?;
            Ok(items
                .into_iter()
                .map(|item| {
                    Item::new(
                        Arc::clone(&self.service),
                        Arc::clone(&self.session),
                        self.algorithm,
                        item,
                    )
                })
                .collect::<Vec<_>>())
        }
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Item<'_>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = api::Secret::new(
                self.algorithm,
                Arc::clone(&self.session),
                secret,
                content_type,
            );

            let item = self
                .inner
                .create_item(label, attributes, &secret, replace)
                .await?;

            Ok(Item::new(
                Arc::clone(&self.service),
                Arc::clone(&self.session),
                self.algorithm,
                item,
            ))
        }
    }

    pub async fn unlock(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.lock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }

    pub async fn lock(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.service.lock(&[self.inner.inner().path()]).await?;
            Ok(())
        }
    }

    pub async fn delete(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.inner.delete().await?;
            *self.available.lock().await = false;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dbus::Service;

    #[tokio::test]
    async fn create_plain_item() {
        let service = Service::new(Algorithm::Plain).await.unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("type", "plain-type-test");
        let secret = "a password".as_bytes();

        let collection = service.default_collection().await.unwrap().unwrap();
        let n_items = collection.items().await.unwrap().len();
        let n_search_items = collection
            .search_items(attributes.clone())
            .await
            .unwrap()
            .len();

        let item = collection
            .create_item("A secret", attributes.clone(), secret, true, "text/plain")
            .await
            .unwrap();

        assert_eq!(item.secret().await.unwrap(), secret);
        assert_eq!(item.attributes().await.unwrap()["type"], "plain-type-test");

        assert_eq!(collection.items().await.unwrap().len(), n_items + 1);
        assert_eq!(
            collection
                .search_items(attributes.clone())
                .await
                .unwrap()
                .len(),
            n_search_items + 1
        );

        item.delete().await.unwrap();

        assert_eq!(collection.items().await.unwrap().len(), n_items);
        assert_eq!(
            collection
                .search_items(attributes.clone())
                .await
                .unwrap()
                .len(),
            n_search_items
        );
    }
}
