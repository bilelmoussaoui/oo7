use std::sync::Arc;

use super::{api, Collection, DEFAULT_COLLECTION};
use crate::{Algorithm, Result};

pub struct Service<'a> {
    inner: Arc<api::Service<'a>>,
    #[allow(unused)]
    service_key: Option<Vec<u8>>,
    session: Arc<api::Session<'a>>,
    algorithm: Arc<Algorithm>,
}

impl<'a> Service<'a> {
    pub async fn new(algorithm: Algorithm) -> Result<Service<'a>> {
        let cnx = zbus::Connection::session().await?;
        let service = Arc::new(api::Service::new(&cnx).await?);
        let (service_key, session) = service.open_session(&algorithm).await?;

        Ok(Self {
            service_key,
            inner: service,
            session: Arc::new(session),
            algorithm: Arc::new(algorithm),
        })
    }

    pub async fn default_collection(&self) -> Result<Option<Collection<'a>>> {
        self.with_alias(DEFAULT_COLLECTION).await
    }

    /// Find a collection with it alias
    ///
    /// Applications should make use of [`Service::default_collection`] instead.
    pub async fn with_alias(&self, alias: &str) -> Result<Option<Collection<'a>>> {
        Ok(self.inner.read_alias(alias).await?.map(|collection| {
            Collection::new(
                Arc::clone(&self.inner),
                Arc::clone(&self.session),
                Arc::clone(&self.algorithm),
                collection,
            )
        }))
    }

    pub async fn collections(&self) -> Result<Vec<Collection<'a>>> {
        Ok(self
            .inner
            .collections()
            .await?
            .into_iter()
            .map(|collection| {
                Collection::new(
                    Arc::clone(&self.inner),
                    Arc::clone(&self.session),
                    Arc::clone(&self.algorithm),
                    collection,
                )
            })
            .collect::<Vec<_>>())
    }

    /// Create a new collection
    ///
    /// The alias can only be equal to [`DEFAULT_COLLECTION`] otherwise it must not be set.
    pub async fn create_collection(
        &self,
        label: &str,
        alias: Option<&str>,
    ) -> Result<Collection<'a>> {
        self.inner
            .create_collection(label, alias)
            .await
            .map(|collection| {
                Collection::new(
                    Arc::clone(&self.inner),
                    Arc::clone(&self.session),
                    Arc::clone(&self.algorithm),
                    collection,
                )
            })
    }

    /// Find a collection with it label
    pub async fn with_label(&self, label: &str) -> Result<Option<Collection<'a>>> {
        let collections = self.collections().await?;
        for collection in collections.into_iter() {
            if collection.label().await? == label {
                return Ok(Some(collection));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Service;

    #[tokio::test]
    async fn create_collection() {
        let service = Service::new(crate::Algorithm::Plain).await.unwrap();
        let collection = service.create_collection("somelabel", None).await.unwrap();

        let found_collection = service.with_label("somelabel").await.unwrap();
        assert!(found_collection.is_some());

        assert_eq!(
            found_collection.unwrap().label().await.unwrap(),
            collection.label().await.unwrap()
        );

        collection.delete().await.unwrap();

        let found_collection = service.with_label("somelabel").await.unwrap();
        assert!(found_collection.is_none());
    }
}
