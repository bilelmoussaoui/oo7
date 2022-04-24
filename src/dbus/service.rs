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

    pub async fn create_collection(&self, label: &str, alias: &str) -> Result<Collection<'a>> {
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
}
