use std::sync::Arc;

use super::{api, Collection, DEFAULT_COLLECTION};
use crate::{Algorithm, Result};

pub struct Service<'a> {
    service: Arc<api::Service<'a>>,
    #[allow(unused)]
    service_key: Option<Vec<u8>>,
    session: Arc<api::Session<'a>>,
    algorithm: Arc<Algorithm>,
}

impl<'a> Service<'a> {
    pub async fn new(algorithm: Algorithm) -> Result<Service<'a>> {
        let cnx = zbus::Connection::session().await?;
        let api_service = Arc::new(api::Service::new(&cnx).await?);
        let (service_key, session) = api_service.open_session(&algorithm).await?;

        Ok(Self {
            service_key,
            service: api_service,
            session: Arc::new(session),
            algorithm: Arc::new(algorithm),
        })
    }

    pub async fn default_collection(&self) -> Result<Option<Collection<'a>>> {
        Ok(self
            .service
            .read_alias(DEFAULT_COLLECTION)
            .await?
            .map(|collection| {
                Collection::new(self.session.clone(), self.algorithm.clone(), collection)
            }))
    }
}
