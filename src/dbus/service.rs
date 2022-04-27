use std::sync::Arc;

use super::{api, Algorithm, Collection, Error, DEFAULT_COLLECTION};
use crate::Key;

/// The entry point of communicating with a [`org.freedesktop.Secrets`](https://specifications.freedesktop.org/secret-service/latest/index.html) implementation.
///
/// It will automatically create a session for you and allow you to retrieve collections or create new ones.
///
/// Certain actions requires on the secret service implementation requires a user prompt to complete
/// like creating a collection, locking or unlocking a collection. The library handles that automatically for you.
///
/// ```ignore
/// let service = Service::new(Algorithm::Plain).await?;
/// let collection = service.default_collection().await?;
///
/// // Do something with the collection
/// ```
#[derive(Debug)]
pub struct Service<'a> {
    inner: Arc<api::Service<'a>>,
    aes_key: Option<Arc<Key>>,
    session: Arc<api::Session<'a>>,
    algorithm: Algorithm,
}

impl<'a> Service<'a> {
    /// Create a new instance of the Service.
    pub async fn new(algorithm: Algorithm) -> Result<Service<'a>, Error> {
        let cnx = zbus::Connection::session().await?;
        let service = Arc::new(api::Service::new(&cnx).await?);

        let (aes_key, session) = match algorithm {
            Algorithm::Plain => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Starting an unecrypted secret service session");
                let (_service_key, session) = service.open_session(None).await?;
                (None, session)
            }
            Algorithm::Encrypted => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Starting an encrypted secret service session");
                let private_key = Key::generate_private_key();
                let public_key = Key::generate_public_key(&private_key);
                let (service_key, session) = service.open_session(Some(&public_key)).await?;
                let aes_key = service_key
                    .map(|service_key| Arc::new(Key::generate_aes_key(&private_key, &service_key)));
                (aes_key, session)
            }
        };

        Ok(Self {
            aes_key,
            inner: service,
            session: Arc::new(session),
            algorithm,
        })
    }

    /// Retrieve the default collection.
    pub async fn default_collection(&self) -> Result<Collection<'a>, Error> {
        self.with_alias(DEFAULT_COLLECTION)
            .await?
            .ok_or_else(|| Error::NotFound(DEFAULT_COLLECTION.to_string()))
    }

    /// Find a collection with it alias.
    ///
    /// Applications should make use of [`Service::default_collection`] instead.
    pub async fn with_alias(&self, alias: &str) -> Result<Option<Collection<'a>>, Error> {
        Ok(self.inner.read_alias(alias).await?.map(|collection| {
            Collection::new(
                Arc::clone(&self.inner),
                Arc::clone(&self.session),
                self.algorithm,
                collection,
                self.aes_key.as_ref().map(Arc::clone),
            )
        }))
    }

    /// Get a list of all the available collections.
    pub async fn collections(&self) -> Result<Vec<Collection<'a>>, Error> {
        Ok(self
            .inner
            .collections()
            .await?
            .into_iter()
            .map(|collection| {
                Collection::new(
                    Arc::clone(&self.inner),
                    Arc::clone(&self.session),
                    self.algorithm,
                    collection,
                    self.aes_key.as_ref().map(Arc::clone),
                )
            })
            .collect::<Vec<_>>())
    }

    /// Create a new collection.
    ///
    /// The alias can only be equal to [`DEFAULT_COLLECTION`] otherwise it must not be set.
    pub async fn create_collection(
        &self,
        label: &str,
        alias: Option<&str>,
    ) -> Result<Collection<'a>, Error> {
        let aes_key = self.aes_key.as_ref().map(Arc::clone);
        self.inner
            .create_collection(label, alias)
            .await
            .map(|collection| {
                Collection::new(
                    Arc::clone(&self.inner),
                    Arc::clone(&self.session),
                    self.algorithm,
                    collection,
                    aes_key,
                )
            })
    }

    /// Find a collection with it label.
    pub async fn with_label(&self, label: &str) -> Result<Option<Collection<'a>>, Error> {
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
#[cfg(feature = "async-std")]
mod tests {
    #[cfg(feature = "local_tests")]
    use super::{Algorithm, Service};

    #[async_std::test]
    #[cfg(feature = "local_tests")]
    async fn create_collection() {
        let service = Service::new(Algorithm::Plain).await.unwrap();
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
