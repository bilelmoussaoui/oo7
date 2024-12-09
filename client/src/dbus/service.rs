use std::sync::Arc;

use ashpd::WindowIdentifier;
use futures_util::{Stream, StreamExt};
use zbus::zvariant::OwnedObjectPath;

use super::{api, Algorithm, Collection, Error};
use crate::Key;

/// The entry point of communicating with a [`org.freedesktop.Secrets`](https://specifications.freedesktop.org/secret-service-spec/latest/index.html) implementation.
///
/// It will automatically create a session for you and allow you to retrieve
/// collections or create new ones.
///
/// Certain actions requires on the Secret Service implementation requires a
/// user prompt to complete like creating a collection, locking or unlocking a
/// collection. The library handles that automatically for you.
///
/// ```no_run
/// use oo7::dbus::Service;
///
/// # async fn run() -> oo7::Result<()> {
/// let service = Service::new().await?;
/// let collection = service.default_collection().await?;
/// // Do something with the collection
///
/// #   Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct Service<'a> {
    inner: Arc<api::Service<'a>>,
    aes_key: Option<Arc<Key>>,
    session: Arc<api::Session<'a>>,
    algorithm: Algorithm,
}

impl<'a> Service<'a> {
    /// The default collection alias.
    ///
    /// In general, you are supposed to use [`Service::default_collection`].
    pub const DEFAULT_COLLECTION: &'static str = "default";

    /// A session collection.
    ///
    /// The collection is cleared when the user ends the session.
    pub const SESSION_COLLECTION: &'static str = "session";

    /// Create a new instance of the Service, an encrypted communication would
    /// be attempted first and would fall back to a plain one if that fails.
    pub async fn new() -> Result<Service<'a>, Error> {
        let service = match Self::encrypted().await {
            Ok(service) => Ok(service),
            Err(Error::Zbus(zbus::Error::MethodError(_, _, _))) => Self::plain().await,
            Err(e) => Err(e),
        }?;
        Ok(service)
    }

    /// Create a new instance of the Service with plain algorithm.
    pub async fn plain() -> Result<Service<'a>, Error> {
        Self::with_algorithm(Algorithm::Plain).await
    }

    /// Create a new instance of the Service with encrypted algorithm.
    pub async fn encrypted() -> Result<Service<'a>, Error> {
        Self::with_algorithm(Algorithm::Encrypted).await
    }

    /// Create a new instance of the Service.
    async fn with_algorithm(algorithm: Algorithm) -> Result<Service<'a>, Error> {
        let cnx = zbus::Connection::session().await?;
        let service = Arc::new(api::Service::new(&cnx).await?);

        let (aes_key, session) = match algorithm {
            Algorithm::Plain => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Starting an unencrypted Secret Service session");
                let (_service_key, session) = service.open_session(None).await?;
                (None, session)
            }
            Algorithm::Encrypted => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Starting an encrypted Secret Service session");
                let private_key = Key::generate_private_key()?;
                let public_key = Key::generate_public_key(&private_key)?;
                let (service_key, session) = service.open_session(Some(&public_key)).await?;
                let aes_key = service_key
                    .map(|service_key| Key::generate_aes_key(&private_key, &service_key))
                    .transpose()?
                    .map(Arc::new);

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

    /// Retrieve the default collection if any or create one.
    ///
    /// The created collection label is set to `Default`. If you want to
    /// translate the string, use [Self::with_alias_or_create] instead.
    pub async fn default_collection(&self) -> Result<Collection<'a>, Error> {
        // TODO: Figure how to make those labels translatable
        self.with_alias_or_create(Self::DEFAULT_COLLECTION, "Default", None)
            .await
    }

    /// Retrieve the session collection if any or create one.
    ///
    /// The created collection label is set to `Default`. If you want to
    /// translate the string, use [Self::with_alias_or_create] instead.
    pub async fn session_collection(&self) -> Result<Collection<'a>, Error> {
        // TODO: Figure how to make those labels translatable
        self.with_alias_or_create(Self::SESSION_COLLECTION, "Session", None)
            .await
    }

    pub async fn with_alias_or_create(
        &self,
        alias: &str,
        label: &str,
        window_id: Option<WindowIdentifier>,
    ) -> Result<Collection<'a>, Error> {
        match self.with_alias(alias).await {
            Ok(Some(collection)) => Ok(collection),
            Ok(None) => self.create_collection(label, alias, window_id).await,
            Err(err) => Err(err),
        }
    }

    /// Find a collection with it alias.
    ///
    /// Applications should make use of [`Service::default_collection`] instead.
    pub async fn with_alias(&self, alias: &str) -> Result<Option<Collection<'a>>, Error> {
        Ok(self
            .inner
            .read_alias(alias)
            .await?
            .map(|collection| self.new_collection(collection)))
    }

    /// Get a list of all the available collections.
    pub async fn collections(&self) -> Result<Vec<Collection<'a>>, Error> {
        Ok(self
            .inner
            .collections()
            .await?
            .into_iter()
            .map(|collection| self.new_collection(collection))
            .collect::<Vec<_>>())
    }

    /// Create a new collection.
    pub async fn create_collection(
        &self,
        label: &str,
        alias: &str,
        window_id: Option<WindowIdentifier>,
    ) -> Result<Collection<'a>, Error> {
        self.inner
            .create_collection(label, alias, window_id)
            .await
            .map(|collection| self.new_collection(collection))
    }

    /// Find a collection with it label.
    pub async fn with_label(&self, label: &str) -> Result<Option<Collection<'a>>, Error> {
        let collections = self.collections().await?;
        for collection in collections {
            if collection.label().await? == label {
                return Ok(Some(collection));
            }
        }
        Ok(None)
    }

    /// Stream yielding when new collections get created
    pub async fn receive_collection_created(
        &self,
    ) -> Result<impl Stream<Item = Collection<'a>> + '_, Error> {
        Ok(self
            .inner
            .receive_collection_created()
            .await?
            .map(|collection| self.new_collection(collection)))
    }

    /// Stream yielding when existing collections get changed
    pub async fn receive_collection_changed(
        &self,
    ) -> Result<impl Stream<Item = Collection<'a>> + '_, Error> {
        Ok(self
            .inner
            .receive_collection_changed()
            .await?
            .map(|collection| self.new_collection(collection)))
    }

    /// Stream yielding when existing collections get deleted
    pub async fn receive_collection_deleted(
        &self,
    ) -> Result<impl Stream<Item = OwnedObjectPath>, Error> {
        self.inner.receive_collection_deleted().await
    }

    // Get public `Collection` from `api::Collection`
    fn new_collection(&self, collection: api::Collection<'a>) -> Collection<'a> {
        Collection::new(
            Arc::clone(&self.inner),
            Arc::clone(&self.session),
            self.algorithm,
            collection,
            self.aes_key.clone(), // Cheap clone, it is an Arc,
        )
    }
}

#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "local_tests"))]
mod tests {
    use super::Service;

    #[tokio::test]
    async fn create_collection() {
        let service = Service::new().await.unwrap();
        let collection = service
            .create_collection("somelabel", "Some Label", None)
            .await
            .unwrap();

        let found_collection = service.with_label("somelabel").await.unwrap();
        assert!(found_collection.is_some());

        assert_eq!(
            found_collection.unwrap().label().await.unwrap(),
            collection.label().await.unwrap()
        );

        collection.delete(None).await.unwrap();

        let found_collection = service.with_label("somelabel").await.unwrap();
        assert!(found_collection.is_none());
    }
}
