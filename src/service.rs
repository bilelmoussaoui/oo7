use zbus::zvariant::ObjectPath;

use crate::{Collection, Result, DESTINATION, PATH};

#[doc(alias = "org.freedesktop.secrets")]
pub struct Service<'a>(zbus::Proxy<'a>);

impl<'a> Service<'a> {
    pub async fn new(connection: &zbus::Connection) -> Result<Service<'a>> {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .path(PATH)?
            .destination(DESTINATION)?
            .interface("org.freedesktop.Secret.Service")?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub async fn collections(&self) -> Result<Vec<Collection<'_>>> {
        let collections_paths = self
            .inner()
            .get_property::<Vec<ObjectPath>>("Collections")
            .await?;
        let mut collections = Vec::with_capacity(collections_paths.capacity());
        for path in collections_paths {
            let collection = Collection::new(self.inner().connection(), path).await?;
            collections.push(collection);
        }
        Ok(collections)
    }

    #[doc(alias = "OpenSession")]
    pub async fn open_session(&self, algorithm: &str, variant: &str) -> Result<()> {
        let output = self
            .inner()
            .call_method("OpenSession", &(algorithm, variant))
            .await?;
        println!("{:#?}", output.body::<zbus::zvariant::Value>());
        Ok(())
    }

    #[doc(alias = "LockService")]
    pub async fn lock_service(&self) -> Result<()> {
        self.inner().call_method("LockService", &()).await?;
        Ok(())
    }
}
