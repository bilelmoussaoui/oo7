use std::collections::HashMap;

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Collection, Prompt, Result, DESTINATION, PATH};

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
        let cnx = self.inner().connection();
        for path in collections_paths {
            let collection = Collection::new(cnx, path).await?;
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

    pub async fn create_collection(
        &self,
        properties: HashMap<&str, zbus::zvariant::Value<'_>>,
        alias: &str,
    ) -> Result<(Option<Collection<'_>>, Option<Prompt<'_>>)> {
        let (collection_path, prompt_path) = self
            .inner()
            .call_method("CreateCollection", &(properties, alias))
            .await?
            .body::<(OwnedObjectPath, OwnedObjectPath)>()?;

        // no prompt is needed in this case
        // TODO: investigate if we can make the whole Prompt part an internal thing
        if collection_path.as_str() != "/" {
            Ok((
                Some(Collection::new(self.inner().connection(), collection_path).await?),
                None,
            ))
        } else {
            // A prompt is needed
            Ok((
                None,
                Some(Prompt::new(self.inner().connection(), prompt_path).await?),
            ))
        }
    }

    pub async fn read_alias(&self, name: &str) -> Result<Option<Collection<'_>>> {
        let collection_path = self
            .inner()
            .call_method("ReadAlias", &(name))
            .await?
            .body::<zbus::zvariant::OwnedObjectPath>()?;

        if collection_path.as_str() != "/" {
            let collection = Collection::new(self.inner().connection(), collection_path).await?;
            Ok(Some(collection))
        } else {
            Ok(None)
        }
    }

    pub async fn set_alias(&self, name: &str, collection: &Collection<'_>) -> Result<()> {
        self.inner()
            .call_method("SetAlias", &(name, collection))
            .await?;
        Ok(())
    }
}
