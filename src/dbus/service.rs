use std::collections::HashMap;
use std::fmt;

use zbus::zvariant::{Array, ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::{secret::SecretInner, Collection, Item, Prompt, Secret, Session, DESTINATION, PATH};
use crate::{Algorithm, Result};

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
        Collection::from_paths(self.inner().connection(), collections_paths).await
    }

    #[doc(alias = "OpenSession")]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
    ) -> Result<(Option<Vec<u8>>, Session<'_>)> {
        let client_key = algorithm.session_input();
        let (service_key, session_path) = self
            .inner()
            .call_method("OpenSession", &(&algorithm, client_key))
            .await?
            .body::<(OwnedValue, OwnedObjectPath)>()?;
        let session = Session::new(self.inner().connection(), session_path).await?;

        let key = if algorithm == Algorithm::Plain {
            None
        } else {
            let mut res = vec![];
            for value in service_key.downcast_ref::<Array>().unwrap().get() {
                res.push(*value.downcast_ref::<u8>().unwrap());
            }
            Some(res)
        };

        Ok((key, session))
    }

    pub async fn create_collection(
        &self,
        properties: HashMap<&str, Value<'_>>,
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
                Prompt::new(self.inner().connection(), prompt_path).await?,
            ))
        }
    }

    pub async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<(Vec<Item<'_>>, Vec<Item<'_>>)> {
        let (unlocked_item_paths, locked_item_paths) = self
            .inner()
            .call_method("SearchItems", &(attributes))
            .await?
            .body::<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>()?;
        let cnx = self.inner().connection();

        let unlocked_items = Item::from_paths(cnx, unlocked_item_paths).await?;
        let locked_items = Item::from_paths(cnx, locked_item_paths).await?;

        Ok((unlocked_items, locked_items))
    }

    pub async fn unlock(&self, items: &[Item<'_>]) -> Result<(Vec<Item<'_>>, Option<Prompt<'_>>)> {
        let (unlocked_item_paths, prompt_path) = self
            .inner()
            .call_method("Unlock", &(items))
            .await?
            .body::<(Vec<OwnedObjectPath>, OwnedObjectPath)>()?;
        let cnx = self.inner().connection();

        let prompt = Prompt::new(cnx, prompt_path).await?;
        let unlocked_items = Item::from_paths(cnx, unlocked_item_paths).await?;
        Ok((unlocked_items, prompt))
    }

    pub async fn lock(&self, items: &[Item<'_>]) -> Result<(Vec<Item<'_>>, Option<Prompt<'_>>)> {
        let (locked_item_paths, prompt_path) = self
            .inner()
            .call_method("Lock", &(items))
            .await?
            .body::<(Vec<OwnedObjectPath>, OwnedObjectPath)>()?;
        let cnx = self.inner().connection();

        let prompt = Prompt::new(cnx, prompt_path).await?;
        let locked_items = Item::from_paths(cnx, locked_item_paths).await?;
        Ok((locked_items, prompt))
    }

    #[doc(alias = "GetSecrets")]
    pub async fn secrets(
        &self,
        items: &[Item<'_>],
        session: &Session<'_>,
    ) -> Result<HashMap<Item<'_>, Secret<'_>>> {
        let secrets = self
            .inner()
            .call_method("GetSecrets", &(items, session))
            .await?
            .body::<HashMap<OwnedObjectPath, SecretInner>>()?;

        let cnx = self.inner().connection();
        let mut output = HashMap::with_capacity(secrets.capacity());
        for (path, secret_inner) in secrets {
            output.insert(
                Item::new(cnx, path).await?,
                Secret::from_inner(cnx, secret_inner).await?,
            );
        }

        Ok(output)
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

impl<'a> fmt::Debug for Service<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Service")
            .field(&self.inner().path().as_str())
            .finish()
    }
}
