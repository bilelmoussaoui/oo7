use std::collections::HashMap;
use std::fmt;

use futures::StreamExt;
use zbus::zvariant::{Array, ObjectPath, OwnedObjectPath, OwnedValue, Type};

use super::{
    secret::SecretInner, Collection, Item, Prompt, Properties, Secret, Session, Unlockable,
    DESTINATION, PATH,
};
use crate::{dbus::Algorithm, Result};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.secrets")]
pub struct Service<'a>(zbus::Proxy<'a>);

impl<'a> Service<'a> {
    pub async fn new(connection: &zbus::Connection) -> Result<Service<'a>> {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .path(PATH)?
            .destination(DESTINATION)?
            .interface("org.freedesktop.Secret.Service")?
            .cache_properties(zbus::CacheProperties::No)
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    #[doc(alias = "CollectionCreated")]
    pub async fn receive_collection_created(&self) -> Result<Collection<'a>> {
        let mut stream = self.inner().receive_signal("CollectionCreated").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Collection::new(self.inner().connection(), object_path).await
    }

    #[doc(alias = "CollectionDeleted")]
    pub async fn receive_collection_deleted(&self) -> Result<Collection<'a>> {
        let mut stream = self.inner().receive_signal("CollectionDeleted").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Collection::new(self.inner().connection(), object_path).await
    }

    #[doc(alias = "CollectionChanged")]
    pub async fn receive_collection_changed(&self) -> Result<Collection<'a>> {
        let mut stream = self.inner().receive_signal("CollectionChanged").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Collection::new(self.inner().connection(), object_path).await
    }

    pub async fn collections(&self) -> Result<Vec<Collection<'a>>> {
        let collections_paths = self
            .inner()
            .get_property::<Vec<ObjectPath>>("Collections")
            .await?;
        Collection::from_paths(self.inner().connection(), collections_paths).await
    }

    #[doc(alias = "OpenSession")]
    pub async fn open_session(
        &self,
        algorithm: &Algorithm,
    ) -> Result<(Option<Vec<u8>>, Session<'a>)> {
        let client_key = algorithm.client_key();
        let (service_key, session_path) = self
            .inner()
            .call_method("OpenSession", &(&algorithm, client_key))
            .await?
            .body::<(OwnedValue, OwnedObjectPath)>()?;
        let session = Session::new(self.inner().connection(), session_path).await?;

        let key = if algorithm == &Algorithm::Plain {
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

    #[doc(alias = "CreateCollection")]
    pub async fn create_collection(
        &self,
        label: &str,
        alias: Option<&str>,
    ) -> Result<Collection<'a>> {
        let properties = Properties::for_collection(label);
        let (collection_path, prompt_path) = self
            .inner()
            .call_method("CreateCollection", &(properties, alias.unwrap_or_default()))
            .await?
            .body::<(OwnedObjectPath, OwnedObjectPath)>()?;

        let collection_path = if let Some(prompt) =
            Prompt::new(self.inner().connection(), prompt_path).await?
        {
            let response = prompt.receive_completed().await?;
            OwnedObjectPath::try_from(response).map_err::<zbus::zvariant::Error, _>(From::from)?
        } else {
            collection_path
        };
        Collection::new(self.inner().connection(), collection_path).await
    }

    #[doc(alias = "SearchItems")]
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

    pub async fn unlock(&self, items: &[impl Unlockable]) -> Result<Vec<OwnedObjectPath>> {
        let (mut unlocked_item_paths, prompt_path) = self
            .inner()
            .call_method("Unlock", &(items))
            .await?
            .body::<(Vec<OwnedObjectPath>, OwnedObjectPath)>()?;
        let cnx = self.inner().connection();

        if let Some(prompt) = Prompt::new(cnx, prompt_path).await? {
            let response = prompt.receive_completed().await?;
            let locked_paths = Vec::<OwnedObjectPath>::try_from(response)
                .map_err::<zbus::zvariant::Error, _>(From::from)?;
            unlocked_item_paths.extend(locked_paths);
        };
        Ok(unlocked_item_paths)
    }

    pub async fn lock(&self, items: &[impl Unlockable]) -> Result<Vec<OwnedObjectPath>> {
        let (mut locked_item_paths, prompt_path) = self
            .inner()
            .call_method("Lock", &(items))
            .await?
            .body::<(Vec<OwnedObjectPath>, OwnedObjectPath)>()?;
        let cnx = self.inner().connection();

        if let Some(prompt) = Prompt::new(cnx, prompt_path).await? {
            let response = prompt.receive_completed().await?;
            let locked_paths = Vec::<OwnedObjectPath>::try_from(response)
                .map_err::<zbus::zvariant::Error, _>(From::from)?;
            locked_item_paths.extend(locked_paths);
        };

        Ok(locked_item_paths)
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

    #[doc(alias = "ReadAlias")]
    pub async fn read_alias(&self, name: &str) -> Result<Option<Collection<'a>>> {
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

    #[doc(alias = "SetAlias")]
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
