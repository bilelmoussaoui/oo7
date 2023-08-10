use std::{collections::HashMap, fmt};

use futures_util::{Stream, StreamExt};
use zbus::zvariant::{self, ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};

use super::{
    secret::SecretInner, Collection, Item, Prompt, Properties, Secret, Session, Unlockable,
    DESTINATION, PATH,
};
use crate::{
    dbus::{Algorithm, Error},
    Key,
};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.secrets")]
pub struct Service<'a>(zbus::Proxy<'a>);

impl<'a> Service<'a> {
    pub async fn new(connection: &zbus::Connection) -> Result<Service<'a>, Error> {
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
    pub async fn receive_collection_created(
        &self,
    ) -> Result<impl Stream<Item = Collection<'_>>, Error> {
        let mut stream = self.inner().receive_signal("CollectionCreated").await?;
        let conn = self.inner().connection();
        Ok(stream.filter_map(move |message| async move {
            let path = message.body::<OwnedObjectPath>().ok()?;
            Collection::new(&conn.clone(), path).await.ok()
        }))
    }

    #[doc(alias = "CollectionDeleted")]
    pub async fn receive_collection_deleted(
        &self,
    ) -> Result<impl Stream<Item = Collection<'_>>, Error> {
        let mut stream = self.inner().receive_signal("CollectionDeleted").await?;
        let conn = self.inner().connection();
        Ok(stream.filter_map(move |message| async move {
            let path = message.body::<OwnedObjectPath>().ok()?;
            Collection::new(&conn.clone(), path).await.ok()
        }))
    }

    #[doc(alias = "CollectionChanged")]
    pub async fn receive_collection_changed(
        &self,
    ) -> Result<impl Stream<Item = Collection<'_>>, Error> {
        let mut stream = self.inner().receive_signal("CollectionChanged").await?;
        let conn = self.inner().connection();
        Ok(stream.filter_map(move |message| async move {
            let path = message.body::<OwnedObjectPath>().ok()?;
            Collection::new(&conn.clone(), path).await.ok()
        }))
    }

    pub async fn collections(&self) -> Result<Vec<Collection<'a>>, Error> {
        let collections_paths = self
            .inner()
            .get_property::<Vec<ObjectPath>>("Collections")
            .await?;
        Collection::from_paths(self.inner().connection(), collections_paths).await
    }

    #[doc(alias = "OpenSession")]
    pub async fn open_session(
        &self,
        client_public_key: Option<&Key>,
    ) -> Result<(Option<Key>, Session<'a>), Error> {
        let (algorithm, key): (_, Value<'_>) = match client_public_key {
            None => (Algorithm::Plain, zvariant::Str::default().into()),
            Some(key) => (Algorithm::Encrypted, key.into()),
        };
        let (service_key, session_path) = self
            .inner()
            .call_method("OpenSession", &(&algorithm, key))
            .await?
            .body::<(OwnedValue, OwnedObjectPath)>()?;
        let session = Session::new(self.inner().connection(), session_path).await?;

        let key = match algorithm {
            Algorithm::Plain => None,
            Algorithm::Encrypted => Some(Key::from(service_key)),
        };

        Ok((key, session))
    }

    #[doc(alias = "CreateCollection")]
    pub async fn create_collection(
        &self,
        label: &str,
        alias: Option<&str>,
    ) -> Result<Collection<'a>, Error> {
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
    ) -> Result<(Vec<Item<'a>>, Vec<Item<'a>>), Error> {
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

    pub async fn unlock(&self, items: &[impl Unlockable]) -> Result<Vec<OwnedObjectPath>, Error> {
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

    pub async fn lock(&self, items: &[impl Unlockable]) -> Result<Vec<OwnedObjectPath>, Error> {
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
    ) -> Result<HashMap<Item<'_>, Secret<'_>>, Error> {
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
    pub async fn read_alias(&self, name: &str) -> Result<Option<Collection<'a>>, Error> {
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
    pub async fn set_alias(&self, name: &str, collection: &Collection<'_>) -> Result<(), Error> {
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
