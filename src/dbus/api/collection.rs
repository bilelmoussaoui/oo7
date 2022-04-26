use std::{collections::HashMap, fmt, time::Duration};

use futures::StreamExt;
use serde::Serialize;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Type};

use super::{Item, Prompt, Properties, Secret, Unlockable, DESTINATION};
use crate::dbus::Error;

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Collection")]
pub struct Collection<'a>(zbus::Proxy<'a>);

impl<'a> Collection<'a> {
    pub async fn new<P>(
        connection: &zbus::Connection,
        object_path: P,
    ) -> Result<Collection<'a>, Error>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Collection")?
            .path(object_path)?
            .cache_properties(zbus::CacheProperties::No)
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub(crate) async fn from_paths<P>(
        connection: &zbus::Connection,
        paths: Vec<P>,
    ) -> Result<Vec<Collection<'a>>, Error>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let mut collections = Vec::with_capacity(paths.capacity());
        for path in paths.into_iter() {
            collections.push(Self::new(connection, path).await?);
        }
        Ok(collections)
    }

    #[doc(alias = "ItemCreated")]
    pub async fn receive_item_created(&self) -> Result<Item<'a>, Error> {
        let mut stream = self.inner().receive_signal("ItemCreated").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Item::new(self.inner().connection(), object_path).await
    }

    #[doc(alias = "ItemDeleted")]
    pub async fn receive_item_deleted(&self) -> Result<Item<'a>, Error> {
        let mut stream = self.inner().receive_signal("ItemDeleted").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Item::new(self.inner().connection(), object_path).await
    }

    #[doc(alias = "ItemChanged")]
    pub async fn receive_item_changed(&self) -> Result<Item<'a>, Error> {
        let mut stream = self.inner().receive_signal("ItemChanged").await?;
        let message = stream.next().await.unwrap();
        let object_path = message.body::<OwnedObjectPath>()?;
        Item::new(self.inner().connection(), object_path).await
    }

    pub async fn items(&self) -> Result<Vec<Item<'a>>, Error> {
        let item_paths = self
            .inner()
            .get_property::<Vec<ObjectPath>>("Items")
            .await?;
        Item::from_paths(self.inner().connection(), item_paths).await
    }

    pub async fn label(&self) -> Result<String, Error> {
        self.inner().get_property("Label").await.map_err(From::from)
    }

    pub async fn set_label(&self, label: &str) -> Result<(), Error> {
        self.inner()
            .set_property("Label", label)
            .await
            .map_err::<zbus::fdo::Error, _>(From::from)?;
        Ok(())
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool, Error> {
        self.inner()
            .get_property("Locked")
            .await
            .map_err(From::from)
    }

    pub async fn created(&self) -> Result<Duration, Error> {
        let time = self.inner().get_property::<u64>("Created").await?;
        Ok(Duration::from_secs(time))
    }

    pub async fn modified(&self) -> Result<Duration, Error> {
        let time = self.inner().get_property::<u64>("Modified").await?;
        Ok(Duration::from_secs(time))
    }

    pub async fn delete(&self) -> Result<(), Error> {
        let prompt_path = self
            .inner()
            .call_method("Delete", &())
            .await?
            .body::<zbus::zvariant::OwnedObjectPath>()?;
        if let Some(prompt) = Prompt::new(self.inner().connection(), prompt_path).await? {
            let _ = prompt.receive_completed().await?;
        }
        Ok(())
    }

    #[doc(alias = "SearchItems")]
    pub async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Item<'a>>, Error> {
        let msg = self
            .inner()
            .call_method("SearchItems", &(attributes))
            .await?;

        let item_paths = msg.body::<Vec<OwnedObjectPath>>()?;
        Item::from_paths(self.inner().connection(), item_paths).await
    }

    #[doc(alias = "CreateItem")]
    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &Secret<'_>,
        replace: bool,
    ) -> Result<Item<'_>, Error> {
        let properties = Properties::for_item(label, attributes);
        let (item_path, prompt_path) = self
            .inner()
            .call_method("CreateItem", &(properties, secret, replace))
            .await?
            .body::<(OwnedObjectPath, OwnedObjectPath)>()?;
        let cnx = self.inner().connection();
        let item_path = if let Some(prompt) = Prompt::new(cnx, prompt_path).await? {
            let response = prompt.receive_completed().await?;
            OwnedObjectPath::try_from(response).map_err::<zbus::zvariant::Error, _>(From::from)?
        } else {
            item_path
        };
        Item::new(self.inner().connection(), item_path).await
    }
}

impl<'a> Serialize for Collection<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl<'a> fmt::Debug for Collection<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Collection")
            .field(&self.inner().path().as_str())
            .finish()
    }
}

impl<'a> Unlockable for Collection<'a> {}
