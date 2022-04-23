use std::{collections::HashMap, time::Duration};

use serde::Serialize;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Item, Prompt, Result, DESTINATION};

#[derive(Debug)]
pub struct Collection<'a>(zbus::Proxy<'a>);

impl<'a> Collection<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Collection<'a>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Collection")?
            .path(object_path)?
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }
    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub async fn items(&self) -> Result<Vec<Item<'_>>> {
        let item_paths = self
            .inner()
            .get_property::<Vec<ObjectPath>>("Items")
            .await?;
        let mut items = Vec::with_capacity(item_paths.capacity());
        let cnx = self.inner().connection();
        for path in item_paths {
            let item = Item::new(cnx, path).await?;
            items.push(item);
        }
        Ok(items)
    }

    pub async fn label(&self) -> Result<String> {
        self.inner().get_property("Label").await.map_err(From::from)
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool> {
        self.inner()
            .get_property("Locked")
            .await
            .map_err(From::from)
    }

    pub async fn created(&self) -> Result<Duration> {
        let time = self.inner().get_property::<u64>("Created").await?;
        Ok(Duration::from_secs(time))
    }

    pub async fn modified(&self) -> Result<Duration> {
        let time = self.inner().get_property::<u64>("Modified").await?;
        Ok(Duration::from_secs(time))
    }

    pub async fn delete(&self) -> Result<Option<Prompt<'_>>> {
        let prompt_path = self
            .inner()
            .call_method("Delete", &())
            .await?
            .body::<zbus::zvariant::OwnedObjectPath>()?;

        if prompt_path.as_str() != "/" {
            let prompt = Prompt::new(self.inner().connection(), prompt_path).await?;
            Ok(Some(prompt))
        } else {
            Ok(None)
        }
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        let msg = self
            .inner()
            .call_method("SearchItems", &(attributes))
            .await?;
        let item_paths = msg.body::<Vec<OwnedObjectPath>>()?;
        let mut items = Vec::with_capacity(item_paths.capacity());

        let cnx = self.inner().connection();
        for path in item_paths {
            items.push(Item::new(cnx, path).await?);
        }

        Ok(items)
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

impl<'a> zbus::zvariant::Type for Collection<'a> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        ObjectPath::signature()
    }
}
