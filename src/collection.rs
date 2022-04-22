use std::{collections::HashMap, time::Duration};

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::{Item, Result, DESTINATION};

#[derive(Debug)]
pub struct Collection<'a>(zbus::Proxy<'a>);

impl<'a> Collection<'a> {
    pub async fn new(
        connection: &zbus::Connection,
        object_path: ObjectPath<'a>,
    ) -> Result<Collection<'a>> {
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

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        let msg = self
            .inner()
            .call_method("SearchItems", &(attributes))
            .await?;
        let item_paths = msg.body::<Vec<OwnedObjectPath>>()?;
        let mut items = Vec::with_capacity(item_paths.capacity());

        let connection = self.inner().connection();
        for path in item_paths {
            items.push(Item::new(connection, path).await?);
        }

        Ok(items)
    }
}
