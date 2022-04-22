use std::{collections::HashMap, time::Duration};

use crate::{Result, DESTINATION};
use zbus::zvariant::OwnedObjectPath;

#[derive(Debug)]
pub struct Item<'a>(zbus::Proxy<'a>);

impl<'a> Item<'a> {
    pub async fn new(
        connection: &zbus::Connection,
        object_path: OwnedObjectPath,
    ) -> Result<Item<'a>> {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Item")?
            .path(object_path)?
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool> {
        self.inner()
            .get_property("Locked")
            .await
            .map_err(From::from)
    }

    pub async fn label(&self) -> Result<String> {
        self.inner().get_property("Label").await.map_err(From::from)
    }

    pub async fn created(&self) -> Result<Duration> {
        let secs = self.inner().get_property::<u64>("Created").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn modified(&self) -> Result<Duration> {
        let secs = self.inner().get_property::<u64>("Modified").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        self.inner()
            .get_property("Attributes")
            .await
            .map_err(From::from)
    }
}
