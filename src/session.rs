use crate::{Result, DESTINATION};
use zbus::zvariant::OwnedObjectPath;

#[derive(Debug)]
pub struct Session<'a>(zbus::Proxy<'a>);

impl<'a> Session<'a> {
    pub async fn new(
        connection: &zbus::Connection,
        object_path: OwnedObjectPath,
    ) -> Result<Session<'a>> {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Session")?
            .path(object_path)?
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub async fn close(&self) -> Result<()> {
        self.inner().call_method("Close", &()).await?;
        Ok(())
    }
}
