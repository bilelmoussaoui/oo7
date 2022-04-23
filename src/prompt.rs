use crate::{Result, DESTINATION};
use zbus::zvariant::ObjectPath;

#[derive(Debug)]
pub struct Prompt<'a>(zbus::Proxy<'a>);

impl<'a> Prompt<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Prompt<'a>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Prompt")?
            .path(object_path)?
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub async fn prompt(&self, window_id: &str) -> Result<()> {
        self.inner().call_method("Prompt", &(window_id)).await?;
        Ok(())
    }

    pub async fn dismiss(&self) -> Result<()> {
        self.inner().call_method("Dismiss", &()).await?;
        Ok(())
    }
}
