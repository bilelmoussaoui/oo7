use crate::{Result, DESTINATION};
use serde::Serialize;
use zbus::zvariant::ObjectPath;

#[derive(Debug)]
pub struct Session<'a>(zbus::Proxy<'a>);

impl<'a> Session<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Session<'a>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
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

impl<'a> Serialize for Session<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl<'a> zbus::zvariant::Type for Session<'a> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        ObjectPath::signature()
    }
}
