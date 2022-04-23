use crate::{Result, DESTINATION};
use serde::Serialize;
use zbus::zvariant::ObjectPath;

#[derive(Debug)]
pub struct Prompt<'a>(zbus::Proxy<'a>);

impl<'a> Prompt<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Option<Prompt<'a>>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let path = object_path.try_into().map_err(Into::into)?;
        if path.as_str() != "/" {
            let inner = zbus::ProxyBuilder::new_bare(connection)
                .interface("org.freedesktop.Secret.Prompt")?
                .path(path)?
                .destination(DESTINATION)?
                .build()
                .await?;
            Ok(Some(Self(inner)))
        } else {
            Ok(None)
        }
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

impl<'a> Serialize for Prompt<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl<'a> zbus::zvariant::Type for Prompt<'a> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        ObjectPath::signature()
    }
}
