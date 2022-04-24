use std::fmt;

use super::DESTINATION;
use crate::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use zbus::{
    export::futures_util::StreamExt,
    zvariant::{ObjectPath, OwnedValue, Type},
};

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

    pub async fn receive_completed<'de, T>(&self) -> std::result::Result<(bool, T), Error>
    where
        T: TryFrom<OwnedValue> + DeserializeOwned + Type,
        Error: From<<T as TryFrom<OwnedValue>>::Error>,
    {
        let mut stream = self.inner().receive_signal("Completed").await?;
        let message = stream.next().await.unwrap();
        let (dismissed, result) = message.body::<(bool, OwnedValue)>()?;
        Ok((dismissed, T::try_from(result).map_err(From::from)?))
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

impl<'a> Type for Prompt<'a> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        ObjectPath::signature()
    }
}

impl<'a> fmt::Debug for Prompt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Prompt")
            .field(&self.inner().path().as_str())
            .finish()
    }
}
