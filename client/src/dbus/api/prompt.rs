use std::fmt;

use futures_util::StreamExt;
use serde::Serialize;
use zbus::{
    zvariant::{ObjectPath, OwnedValue, Type},
    ProxyDefault,
};

use super::DESTINATION;
use crate::dbus::{Error, ServiceError};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Prompt")]
pub struct Prompt<'a>(zbus::Proxy<'a>);

impl<'a> ProxyDefault for Prompt<'a> {
    const INTERFACE: Option<&'static str> = Some("org.freedesktop.Secret.Prompt");
    const DESTINATION: Option<&'static str> = Some(DESTINATION);
    const PATH: Option<&'static str> = None;
}

impl<'a> From<zbus::Proxy<'a>> for Prompt<'a> {
    fn from(value: zbus::Proxy<'a>) -> Self {
        Self(value)
    }
}

impl<'a> Prompt<'a> {
    pub async fn new<P>(
        connection: &zbus::Connection,
        object_path: P,
    ) -> Result<Option<Prompt<'a>>, Error>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let path = object_path.try_into().map_err(Into::into)?;
        if path != ObjectPath::default() {
            Ok(Some(
                zbus::ProxyBuilder::new(connection)
                    .path(path)?
                    .build()
                    .await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    pub async fn prompt(&self, window_id: &str) -> Result<(), Error> {
        self.inner()
            .call_method("Prompt", &(window_id))
            .await
            .map_err::<ServiceError, _>(From::from)?;
        Ok(())
    }

    #[allow(unused)]
    pub async fn dismiss(&self) -> Result<(), Error> {
        self.inner()
            .call_method("Dismiss", &())
            .await
            .map_err::<ServiceError, _>(From::from)?;
        Ok(())
    }

    pub async fn receive_completed(&self) -> Result<OwnedValue, Error> {
        let mut stream = self.inner().receive_signal("Completed").await?;
        // TODO: figure out how to come with a window-id without depending on ashpd for
        // it WindowIdentifier thingy
        let (value, _) = futures_util::try_join!(
            async {
                let message = stream.next().await.unwrap();
                let (dismissed, result) = message.body().deserialize::<(bool, OwnedValue)>()?;
                if dismissed {
                    Err(Error::Dismissed)
                } else {
                    Ok(result)
                }
            },
            self.prompt("")
        )?;
        Ok(value)
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

impl<'a> fmt::Debug for Prompt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Prompt")
            .field(&self.inner().path().as_str())
            .finish()
    }
}
