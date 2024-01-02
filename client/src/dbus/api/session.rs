use std::fmt;

use serde::Serialize;
use zbus::zvariant::{ObjectPath, Type};

use super::DESTINATION;
use crate::dbus::{Error, ServiceError};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Session")]
pub struct Session<'a>(zbus::Proxy<'a>);

impl<'a> Session<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Session<'a>, Error>
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

    pub async fn close(&self) -> Result<(), Error> {
        self.inner()
            .call_method("Close", &())
            .await
            .map_err::<ServiceError, _>(From::from)?;
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

impl<'a> fmt::Debug for Session<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Session")
            .field(&self.inner().path().as_str())
            .finish()
    }
}
