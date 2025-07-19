use std::fmt;

use serde::Serialize;
use zbus::zvariant::{ObjectPath, Type};

use super::DESTINATION;
use crate::dbus::{Error, ServiceError};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Session")]
pub struct Session<'a>(zbus::Proxy<'a>);

impl zbus::proxy::Defaults for Session<'_> {
    const INTERFACE: &'static Option<zbus::names::InterfaceName<'static>> = &Some(
        zbus::names::InterfaceName::from_static_str_unchecked("org.freedesktop.Secret.Session"),
    );
    const DESTINATION: &'static Option<zbus::names::BusName<'static>> = &Some(DESTINATION);
    const PATH: &'static Option<ObjectPath<'static>> = &None;
}

impl<'a> From<zbus::Proxy<'a>> for Session<'a> {
    fn from(value: zbus::Proxy<'a>) -> Self {
        Self(value)
    }
}

impl<'a> Session<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Session<'a>, Error>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        zbus::proxy::Builder::new(connection)
            .path(object_path)?
            .build()
            .await
            .map_err(From::from)
    }

    pub fn inner(&self) -> &zbus::Proxy<'_> {
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

impl Serialize for Session<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Session")
            .field(&self.inner().path().as_str())
            .finish()
    }
}
