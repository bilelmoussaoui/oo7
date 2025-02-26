use std::{collections::HashMap, fmt, hash::Hash, time::Duration};

use ashpd::WindowIdentifier;
use serde::Serialize;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Type};

use super::{DBusSecret, Prompt, Session, Unlockable, DESTINATION};
use crate::{
    dbus::{Error, ServiceError},
    AsAttributes,
};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Item")]
pub struct Item<'a>(zbus::Proxy<'a>);

impl zbus::proxy::Defaults for Item<'_> {
    const INTERFACE: &'static Option<zbus::names::InterfaceName<'static>> = &Some(
        zbus::names::InterfaceName::from_static_str_unchecked("org.freedesktop.Secret.Item"),
    );
    const DESTINATION: &'static Option<zbus::names::BusName<'static>> = &Some(DESTINATION);
    const PATH: &'static Option<ObjectPath<'static>> = &None;
}

impl<'a> From<zbus::Proxy<'a>> for Item<'a> {
    fn from(value: zbus::Proxy<'a>) -> Self {
        Self(value)
    }
}

impl<'a> Item<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Item<'a>, Error>
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

    pub(crate) async fn from_paths<P>(
        connection: &zbus::Connection,
        paths: Vec<P>,
    ) -> Result<Vec<Item<'a>>, Error>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let mut items = Vec::with_capacity(paths.capacity());
        for path in paths.into_iter() {
            items.push(Self::new(connection, path).await?);
        }
        Ok(items)
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool, Error> {
        self.inner()
            .get_property("Locked")
            .await
            .map_err(From::from)
    }

    pub async fn label(&self) -> Result<String, Error> {
        self.inner().get_property("Label").await.map_err(From::from)
    }

    pub async fn set_label(&self, label: &str) -> Result<(), Error> {
        self.inner().set_property("Label", label).await?;
        Ok(())
    }

    pub async fn created(&self) -> Result<Duration, Error> {
        let secs = self.inner().get_property::<u64>("Created").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn modified(&self) -> Result<Duration, Error> {
        let secs = self.inner().get_property::<u64>("Modified").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>, Error> {
        self.inner()
            .get_property("Attributes")
            .await
            .map_err(From::from)
    }

    pub async fn set_attributes(&self, attributes: &impl AsAttributes) -> Result<(), Error> {
        self.inner()
            .set_property("Attributes", attributes.as_attributes())
            .await?;
        Ok(())
    }

    pub async fn delete(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        let prompt_path = self
            .inner()
            .call_method("Delete", &())
            .await
            .map_err::<ServiceError, _>(From::from)?
            .body()
            .deserialize::<OwnedObjectPath>()?;
        if let Some(prompt) = Prompt::new(self.inner().connection(), prompt_path).await? {
            let _ = prompt.receive_completed(window_id).await?;
        }
        Ok(())
    }

    #[doc(alias = "GetSecret")]
    pub async fn secret(&self, session: &Session<'_>) -> Result<DBusSecret<'_>, Error> {
        let inner = self
            .inner()
            .call_method("GetSecret", &(session))
            .await
            .map_err::<ServiceError, _>(From::from)?
            .body()
            .deserialize::<super::secret::DBusSecretInner>()?;
        DBusSecret::from_inner(self.inner().connection(), inner).await
    }

    #[doc(alias = "SetSecret")]
    pub async fn set_secret(&self, secret: &DBusSecret<'_>) -> Result<(), Error> {
        self.inner()
            .call_method("SetSecret", &(secret,))
            .await
            .map_err::<ServiceError, _>(From::from)?;
        Ok(())
    }
}

impl Serialize for Item<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl PartialEq for Item<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.inner().path() == other.inner().path()
    }
}

impl Eq for Item<'_> {}

impl Hash for Item<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner().path().hash(state);
    }
}

impl fmt::Debug for Item<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Item")
            .field(&self.inner().path().as_str())
            .finish()
    }
}

impl Unlockable for Item<'_> {}
