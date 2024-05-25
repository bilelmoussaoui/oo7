use std::{collections::HashMap, fmt, hash::Hash, time::Duration};

use serde::Serialize;
use zbus::{
    zvariant::{ObjectPath, OwnedObjectPath, Type},
    ProxyDefault,
};

use super::{secret::SecretInner, Prompt, Secret, Session, Unlockable, DESTINATION};
use crate::{
    dbus::{Error, ServiceError},
    AsAttributes,
};

#[derive(Type)]
#[zvariant(signature = "o")]
#[doc(alias = "org.freedesktop.Secret.Item")]
pub struct Item<'a>(zbus::Proxy<'a>);

impl<'a> ProxyDefault for Item<'a> {
    const INTERFACE: Option<&'static str> = Some("org.freedesktop.Secret.Item");
    const DESTINATION: Option<&'static str> = Some(DESTINATION);
    const PATH: Option<&'static str> = None;
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
        zbus::ProxyBuilder::new(connection)
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
        self.inner()
            .set_property("Label", label)
            .await
            .map_err::<zbus::fdo::Error, _>(From::from)?;
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
            .await
            .map_err::<zbus::fdo::Error, _>(From::from)?;
        Ok(())
    }

    pub async fn delete(&self) -> Result<(), Error> {
        let prompt_path = self
            .inner()
            .call_method("Delete", &())
            .await
            .map_err::<ServiceError, _>(From::from)?
            .body()
            .deserialize::<OwnedObjectPath>()?;
        if let Some(prompt) = Prompt::new(self.inner().connection(), prompt_path).await? {
            let _ = prompt.receive_completed().await?;
        }
        Ok(())
    }

    #[doc(alias = "GetSecret")]
    pub async fn secret(&self, session: &Session<'_>) -> Result<Secret<'_>, Error> {
        let inner = self
            .inner()
            .call_method("GetSecret", &(session))
            .await
            .map_err::<ServiceError, _>(From::from)?
            .body()
            .deserialize::<SecretInner>()?;
        Secret::from_inner(self.inner().connection(), inner).await
    }

    #[doc(alias = "SetSecret")]
    pub async fn set_secret(&self, secret: &Secret<'_>) -> Result<(), Error> {
        self.inner()
            .call_method("SetSecret", &(secret,))
            .await
            .map_err::<ServiceError, _>(From::from)?;
        Ok(())
    }
}

impl<'a> Serialize for Item<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl<'a> PartialEq for Item<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.inner().path() == other.inner().path()
    }
}

impl<'a> Eq for Item<'a> {}

impl<'a> Hash for Item<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner().path().hash(state);
    }
}

impl<'a> fmt::Debug for Item<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Item")
            .field(&self.inner().path().as_str())
            .finish()
    }
}

impl<'a> Unlockable for Item<'a> {}
