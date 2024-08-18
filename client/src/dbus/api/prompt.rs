use std::fmt;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use zbus::{
    zvariant::{ObjectPath, OwnedValue, Type},
    ProxyDefault,
};

use super::DESTINATION;
use crate::dbus::{Error, ServiceError};

#[derive(Debug, Clone, PartialEq, Eq, Type)]
#[zvariant(signature = "s")]
/// A Window Identifier
pub enum WindowIdentifier {
    /// X11.
    X11(std::os::raw::c_ulong),
    /// Wayland.
    Wayland(String),
}

impl fmt::Display for WindowIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X11(xid) => f.write_str(&format!("x11:0x{xid:x}")),
            Self::Wayland(handle) => f.write_str(&format!("wayland:{handle}")),
        }
    }
}

impl std::str::FromStr for WindowIdentifier {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, handle) = s
            .split_once(':')
            .ok_or_else(|| Error::InvalidWindowIdentifier(s.to_owned()))?;
        match kind {
            "x11" => {
                let handle = handle.trim_start_matches("0x");
                Ok(Self::X11(
                    std::os::raw::c_ulong::from_str_radix(handle, 16)
                        .map_err(|_| Error::InvalidWindowIdentifier(s.to_owned()))?,
                ))
            }
            "wayland" => Ok(Self::Wayland(handle.to_owned())),
            _ => Err(Error::InvalidWindowIdentifier(s.to_owned())),
        }
    }
}

impl Serialize for WindowIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for WindowIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let handle = String::deserialize(deserializer)?;
        handle
            .parse::<Self>()
            .map_err(|e| serde::de::Error::custom(format!("Invalid Window identifier {e}")))
    }
}

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

    pub async fn prompt(&self, window_id: Option<WindowIdentifier>) -> Result<(), Error> {
        let id = match window_id {
            Some(id) => id.to_string(),
            None => Default::default(),
        };
        self.inner()
            .call_method("Prompt", &(id))
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

    pub async fn receive_completed(
        &self,
        window_id: Option<WindowIdentifier>,
    ) -> Result<OwnedValue, Error> {
        let mut stream = self.inner().receive_signal("Completed").await?;
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
            self.prompt(window_id)
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
