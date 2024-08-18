use std::fmt;

/// DBus Secret Service specific errors.
/// <https://specifications.freedesktop.org/secret-service-spec/latest/errors.html>
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum ServiceError {
    #[zbus(error)]
    /// ZBus specific error.
    ZBus(zbus::Error),
    /// Collection/Item is locked.
    IsLocked,
    /// Session does not exist.
    NoSession,
    /// Collection/Item does not exist.
    NoSuchObject,
}

/// DBus backend specific errors.
#[derive(Debug)]
pub enum Error {
    /// Something went wrong on the wire.
    Zbus(zbus::Error),
    /// A service error.
    Service(ServiceError),
    /// The item/collection was removed.
    Deleted,
    /// The prompt request was dismissed.
    Dismissed,
    /// The collection doesn't exists
    NotFound(String),
    /// Input/Output.
    IO(std::io::Error),
    /// Invalid window identifier
    InvalidWindowIdentifier(String),
}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Self::Zbus(e)
    }
}

impl From<zbus::fdo::Error> for Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Self::Zbus(zbus::Error::FDO(Box::new(e)))
    }
}

impl From<zbus::zvariant::Error> for Error {
    fn from(e: zbus::zvariant::Error) -> Self {
        Self::Zbus(zbus::Error::Variant(e))
    }
}

impl From<ServiceError> for Error {
    fn from(e: ServiceError) -> Self {
        Self::Service(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zbus(err) => write!(f, "zbus error {err}"),
            Self::Service(err) => write!(f, "service error {err}"),
            Self::IO(err) => write!(f, "IO error {err}"),
            Self::Deleted => write!(f, "Item/Collection was deleted, can no longer be used"),
            Self::NotFound(name) => write!(f, "The collection '{name}' doesn't exists"),
            Self::Dismissed => write!(f, "Prompt was dismissed"),
            Self::InvalidWindowIdentifier(identifier) => {
                write!(f, "Invalid window identifier {identifier}")
            }
        }
    }
}
