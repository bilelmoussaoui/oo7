use std::fmt;

use oo7::dbus::ServiceError;

use crate::capability;

#[derive(Debug)]
pub enum Error {
    // File backend error
    File(oo7::file::Error),
    // Zbus error
    Zbus(zbus::Error),
    // IO error
    IO(std::io::Error),
    // Empty password error
    EmptyPassword,
    // Invalid item error
    InvalidItem(oo7::file::InvalidItemError),
    // Capability error
    Capability(capability::Error),
}

impl From<zbus::Error> for Error {
    fn from(err: zbus::Error) -> Self {
        Self::Zbus(err)
    }
}

impl From<oo7::file::Error> for Error {
    fn from(err: oo7::file::Error) -> Self {
        Self::File(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

impl From<capability::Error> for Error {
    fn from(err: capability::Error) -> Self {
        Self::Capability(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(err) => write!(f, "Portal error {err}"),
            Self::Zbus(err) => write!(f, "Zbus error {err}"),
            Self::IO(err) => write!(f, "IO error {err}"),
            Self::EmptyPassword => write!(f, "Login password can't be empty"),
            Self::InvalidItem(err) => write!(f, "Item cannot be decrypted {err}"),
            Self::Capability(err) => write!(f, "Capability error {err}"),
        }
    }
}

pub(crate) fn custom_service_error(error: &str) -> ServiceError {
    ServiceError::ZBus(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
        error.to_string(),
    ))))
}
