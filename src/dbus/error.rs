use std::fmt;

// TODO: support secret service errors
// https://specifications.freedesktop.org/secret-service/latest/ch15.html
/// DBus Secret Service specific errors.
#[derive(Debug)]
pub enum Error {
    /// Something went wrong on the wire.
    Zbus(zbus::Error),
    /// The item/collection was removed.
    Deleted,
    /// The prompt request was dimissed.
    Dismissed,
    /// Input/Output.
    IO(std::io::Error),
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
            Self::IO(err) => write!(f, "IO error {err}"),
            Self::Deleted => write!(f, "Item/Collection was deleted, can no longer be used"),
            Self::Dismissed => write!(f, "Prompt was dismissed"),
        }
    }
}
