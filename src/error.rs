use std::fmt;

/// Alias for [`std::result::Result`] with the error type [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Portal(crate::portal::Error),
    DBus(crate::dbus::Error),
}

impl From<crate::portal::Error> for Error {
    fn from(e: crate::portal::Error) -> Self {
        Self::Portal(e)
    }
}

impl From<crate::dbus::Error> for Error {
    fn from(e: crate::dbus::Error) -> Self {
        Self::DBus(e)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Portal(e) => write!(f, "Portal error {e}"),
            Self::DBus(e) => write!(f, "DBus error {e}"),
        }
    }
}
