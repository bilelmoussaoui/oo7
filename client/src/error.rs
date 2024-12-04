use std::fmt;

/// Alias for [`std::result::Result`] with the error type [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for oo7.
#[derive(Debug)]
pub enum Error {
    /// File backend error.
    File(crate::file::Error),
    /// Secret Service error.
    DBus(crate::dbus::Error),
}

impl From<crate::file::Error> for Error {
    fn from(e: crate::file::Error) -> Self {
        Self::File(e)
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
            Self::File(e) => write!(f, "File backend error {e}"),
            Self::DBus(e) => write!(f, "DBus error {e}"),
        }
    }
}
