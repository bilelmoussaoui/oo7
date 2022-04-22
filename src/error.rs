use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Zbus(zbus::Error),
}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Self::Zbus(e)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zbus(err) => write!(f, "zbus error {err}"),
        }
    }
}
