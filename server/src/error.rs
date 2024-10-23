use std::fmt;

#[derive(Debug)]
pub enum Error {
    // File backend error
    Portal(oo7::portal::Error),
    // Zbus error
    Zbus(zbus::Error),
    // IO error
    IO(std::io::Error),
    // Empty password error
    EmptyPassword,
}

impl From<zbus::Error> for Error {
    fn from(err: zbus::Error) -> Self {
        Self::Zbus(err)
    }
}

impl From<oo7::portal::Error> for Error {
    fn from(err: oo7::portal::Error) -> Self {
        Self::Portal(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Portal(err) => write!(f, "Portal error {err}"),
            Self::Zbus(err) => write!(f, "Zbus error {err}"),
            Self::IO(err) => write!(f, "IO error {err}"),
            Self::EmptyPassword => write!(f, "Login password can't be empty"),
        }
    }
}
