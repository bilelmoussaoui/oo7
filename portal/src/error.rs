#[derive(Debug)]
pub enum Error {
    Rand(getrandom::Error),
    Oo7(oo7::dbus::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rand(e) => f.write_fmt(format_args!("Rand error {e}")),
            Error::Oo7(e) => f.write_fmt(format_args!("DBus error: {e}")),
            Error::Io(e) => f.write_fmt(format_args!("IO error: {e}")),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Rand(_) => None,
            Error::Oo7(e) => Some(e),
            Error::Io(e) => Some(e),
        }
    }
}

impl From<getrandom::Error> for Error {
    fn from(err: getrandom::Error) -> Self {
        Self::Rand(err)
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(value: oo7::dbus::Error) -> Self {
        Self::Oo7(value)
    }
}

impl From<oo7::zbus::Error> for Error {
    fn from(value: oo7::zbus::Error) -> Self {
        Self::Oo7(oo7::dbus::Error::Zbus(value))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
