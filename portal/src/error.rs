#[derive(Debug)]
pub enum Error {
    Oo7(oo7::dbus::Error),
    Io(std::io::Error),
    Portal(ashpd::PortalError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oo7(e) => f.write_fmt(format_args!("DBus error: {e}")),
            Self::Io(e) => f.write_fmt(format_args!("IO error: {e}")),
            Self::Portal(e) => f.write_fmt(format_args!("Portal error: {e}")),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Oo7(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Portal(e) => Some(e),
        }
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(value: oo7::dbus::Error) -> Self {
        Self::Oo7(value)
    }
}

impl From<oo7::zbus::Error> for Error {
    fn from(value: oo7::zbus::Error) -> Self {
        Self::Oo7(oo7::dbus::Error::ZBus(value))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ashpd::PortalError> for Error {
    fn from(value: ashpd::PortalError) -> Self {
        Self::Portal(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
