#[derive(zbus::DBusError, Debug)]
pub enum Error {
    Owned(String),
}

impl From<zbus::fdo::Error> for Error {
    fn from(err: zbus::fdo::Error) -> Self {
        Self::Owned(err.to_string())
    }
}
impl From<zbus::Error> for Error {
    fn from(err: zbus::Error) -> Self {
        Self::Owned(err.to_string())
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(err: oo7::dbus::Error) -> Self {
        Self::Owned(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Owned(err.to_string())
    }
}

impl From<getrandom::Error> for Error {
    fn from(err: getrandom::Error) -> Self {
        Self::Owned(err.to_string())
    }
}
