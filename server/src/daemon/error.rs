/// DBus Secret Service specific errors.
/// <https://specifications.freedesktop.org/secret-service/latest/ch15.html>
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

impl From<oo7::portal::Error> for ServiceError {
    fn from(value: oo7::portal::Error) -> Self {
        Self::ZBus(zbus::Error::Failure(value.to_string()))
    }
}
