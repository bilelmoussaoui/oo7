// org.freedesktop.Secret.Item

use oo7::dbus::{api::SecretInner, ServiceError};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

#[derive(Debug)]
pub struct Item {
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath, ServiceError> {
        todo!()
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(&self, _session: ObjectPath<'_>) -> Result<SecretInner, ServiceError> {
        todo!()
    }

    pub async fn set_secret(&self, _secret: SecretInner) -> Result<(), ServiceError> {
        todo!()
    }
}

impl Item {
    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}
