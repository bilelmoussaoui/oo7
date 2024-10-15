// org.freedesktop.Secret.Item

use oo7::dbus::api::SecretInner;
use zbus::zvariant::ObjectPath;

use super::Result;

#[derive(Debug)]
pub struct Item {}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    pub async fn delete(&self) -> Result<ObjectPath> {
        todo!()
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(&self, _session: ObjectPath<'_>) -> Result<SecretInner> {
        todo!()
    }

    pub async fn set_secret(&self, _secret: SecretInner) -> Result<()> {
        todo!()
    }
}
