// org.freedesktop.Secret.Session

use zbus::{dbus_interface, fdo, zvariant};
use zvariant::OwnedObjectPath;

#[derive(Debug)]
pub struct Session {
    pub path: OwnedObjectPath,
}

#[dbus_interface(name = "org.freedesktop.Secret.Service")]
impl Session {
    pub async fn close(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        object_server
            .remove::<Self, &OwnedObjectPath>(&self.path)
            .await?;
        Ok(())
    }
}

impl Session {
    pub async fn new(path: OwnedObjectPath) -> Self {
        Self { path }
    }

    pub async fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
