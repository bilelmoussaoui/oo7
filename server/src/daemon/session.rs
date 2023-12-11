// org.freedesktop.Secret.Session

use oo7::Key;
use zbus::{fdo, interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

#[derive(Debug)]
pub struct Session {
    client_public_key: Option<Key>,
    pub path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Session {
    pub async fn close(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        object_server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }
}

impl Session {
    pub fn new(client_public_key: Option<Key>) -> (Self, Option<Key>) {
        // make use of the keys
        let service_key = vec![0];
        let instance = Self {
            client_public_key,
            path: OwnedObjectPath::try_from(format!("{}", "a")).unwrap(),
        };

        (instance, Some(Key::new(service_key)))
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}
