// org.freedesktop.Secret.Session

use std::sync::{Arc, Mutex};

use oo7::Key;
use zbus::{fdo, interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::service_manager::ServiceManager;

const SECRET_SESSION_OBJECTPATH: &str = "/org/freedesktop/secrets.Devel/session/";

#[derive(Debug, Clone)]
pub struct Session {
    client_public_key: Arc<Option<Key>>,
    manager: Arc<Mutex<ServiceManager>>,
    pub path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Session {
    pub async fn close(
        &mut self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        self.manager.lock().unwrap().remove_session(self.path());
        object_server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }
}

impl Session {
    pub fn new(
        client_public_key: Option<Key>,
        manager: Arc<Mutex<ServiceManager>>,
        sessions_counter: i32,
    ) -> (Self, Option<Key>) {
        // make use of the keys
        let service_key = vec![0];
        let instance = Self {
            client_public_key: Arc::new(client_public_key),
            path: OwnedObjectPath::try_from(format!(
                "{}{}{}",
                SECRET_SESSION_OBJECTPATH, "s", sessions_counter
            ))
            .unwrap(),
            manager,
        };

        (instance, Some(Key::new(service_key)))
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}
