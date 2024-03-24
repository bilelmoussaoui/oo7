// org.freedesktop.Secret.Session

use std::sync::{Arc, Mutex};

use oo7::Key;
use zbus::{fdo, interface, zvariant};
use zvariant::{ObjectPath, OwnedObjectPath};

use super::service_manager::ServiceManager;
use crate::SECRET_SESSION_PREFIX;

#[derive(Debug, Clone)]
pub struct Session {
    aes_key: Arc<Option<Key>>,
    manager: Arc<Mutex<ServiceManager>>,
    pub path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
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
        aes_key: Option<Key>,
        manager: Arc<Mutex<ServiceManager>>,
        sessions_counter: i32,
    ) -> Self {
        Self {
            aes_key: Arc::new(aes_key),
            path: OwnedObjectPath::try_from(format!(
                "{}s{}",
                SECRET_SESSION_PREFIX, sessions_counter
            ))
            .unwrap(),
            manager,
        }
    }

    pub fn aes_key(&self) -> &Option<Key> {
        self.aes_key.as_ref()
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}
