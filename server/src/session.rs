// org.freedesktop.Secret.Session

use std::sync::Arc;

use oo7::Key;
use tokio::sync::Mutex;
use zbus::{interface, zvariant::OwnedObjectPath};

use super::Result;
use crate::service_manager::ServiceManager;

#[derive(Debug, Clone)]
pub struct Session {
    _aes_key: Option<Arc<Key>>,
    manager: Arc<Mutex<ServiceManager>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    pub async fn close(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<()> {
        self.manager.lock().await.remove_session(&self.path);
        object_server.remove::<Self, _>(&self.path).await?;

        Ok(())
    }
}

impl Session {
    pub async fn new(aes_key: Option<Arc<Key>>, manager: Arc<Mutex<ServiceManager>>) -> Self {
        let index = manager.lock().await.n_sessions() + 1;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{index}"))
                .unwrap(),
            _aes_key: aes_key,
            manager,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
