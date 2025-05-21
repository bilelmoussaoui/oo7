// org.freedesktop.Secret.Session

use std::sync::Arc;

use oo7::{dbus::ServiceError, Key};
use zbus::{interface, zvariant::OwnedObjectPath};

use crate::Service;

#[derive(Debug, Clone)]
pub struct Session {
    aes_key: Option<Arc<Key>>,
    client_name: String,
    service: Service,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    pub async fn close(&self) -> Result<(), ServiceError> {
        self.service.remove_session(&self.path).await;
        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;

        Ok(())
    }
}

impl Session {
    pub async fn new(aes_key: Option<Arc<Key>>, client_name: String, service: Service) -> Self {
        let index = service.session_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{index}"))
                .unwrap(),
            aes_key,
            client_name,
            service,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }

    pub fn aes_key(&self) -> Option<Arc<Key>> {
        self.aes_key.as_ref().map(Arc::clone)
    }

    pub fn client_name(&self) -> &str {
        &self.client_name
    }
}
