// org.freedesktop.Secret.Session

use std::sync::Arc;

use oo7::{Key, dbus::ServiceError};
use zbus::{
    interface,
    names::UniqueName,
    zvariant::{ObjectPath, OwnedObjectPath},
};

use crate::Service;

#[derive(Debug, Clone)]
pub struct Session {
    aes_key: Option<Arc<Key>>,
    service: Service,
    path: OwnedObjectPath,
    sender: UniqueName<'static>,
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
    pub async fn new(
        aes_key: Option<Arc<Key>>,
        service: Service,
        sender: UniqueName<'static>,
    ) -> Self {
        let index = service.session_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{index}"))
                .unwrap(),
            aes_key,
            service,
            sender,
        }
    }

    pub fn sender(&self) -> &UniqueName<'static> {
        &self.sender
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn aes_key(&self) -> Option<Arc<Key>> {
        self.aes_key.as_ref().map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn close() -> Result<(), Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = crate::tests::create_p2p_connection().await?;
        let server = crate::Service::run_with_connection(
            server_conn,
            Some(oo7::Secret::from("test-password-long-enough")),
        )
        .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = oo7::dbus::api::Service::new(&client_conn).await?;

        // Open a session
        let (_aes_key, session) = service_api.open_session(None).await?;
        let path = session.inner().path().to_owned();

        // Verify session exists on the server
        let session_check = server.session(&path).await;
        assert!(
            session_check.is_some(),
            "Session should exist on server before close"
        );

        // Close the session
        session.close().await?;

        // Verify session no longer exists on the server
        let session_check_after = server.session(&path).await;
        assert!(
            session_check_after.is_none(),
            "Session should not exist on server after close"
        );

        Ok(())
    }
}
