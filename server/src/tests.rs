use std::sync::Arc;

use oo7::{Secret, dbus};

use crate::service::Service;

/// Helper to create a peer-to-peer connection pair using Unix socket
async fn create_p2p_connection()
-> Result<(zbus::Connection, zbus::Connection), Box<dyn std::error::Error>> {
    let guid = zbus::Guid::generate();
    let (p0, p1) = tokio::net::UnixStream::pair()?;

    let (client_conn, server_conn) = tokio::try_join!(
        // Client
        zbus::connection::Builder::unix_stream(p0).p2p().build(),
        // Server
        zbus::connection::Builder::unix_stream(p1)
            .server(guid)?
            .p2p()
            .build(),
    )?;

    Ok((server_conn, client_conn))
}

pub(crate) struct TestServiceSetup {
    pub server: Service,
    pub client_conn: zbus::Connection,
    pub service_api: dbus::api::Service<'static>,
    pub session: Arc<dbus::api::Session<'static>>,
    pub collections: Vec<dbus::api::Collection<'static>>,
    pub server_public_key: Option<oo7::Key>,
    pub aes_key: Option<Arc<oo7::Key>>,
}

impl TestServiceSetup {
    pub(crate) async fn plain_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = create_p2p_connection().await?;

        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let server = Service::run_with_connection(server_conn, secret).await?;

        // Give the server a moment to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        let (server_public_key, session) = service_api.open_session(None).await?;
        let session = Arc::new(session);

        let collections = service_api.collections().await?;

        Ok(TestServiceSetup {
            server,
            client_conn,
            service_api,
            session,
            collections,
            server_public_key,
            aes_key: None,
        })
    }

    pub(crate) async fn encrypted_session(
        with_default_collection: bool,
    ) -> Result<TestServiceSetup, Box<dyn std::error::Error>> {
        let (server_conn, client_conn) = create_p2p_connection().await?;

        let secret = if with_default_collection {
            Some(Secret::from("test-password-long-enough"))
        } else {
            None
        };

        let server = Service::run_with_connection(server_conn, secret).await?;

        // Give the server a moment to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let service_api = dbus::api::Service::new(&client_conn).await?;

        // Generate client key pair for encrypted session
        let client_private_key = oo7::Key::generate_private_key()?;
        let client_public_key = oo7::Key::generate_public_key(&client_private_key)?;

        let (server_public_key, session) =
            service_api.open_session(Some(client_public_key)).await?;
        let session = Arc::new(session);

        let aes_key =
            oo7::Key::generate_aes_key(&client_private_key, &server_public_key.as_ref().unwrap())?;

        let collections = service_api.collections().await?;

        Ok(Self {
            server,
            client_conn,
            service_api,
            session,
            collections,
            server_public_key: server_public_key,
            aes_key: Some(Arc::new(aes_key)),
        })
    }
}
