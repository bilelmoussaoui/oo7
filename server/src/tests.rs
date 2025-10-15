use std::{collections::HashMap, sync::Arc};

use base64::Engine;
use oo7::{Secret, crypto, dbus};
use zbus::zvariant::{ObjectPath, Optional, Value};

use crate::{
    gnome::{
        prompter::{PromptType, Properties, Reply},
        secret_exchange,
    },
    service::Service,
};

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
    pub mock_prompter: MockPrompterService,
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

        let server = Service::run_with_connection(server_conn.clone(), secret).await?;

        // Create and serve the mock prompter
        let mock_prompter = MockPrompterService::new();
        client_conn
            .object_server()
            .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
            .await?;

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
            mock_prompter,
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

        let server = Service::run_with_connection(server_conn.clone(), secret).await?;

        // Create and serve the mock prompter
        let mock_prompter = MockPrompterService::new();
        client_conn
            .object_server()
            .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
            .await?;

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
            server_public_key,
            aes_key: Some(Arc::new(aes_key)),
            mock_prompter,
        })
    }
}

/// Mock implementation of org.gnome.keyring.internal.Prompter
///
/// This simulates the GNOME System Prompter for testing without requiring
/// the actual GNOME keyring prompter service to be running.
#[derive(Debug, Clone)]
pub(crate) struct MockPrompterService {
    /// The password to use for unlock prompts (simulates user input)
    unlock_password: Arc<tokio::sync::Mutex<Option<oo7::Secret>>>,
    /// Whether to accept (true) or dismiss (false) prompts
    should_accept: Arc<tokio::sync::Mutex<bool>>,
}

impl MockPrompterService {
    pub fn new() -> Self {
        Self {
            unlock_password: Arc::new(tokio::sync::Mutex::new(Some(oo7::Secret::from(
                "test-password-long-enough",
            )))),
            should_accept: Arc::new(tokio::sync::Mutex::new(true)),
        }
    }

    /// Set whether prompts should be accepted or dismissed
    pub async fn set_accept(&self, accept: bool) {
        *self.should_accept.lock().await = accept;
    }
}

#[zbus::interface(name = "org.gnome.keyring.internal.Prompter")]
impl MockPrompterService {
    async fn begin_prompting(
        &self,
        callback: ObjectPath<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("MockPrompter: begin_prompting called for {}", callback);
        let callback_path = callback.to_owned();
        let connection = connection.clone();

        // Spawn a task to send the initial prompt_ready call
        tokio::spawn(async move {
            tracing::debug!("MockPrompter: spawned task starting");
            // Small delay to ensure callback is fully registered
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Call PromptReady directly without building a proxy (avoids introspection
            // issues in p2p)
            tracing::debug!(
                "MockPrompter: calling PromptReady with None on {}",
                callback_path
            );
            let properties: HashMap<String, Value> = HashMap::new();
            let empty_exchange = "";

            connection
                .call_method(
                    None::<()>, // No destination in p2p
                    &callback_path,
                    Some("org.gnome.keyring.internal.Prompter.Callback"),
                    "PromptReady",
                    &(Optional::<Reply>::from(None), properties, empty_exchange),
                )
                .await?;

            tracing::debug!("MockPrompter: PromptReady(None) completed");
            Ok::<_, zbus::Error>(())
        });

        Ok(())
    }

    async fn perform_prompt(
        &self,
        callback: ObjectPath<'_>,
        type_: PromptType,
        _properties: Properties,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!(
            "MockPrompter: perform_prompt called for {}, type={:?}",
            callback,
            type_
        );
        // This is called by PrompterCallback.prompter_init() with the server's exchange
        let callback_path = callback.to_owned();
        let unlock_password = self.unlock_password.clone();
        let should_accept = self.should_accept.clone();
        let exchange = exchange.to_owned();
        let connection = connection.clone();

        // Spawn a task to simulate user interaction and send final response
        tokio::spawn(async move {
            tracing::debug!("MockPrompter: perform_prompt task starting");
            // Small delay to simulate user interaction
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            let accept = *should_accept.lock().await;
            let properties: HashMap<String, Value> = HashMap::new();

            if !accept {
                tracing::debug!("MockPrompter: dismissing prompt");
                // Dismiss the prompt
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::No, properties, ""),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(no) completed");

                // Call PromptDone to clean up the callback
                tracing::debug!("MockPrompter: calling PromptDone");
                connection
                    .call_method(
                        None::<()>,
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptDone",
                        &(),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptDone completed");

                return Ok(());
            } else if type_ == PromptType::Password {
                tracing::debug!("MockPrompter: performing unlock (password prompt)");
                // Unlock prompt - perform secret exchange
                let password = unlock_password.lock().await.clone().unwrap();

                // Generate our own key pair
                let private_key = oo7::Key::generate_private_key().unwrap();
                let public_key = crate::gnome::crypto::generate_public_key(&private_key).unwrap();

                // Handshake with server's exchange to get AES key
                let aes_key = secret_exchange::handshake(&private_key, &exchange).unwrap();

                // Encrypt the password
                let iv = crypto::generate_iv().unwrap();
                let encrypted = crypto::encrypt(password.as_bytes(), &aes_key, &iv).unwrap();

                // Create final exchange with encrypted secret
                let final_exchange = format!(
                    "[sx-aes-1]\npublic={}\nsecret={}\niv={}",
                    base64::prelude::BASE64_STANDARD.encode(public_key.as_ref()),
                    base64::prelude::BASE64_STANDARD.encode(&encrypted),
                    base64::prelude::BASE64_STANDARD.encode(&iv)
                );

                tracing::debug!("MockPrompter: calling PromptReady with yes");
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::Yes, properties, final_exchange.as_str()),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(yes) with secret exchange completed");
            } else {
                tracing::debug!("MockPrompter: accepting confirm prompt");
                // Lock/confirm prompt - just accept
                connection
                    .call_method(
                        None::<()>, // No destination in p2p
                        &callback_path,
                        Some("org.gnome.keyring.internal.Prompter.Callback"),
                        "PromptReady",
                        &(Reply::Yes, properties, ""),
                    )
                    .await?;
                tracing::debug!("MockPrompter: PromptReady(yes) completed");
            }

            // Call PromptDone to clean up the callback
            tracing::debug!("MockPrompter: calling PromptDone");
            connection
                .call_method(
                    None::<()>,
                    &callback_path,
                    Some("org.gnome.keyring.internal.Prompter.Callback"),
                    "PromptDone",
                    &(),
                )
                .await?;
            tracing::debug!("MockPrompter: PromptDone completed");

            Ok::<_, zbus::Error>(())
        });

        Ok(())
    }

    async fn stop_prompting(&self, _callback: ObjectPath<'_>) -> zbus::fdo::Result<()> {
        // Called when prompting is complete
        Ok(())
    }
}
