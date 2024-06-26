// org.gnome.keyring.Prompter
// https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/org.gnome.keyring.Prompter.xml

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio;
use zbus::{
    fdo, interface,
    message::Header,
    proxy,
    zvariant::{self, ObjectPath, OwnedObjectPath, Value},
};

use super::{secret_exchange::SecretExchange, service_manager::ServiceManager};

// May be change this to /org/oo7_daemon/Prompt
const SECRET_PROMPTER_PREFIX: &str = "/org/gnome/keyring/Prompt/";

// org.gnome.keyring.internal.Prompter.Callback

#[derive(Clone, Debug)]
pub struct PrompterCallback {
    manager: Arc<Mutex<ServiceManager>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: &str, // the purpose of this?
        properties: HashMap<&str, Value<'_>>,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        // During a Prompt execution, prompt_ready() get called twise.
        // In the first call properties argument is empty.
        if properties.is_empty() {
            tracing::info!("first prompt_ready() call");

            let mut properties: HashMap<&str, zvariant::Value<'_>> = HashMap::new();
            let secret_exchange = SecretExchange::new();
            let oo7_exchange = secret_exchange.begin();
            self.manager.lock().unwrap().set_oo7_exchange(&oo7_exchange);

            if header.path().unwrap().as_str().to_string().contains("/u") {
                // setting properties related to Secret.Service.Unlock
                properties.insert("continue-label", Value::new("Unlock"));
                properties.insert("warning", Value::new(""));
                properties.insert("choice-chosen", Value::new(true));
                properties.insert(
                    "description",
                    Value::new(
                        "An application wants access to the keyring \"login\", but it is locked.",
                    ),
                );
                properties.insert("title", Value::new("Unlock Keyring"));
                properties.insert("message", Value::new("Authentication required"));
                properties.insert(
                    "choice-label",
                    Value::new("Automatically unlock this keyring whenever I'm logged in"),
                );
                properties.insert("caller-window", Value::new(""));
                properties.insert("cancel-label", Value::new("Cancel"));
            } else {
                // setting properties related to Secret.Service.CreateCollection
                properties.insert("continue-label", Value::new("Continue"));
                properties.insert("warning", Value::new(""));
                properties.insert("choice-chosen", Value::new(false));
                properties.insert("description", Value::new("An application wants to create a new keyring. Choose the password you want to use for it."));
                properties.insert("title", Value::new(""));
                properties.insert("message", Value::new("Choose password for new keyring"));
                properties.insert("choice-label", Value::new(""));
                properties.insert("caller-window", Value::new(""));
                properties.insert("cancel-label", Value::new("Cancel"));
                properties.insert("password-new", Value::new(true));
            }

            let path = Arc::new(header.path().unwrap().to_owned());
            let connection = Arc::new(connection.to_owned());

            // self.manager.lock().unwrap().exchange = Arc::clone(&exchange); // todo:
            // setter

            tokio::spawn(async move {
                let prompter = PrompterProxy::new(&Arc::clone(&connection)).await.unwrap();
                prompter
                    .perform_prompt(&Arc::clone(&path), "password", properties, &oo7_exchange)
                    .await
                    .unwrap();
            });

        // In second call properties argument is not empty
        } else {
            tracing::info!("second prompt_ready() call");

            let connection = Arc::new(connection.clone());
            let path = Arc::new(header.path().unwrap().to_owned());

            tokio::spawn(async move {
                let prompter = PrompterProxy::new(&Arc::clone(&connection)).await.unwrap();
                prompter.stop_prompting(&Arc::clone(&path)).await.unwrap();
            });
        }

        Ok(())
    }

    pub async fn prompt_done(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        let connection = Arc::new(connection.to_owned());
        let path = Arc::new(header.path().unwrap().to_owned());
        println!("prompt_done: path: {}", path);

        // tokio::spawn(async move {
        // let prompter = PrompterProxy::new(&connection).await.unwrap();
        // prompter.stop_prompting(&path).await.unwrap();
        // });

        object_server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }
}

impl PrompterCallback {
    pub fn for_unlock(manager: Arc<Mutex<ServiceManager>>) -> Self {
        let counter = manager.lock().unwrap().prompts_counter();

        Self {
            path: OwnedObjectPath::try_from(format!(
                "{}{}{}",
                SECRET_PROMPTER_PREFIX, "u", counter
            ))
            .unwrap(),
            manager,
        }
    }

    pub fn for_new_collection(manager: Arc<Mutex<ServiceManager>>) -> Self {
        let counter = manager.lock().unwrap().prompts_counter();

        Self {
            path: OwnedObjectPath::try_from(format!(
                "{}{}{}",
                SECRET_PROMPTER_PREFIX, "p", counter
            ))
            .unwrap(),
            manager,
        }
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}

// org.gnome.keyring.internal.Prompter

#[proxy(
    default_service = "org.gnome.keyring.SystemPrompter",
    interface = "org.gnome.keyring.internal.Prompter",
    default_path = "/org/gnome/keyring/Prompter"
)]
pub trait Prompter {
    fn begin_prompting(&self, callback: &ObjectPath<'_>) -> zbus::Result<()>;

    fn perform_prompt(
        &self,
        callback: &ObjectPath<'_>,
        type_: &str, // 'password' or 'confirm', put this in Enum?
        properties: HashMap<&str, Value<'_>>,
        exchange: &str,
    ) -> zbus::Result<()>;

    fn stop_prompting(&self, callback: &ObjectPath<'_>) -> zbus::Result<()>;
}
