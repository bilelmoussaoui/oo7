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
    zvariant::{self, ObjectPath, OwnedObjectPath, OwnedValue, Value},
    SignalContext,
};

use super::{
    prompt::Prompt,
    secret_exchange::{retrieve_secret, SecretExchange},
    service_manager::ServiceManager,
};

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
        properties: HashMap<String, OwnedValue>,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> fdo::Result<()> {
        // During a Prompt execution, prompt_ready() get called twise.
        // In the first call properties argument is empty.
        if properties.is_empty() {
            tracing::info!("first prompt_ready() call");

            let mut properties: HashMap<String, zvariant::OwnedValue> = HashMap::new();
            let secret_exchange = SecretExchange::new();
            let oo7_exchange = secret_exchange.begin();
            let aes_key = secret_exchange.create_shared_secret(exchange);
            self.manager
                .lock()
                .unwrap()
                .set_secret_exchange_aes_key(&aes_key);

            if header.path().unwrap().as_str().to_string().contains("/u") {
                // setting properties related to Secret.Service.Unlock
                properties.insert(
                    String::from("continue-label"),
                    Value::new("Unlock").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("warning"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("choice-chosen"),
                    Value::new(true).try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("description"),
                    Value::new(
                        "An application wants access to the keyring \"login\", but it is locked.",
                    )
                    .try_to_owned()
                    .unwrap(),
                );
                properties.insert(
                    String::from("title"),
                    Value::new("Unlock Keyring").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("message"),
                    Value::new("Authentication required")
                        .try_to_owned()
                        .unwrap(),
                );
                properties.insert(
                    String::from("choice-label"),
                    Value::new("Automatically unlock this keyring whenever I'm logged in")
                        .try_to_owned()
                        .unwrap(),
                );
                properties.insert(
                    String::from("caller-window"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("cancel-label"),
                    Value::new("Cancel").try_to_owned().unwrap(),
                );
            } else {
                // setting properties related to Secret.Service.CreateCollection
                properties.insert(
                    String::from("continue-label"),
                    Value::new("Continue").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("warning"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("choice-chosen"),
                    Value::new(false).try_to_owned().unwrap(),
                );
                properties.insert(String::from("description"), Value::new("An application wants to create a new keyring. Choose the password you want to use for it.").try_to_owned().unwrap());
                properties.insert(
                    String::from("title"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("message"),
                    Value::new("Choose password for new keyring")
                        .try_to_owned()
                        .unwrap(),
                );
                properties.insert(
                    String::from("choice-label"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("caller-window"),
                    Value::new("").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("cancel-label"),
                    Value::new("Cancel").try_to_owned().unwrap(),
                );
                properties.insert(
                    String::from("password-new"),
                    Value::new(true).try_to_owned().unwrap(),
                );
            }

            let path = Arc::new(header.path().unwrap().to_owned());
            let connection = Arc::new(connection.to_owned());

            // to call Prompter::PerformPrompt
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

            let secret = retrieve_secret(
                exchange,
                &self.manager.lock().unwrap().secret_exchange_aes_key(),
            );
            if secret.is_none() {
                // the prompt is dismissed
                self.manager.lock().unwrap().set_prompt_dismissed(true);
            } else {
                self.manager.lock().unwrap().set_prompt_dismissed(false);
            }

            let connection = Arc::new(connection.clone());
            let path = Arc::new(header.path().unwrap().to_owned());

            // to call Prompter::StopPrompting
            tokio::spawn(async move {
                let prompter = PrompterProxy::new(&Arc::clone(&connection)).await.unwrap();
                prompter.stop_prompting(&Arc::clone(&path)).await.unwrap();
            });

            let signal_context = Arc::new(ctxt.to_owned());
            let dismissed_out = Arc::new(self.manager.lock().unwrap().prompt_dismissed());
            let result_out = Arc::new(self.manager.lock().unwrap().collections());

            // to send Prompt::completed signal
            tokio::spawn(async move {
                let mut dismissed = true;
                let mut result: Vec<OwnedObjectPath> = Vec::new();
                let dismissed_in = Arc::clone(&dismissed_out);
                let result_in = Arc::clone(&result_out);

                if dismissed_in == false.into() {
                    result = result_in.to_vec();
                    dismissed = false;
                }

                let result = Value::new(result);
                let _ = Prompt::completed(&Arc::clone(&signal_context), dismissed, result).await;
            });
        }

        Ok(())
    }

    pub async fn prompt_done(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        tracing::info!("Prompt done: {}", self.path);

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
        properties: HashMap<String, OwnedValue>,
        exchange: &str,
    ) -> zbus::Result<()>;

    fn stop_prompting(&self, callback: &ObjectPath<'_>) -> zbus::Result<()>;
}
