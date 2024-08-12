// org.gnome.keyring.Prompter
// https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/org.gnome.keyring.Prompter.xml

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oo7::portal::{Keyring, Secret};
use tokio;
use zbus::{
    fdo, interface,
    message::Header,
    proxy,
    zvariant::{self, ObjectPath, OwnedObjectPath, OwnedValue, Value},
};
use zbus_names::BusName;

use super::{
    collection::Collection,
    item,
    prompt::Prompt,
    secret_exchange::{retrieve_secret, SecretExchange},
    service::Service,
    service_manager::ServiceManager,
};
use crate::{LOGIN_KEYRING, SERVICE_PATH};

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
        reply: &str,
        properties: HashMap<String, OwnedValue>,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        // flag to indicate to repeat another PromptReady when password is incorrect.
        // this flag will be used to exit early to avoid executing StopPrompting call
        // and Prompt::completed signal.
        let mut repeat = false;

        // During a Prompt execution, prompt_ready() get called twise.
        // In the first call properties argument is empty.

        if properties.is_empty() {
            tracing::info!("first prompt_ready() call");

            let mut properties: HashMap<String, zvariant::OwnedValue> = HashMap::new();
            let secret_exchange = SecretExchange::new();
            let oo7_exchange = secret_exchange.begin();
            let aes_key = secret_exchange.create_shared_secret(exchange);

            let mut lock = self.manager.lock().unwrap();
            // storing oo7 server generated public_key in case we need it later when
            // handling incorrect password attempts.
            lock.set_secret_exchange_public_key(&oo7_exchange);
            drop(lock);
            // storing the aes_key for retrieve_secret() call
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
                // the secret is retrieved from the exchange and available in this branch
                self.manager.lock().unwrap().set_prompt_dismissed(false);

                let secret = secret.unwrap();
                // to verify the secret/password
                match Keyring::open(LOGIN_KEYRING, Secret::from(secret.to_vec())).await {
                    Ok(_) => {
                        tracing::info!("password matches");

                        let collections = self.manager.lock().unwrap().collections_to_unlock();
                        let connection_out = Arc::new(connection.to_owned());

                        // to update locked properties and sent out signals usings a separate task
                        tokio::spawn(async move {
                            let connection = Arc::clone(&connection_out);

                            for collection in collections {
                                let collection_interface_ref = connection
                                    .object_server()
                                    .interface::<_, Collection>(collection.clone())
                                    .await
                                    .unwrap();
                                let collection_interface = collection_interface_ref.get_mut().await;

                                let items = collection_interface.items().await;
                                if items.len() > 0 {
                                    for item in items {
                                        let item_interface_ref = connection
                                            .object_server()
                                            .interface::<_, item::Item>(item.clone())
                                            .await
                                            .unwrap();
                                        let item_interface = item_interface_ref.get_mut().await;

                                        // update item locked property
                                        item_interface.set_locked(false).await;
                                        // send PropertiesChanged
                                        item_interface
                                            .locked_changed(item_interface_ref.signal_context())
                                            .await
                                            .unwrap();
                                        // send Collection.ItemChanged signal
                                        Collection::item_changed(
                                            collection_interface_ref.signal_context(),
                                            item.into(),
                                        )
                                        .await
                                        .unwrap();
                                    }
                                }
                                // update the collection locked property
                                collection_interface.set_locked(false).await;
                                // calling zbus generated locked_changed to send PropertiesChanged
                                // signal
                                collection_interface
                                    .locked_changed(collection_interface_ref.signal_context())
                                    .await
                                    .unwrap();

                                // to retrieve the signal_context for the Service objectpath
                                let service_interface_ref = connection
                                    .object_server()
                                    .interface::<_, Service>(
                                        OwnedObjectPath::try_from(SERVICE_PATH).unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                // send the Service.CollectionChanged signal
                                Service::collection_changed(
                                    service_interface_ref.signal_context(),
                                    collection.into(),
                                )
                                .await
                                .unwrap();
                            }
                        });
                    }
                    Err(_) => {
                        tracing::info!("unlock password is incorrect");

                        // set repeat flag to true to indicate another PromptReady is needed
                        repeat = true;

                        let mut map: HashMap<String, zvariant::OwnedValue> = properties;
                        map.insert(
                            String::from("warning"),
                            Value::new("The unlock password was incorrect")
                                .try_to_owned()
                                .unwrap(),
                        );

                        let oo7_exchange =
                            self.manager.lock().unwrap().secret_exchange_public_key();

                        let connection = Arc::new(connection.to_owned());
                        let path = Arc::new(header.path().unwrap().to_owned());

                        // repeating Prompter::PerformPrompt
                        tokio::spawn(async move {
                            let prompter =
                                PrompterProxy::new(&Arc::clone(&connection)).await.unwrap();
                            prompter
                                .perform_prompt(&Arc::clone(&path), "password", map, &oo7_exchange)
                                .await
                                .unwrap();
                        });
                    }
                };
            }

            // early exit to prompt another PromptReady call from the gnome-shell
            if repeat {
                return Ok(());
            }

            let connection = Arc::new(connection.clone());
            let connection_for_stop_prompting = Arc::clone(&connection);
            let path = Arc::new(header.path().unwrap().to_owned());

            // to call Prompter::StopPrompting
            tokio::spawn(async move {
                let prompter = PrompterProxy::new(&Arc::clone(&connection_for_stop_prompting))
                    .await
                    .unwrap();
                prompter.stop_prompting(&Arc::clone(&path)).await.unwrap();
            });

            // retrieve the Unlock request sender's BusName and Prompt path
            let sender = self.manager.lock().unwrap().unlock_request_sender();
            let prompt_path = self.manager.lock().unwrap().unlock_prompt_path();

            // rather than using the signal_context from "zbus(signal_context)]" attribute
            // we need to retrieve the signal_context for the Unlock request Prompt
            // objectpath
            let interface_ref = connection
                .object_server()
                .interface::<_, Prompt>(prompt_path)
                .await
                .unwrap();
            let signal_ctxt = interface_ref.signal_context().to_owned();

            // create a new SignalContext with a predefined destination.
            // because later we need to send Prompt.Completed signal as a "Directed signal"
            let new_signal_ctxt = signal_ctxt.set_destination(BusName::try_from(sender).unwrap());

            let signal_context = Arc::new(new_signal_ctxt);
            let dismissed_out = Arc::new(self.manager.lock().unwrap().prompt_dismissed());
            let result_out = Arc::new(self.manager.lock().unwrap().collections_to_unlock());
            self.manager.lock().unwrap().reset_collections_to_unlock();

            // send Prompt.Completed signal
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
