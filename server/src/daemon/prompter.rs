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
    zvariant::{
        self, DeserializeDict, ObjectPath, OwnedObjectPath, OwnedValue, SerializeDict, Type,
    },
    Connection, SignalContext,
};

use super::{secret_exchange, service_manager::ServiceManager};

// May be change this to /org/oo7_daemon/Prompt
const SECRET_PROMPTER_PREFIX: &str = "/org/gnome/keyring/Prompt/";

#[derive(Clone, Default, DeserializeDict, Debug, Type, SerializeDict)]
#[zvariant(signature = "dict")]
pub struct Properties {
    title: Option<String>,
    message: Option<String>,
    description: Option<String>,
    warning: Option<String>,
    #[zvariant(rename = "choice-label")]
    choice_label: Option<String>,
    #[zvariant(rename = "caller-window")]
    caller_window: Option<String>,
    #[zvariant(rename = "continue-label")]
    continue_label: Option<String>,
    #[zvariant(rename = "cancel-label")]
    cancel_label: Option<String>,
    #[zvariant(rename = "choice-chosen")]
    choice_chosen: Option<bool>,
    #[zvariant(rename = "password-new")]
    password_new: Option<bool>,
    #[zvariant(rename = "password-strength")]
    password_strength: Option<u32>,
}

// org.gnome.keyring.internal.Prompter.Callback

#[derive(Clone, Debug)]
pub struct PrompterCallback {
    properties: Arc<Mutex<Properties>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: &str,            // the purpose of this?
        properties: Properties, // this should probably be &mut Properties
        exchange: &str,         // this should probably be &mut String
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        println!("prompter: {}", header.path().unwrap());

        let mut properties = properties.clone();

        if header.path().unwrap().as_str().to_string().contains("/u") {
            // setting properties related to Secret.Service.Unlock
            properties.continue_label = Some(String::from("Unlock"));
            properties.warning = Some(String::new());
            properties.choice_chosen = Some(true);
            properties.description = Some(String::from(
                "An application wants access to the keyring \"login\", but it is locked.",
            ));
            properties.title = Some(String::from("Unlock Keyring"));
            properties.message = Some(String::from("Authentication required"));
            properties.choice_label = Some(String::from(
                "Automatically unlock this keyring whenever I'm logged in",
            ));
            properties.caller_window = Some(String::new());
            properties.cancel_label = Some(String::from("Cancel"));
        } else {
            // setting properties related to Secret.Service.CreateCollection
            properties.continue_label = Some(String::from("Continue"));
            properties.warning = Some(String::new());
            properties.choice_chosen = Some(false);
            properties.description = Some(String::from(
                "An application wants to create a new keyring. Choose the password you want to use for it.",
            ));
            properties.title = Some(String::new());
            properties.message = Some(String::from("Choose password for new keyring"));
            properties.choice_label = Some(String::new());
            properties.caller_window = Some(String::new());
            properties.cancel_label = Some(String::from("Cancel"));
            properties.password_new = Some(true);
        }

        *self.properties.lock().unwrap() = properties.clone();

        let path = Arc::new(header.path().unwrap().to_owned());
        let exchange = exchange.to_string();
        let connection = Arc::new(connection.to_owned());

        tokio::spawn(async move {
            let prompter = PrompterProxy::new(&connection).await.unwrap();
            prompter
                .perform_prompt(&path, "password", properties, exchange)
                .await
                .unwrap();
        });

        Ok(())
    }

    pub async fn prompt_done(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        object_server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }
}

impl PrompterCallback {
    pub fn new(post_fix: Option<&str>, prompts_counter: i32) -> Self {
        let path = if post_fix.is_some() {
            OwnedObjectPath::try_from(format!(
                "{}{}{}",
                SECRET_PROMPTER_PREFIX,
                post_fix.unwrap(),
                prompts_counter
            ))
            .unwrap()
        } else {
            OwnedObjectPath::try_from(format!("{}p{}", SECRET_PROMPTER_PREFIX, prompts_counter))
                .unwrap()
        };

        Self {
            properties: Arc::new(Mutex::new(Properties::default())),
            path: path,
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
        properties: Properties,
        exchange: String, // this should probably be &mut String
    ) -> zbus::Result<()>;

    fn stop_prompting(&self, callback: &ObjectPath<'_>) -> zbus::Result<()>;
}

#[cfg(test)]
mod test {
    use super::*;

    // WIP: not complete

    #[tokio::test]
    async fn test_prompt() -> Result<(), zbus::Error> {
        let connection = zbus::Connection::session().await?;

        let secret_exchange = secret_exchange::SecretExchange::new();
        let exchange = secret_exchange.secret_exchange_begin();

        let callback = CallbackProxy::new(&connection).await?;
        let prompter = PrompterProxy::new(&connection).await?;

        let mut properties = Properties::default();
        properties.title = Some(String::from("Test Prompt"));
        properties.message = Some(String::from("The message"));
        properties.description = Some(String::from("The description"));
        properties.choice_label = None;
        properties.warning = Some(String::from("Enter a strong password"));

        println!("{}", callback.0.path());

        let _ = prompter.begin_prompting(callback.0.path()).await;
        let _ = callback.prompt_ready("yes", &properties, &exchange).await;
        let _ = prompter
            .perform_prompt(callback.0.path(), "password", &properties, &exchange)
            .await;
        let _ = callback.prompt_ready("test", &properties, &exchange).await;

        // println!("{}", secret_exchange::get_secret(&exchange).unwrap());

        Ok(())
    }
}
