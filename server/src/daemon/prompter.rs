// org.gnome.keyring.Prompter
// https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/org.gnome.keyring.Prompter.xml

use std::collections::HashMap;

use zbus::{
    fdo, interface, proxy,
    zvariant::{
        self, DeserializeDict, ObjectPath, OwnedObjectPath, OwnedValue, SerializeDict, Type,
    },
    SignalContext,
};

use super::secret_exchange;

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
    choice_chosen: Option<String>,
    #[zvariant(rename = "password-new")]
    password_new: Option<bool>,
    #[zvariant(rename = "password-strength")]
    password_strength: Option<u32>,
}

// org.gnome.keyring.internal.Prompter.Callback

#[derive(Clone, Debug)]
pub struct PrompterCallback {
    path: OwnedObjectPath,
}

#[interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: &str,            // the purpose of this?
        properties: Properties, // this should probably be &mut Properties
        exchange: &str,         // this should probably be &mut String
    ) -> fdo::Result<()> {
        // TODO: add implementation

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
    pub fn new(prompts_counter: i32) -> Self {
        Self {
            path: OwnedObjectPath::try_from(format!(
                "{}p{}",
                SECRET_PROMPTER_PREFIX, prompts_counter
            ))
            .unwrap(),
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
        type_: &str,             // 'password' or 'confirm', put this in Enum?
        properties: &Properties, // probably should be &mut
        exchange: &str,          // this should probably be &mut String
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
