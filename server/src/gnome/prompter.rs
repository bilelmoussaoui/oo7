use oo7::dbus::ServiceError;
use serde::{Deserialize, Serialize};
use zbus::zvariant::{self, DeserializeDict, Optional, OwnedObjectPath, SerializeDict, Type};

use crate::service::Service;

#[derive(Debug, DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
// GcrPrompt properties <https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-prompt.c#L95>
// This struct causes "Unexpected non-0 padding byte `1`" error.
// See <https://github.com/dbus2/zbus/issues/1303>
struct Properties {
    title: Option<String>,
    message: Option<String>,
    description: Option<String>,
    warning: Option<String>,
    #[zvariant(rename = "password-new")]
    password_new: Option<bool>,
    #[zvariant(rename = "password-strength")]
    password_strength: Option<u32>,
    #[zvariant(rename = "choice-label")]
    choice_label: Option<String>,
    #[zvariant(rename = "choice-chosen")]
    choice_chosen: Option<bool>,
    #[zvariant(rename = "caller-window")]
    caller_window: Option<String>,
    #[zvariant(rename = "continue-label")]
    continue_label: Option<String>,
    #[zvariant(rename = "cancel-label")]
    cancel_label: Option<String>,
}
impl Properties {
    fn for_lock(keyring: &str, window_id: Option<&str>) -> Self {
        Self {
            title: None,
            message: Some("Lock Keyring".to_owned()),
            description: Some(format!("Confirm locking '{}' Keyring", keyring)),
            warning: None,
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some("Lock".to_owned()),
            cancel_label: Some("Cancel".to_owned()),
        }
    }

    fn for_unlock(keyring: &str, warning: Option<&str>, window_id: Option<&str>) -> Self {
        Self {
            title: Some("Unlock Keyring".to_owned()),
            message: Some("Authentication required".to_owned()),
            description: Some(format!(
                "An application wants access to the keyring '{}', but it is locked",
                keyring
            )),
            warning: warning.map(ToOwned::to_owned),
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some("Unlock".to_owned()),
            cancel_label: Some("Cancel".to_owned()),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
enum Reply {
    No,
    Yes,
}

impl zvariant::NoneValue for Reply {
    type NoneType = String;

    fn null_value() -> Self::NoneType {
        String::new()
    }
}

impl TryFrom<String> for Reply {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "no" => Ok(Reply::No),
            "yes" => Ok(Reply::Yes),
            _ => Err("Invalid value".to_string()),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
enum PromptType {
    Confirm,
    Password,
}

#[zbus::proxy(
    default_service = "org.gnome.keyring.SystemPrompter",
    interface = "org.gnome.keyring.internal.Prompter",
    default_path = "/org/gnome/keyring/Prompter",
    gen_blocking = false
)]
pub trait Prompter {
    fn begin_prompting(&self, callback: &OwnedObjectPath) -> Result<(), ServiceError>;

    fn perform_prompt(
        &self,
        callback: OwnedObjectPath,
        type_: PromptType,
        properties: Properties,
        exchange: &str,
    ) -> Result<(), ServiceError>;

    fn stop_prompting(&self, callback: OwnedObjectPath) -> Result<(), ServiceError>;
}

pub struct PrompterCallback {
    window_id: String,
    service: Service,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    async fn prompt_ready(
        &self,
        reply: Optional<Reply>,
        _properties: Properties,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), ServiceError> {
        todo!();
    }

    async fn prompt_done(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        todo!();
    }
}

impl PrompterCallback {
    pub async fn new(
        window_id: &str,
        service: Service,
        prompt_path: OwnedObjectPath,
    ) -> Result<Self, oo7::crypto::Error> {
        let index = 0;
        Ok(Self {
            window_id: window_id.to_owned(),
            path: OwnedObjectPath::try_from(format!("/org/gnome/keyring/Prompt/p{index}")).unwrap(),
            service,
            prompt_path,
        })
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
