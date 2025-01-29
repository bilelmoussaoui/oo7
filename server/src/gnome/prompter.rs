// org.gnome.keyring.Prompter
// https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/org.gnome.keyring.Prompter.xml

use clap::error::Result;
use oo7::{dbus::ServiceError, Key};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zbus::{
    interface, proxy,
    zvariant::{
        DeserializeDict, NoneValue, Optional, OwnedObjectPath, OwnedValue, SerializeDict, Type,
        Value,
    },
};

use crate::{
    gnome::secret_exchange,
    prompt::{Prompt, PromptRole},
    service::Service,
};

#[derive(Debug, DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
// GcrPrompt properties: https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-prompt.c#L95
// This struct causes "Unexpected non-0 padding byte `1`" error.
// Use properties: HashMap<&str, OwnedValue> to avoid this.
pub struct Properties {
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
    fn for_lock(object: &str, window_id: &str) -> Self {
        Self {
            title: None,
            message: Some("Lock Keyring".to_owned()),
            description: Some(format!("Confirm locking '{}' Keyring", object)),
            warning: None,
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: Some(window_id.to_owned()),
            continue_label: Some("Lock".to_owned()),
            cancel_label: Some("Cancel".to_owned()),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
// Possible values for PromptReady reply parameter
pub enum Reply {
    No,
    Yes,
}

impl NoneValue for Reply {
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
// Possible values for PerformPrompt type parameter
pub enum PromptType {
    Confirm,
    Password,
}

// org.gnome.keyring.internal.Prompter

#[proxy(
    default_service = "org.gnome.keyring.SystemPrompter",
    interface = "org.gnome.keyring.internal.Prompter",
    default_path = "/org/gnome/keyring/Prompter"
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

// org.gnome.keyring.internal.Prompter.Callback

pub struct PrompterCallback {
    window_id: String,
    private_key: Key,
    public_key: Key,
    aes_key: RwLock<Option<Key>>,
    exchange: RwLock<String>,
    service: Service,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: Optional<Reply>,
        _properties: Properties,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), ServiceError> {
        let Some(prompt) = self.service.prompt(&self.prompt_path).await else {
            return Err(ServiceError::NoSuchObject(
                "Prompt does not exist.".to_string(),
            ));
        };

        let prompt_role = prompt.role();
        match prompt_role {
            PromptRole::Lock => {
                self.prompt(
                    prompt_role,
                    reply,
                    exchange,
                    connection.clone(),
                    prompt.path().clone(),
                    prompt.objects().to_owned(),
                )
                .await?;
            }
            PromptRole::Unlock => todo!(),
            PromptRole::CreateCollection => todo!(),
        };

        Ok(())
    }

    pub async fn prompt_done(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        if let Some(prompt) = self.service.prompt(&self.prompt_path).await {
            let path = prompt.path();
            object_server.remove::<Prompt, _>(path).await?;
            self.service.remove_prompt(path).await;
        }
        object_server.remove::<Self, _>(&self.path).await?;

        Ok(())
    }
}

impl PrompterCallback {
    pub async fn new(
        window_id: &str,
        service: Service,
        prompt_path: OwnedObjectPath,
    ) -> Result<Self, oo7::crypto::Error> {
        let index = service.prompt_index().await;
        let private_key = Key::generate_private_key()?;
        Ok(Self {
            window_id: window_id.to_owned(),
            public_key: crate::gnome::crypto::generate_public_key(&private_key)?,
            aes_key: Default::default(),
            exchange: Default::default(),
            path: OwnedObjectPath::try_from(format!("/org/gnome/keyring/Prompt/p{index}")).unwrap(),
            private_key,
            service,
            prompt_path,
        })
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }

    pub async fn object_label(&self, objects: &Vec<OwnedObjectPath>) -> Option<String> {
        for object in objects {
            if let Some(collection) = self.service.collection_from_path(object).await {
                return Some(collection.label().await);
            } else if let Some(item) = self.service.item_from_path(object).await {
                return Some(item.label().await);
            }
        }
        None
    }

    // Wrappers around PrompterProxy methods
    pub async fn begin_prompting(
        connection: zbus::Connection,
        path: OwnedObjectPath,
    ) -> Result<(), ServiceError> {
        let prompter = PrompterProxy::new(&connection).await?;
        prompter.begin_prompting(&path).await?;
        Ok(())
    }

    pub async fn perform_prompt(
        connection: zbus::Connection,
        path: OwnedObjectPath,
        prompt_type: PromptType,
        properties: Properties,
        exchange: String,
    ) -> Result<(), ServiceError> {
        let prompter = PrompterProxy::new(&connection).await?;
        prompter
            .perform_prompt(path, prompt_type, properties, &exchange)
            .await?;

        Ok(())
    }

    pub async fn stop_prompting(
        connection: zbus::Connection,
        path: OwnedObjectPath,
    ) -> Result<(), ServiceError> {
        let prompter = PrompterProxy::new(&connection).await?;
        prompter.stop_prompting(path).await?;

        Ok(())
    }

    pub async fn prompt_completed(
        signal_emitter: zbus::object_server::SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> Result<(), ServiceError> {
        Prompt::completed(&signal_emitter, dismissed, result).await?;
        tracing::debug!("Prompt completed.");

        Ok(())
    }

    pub async fn prompt(
        &self,
        prompt_role: PromptRole,
        reply: Optional<Reply>,
        exchange: &str,
        connection: zbus::Connection,
        prompt_path: OwnedObjectPath,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(), ServiceError> {
        match *reply {
            Some(Reply::No) => {
                // Second PromptReady call and the prompt is dismissed
                tracing::debug!("Prompt is being dismissed.");

                tokio::spawn(PrompterCallback::stop_prompting(
                    connection,
                    self.path.clone(),
                ));

                let signal_emitter = self.service.signal_emitter(prompt_path)?;
                let result = Value::new::<Vec<OwnedObjectPath>>(vec![])
                    .try_to_owned()
                    .unwrap();

                tokio::spawn(PrompterCallback::prompt_completed(
                    signal_emitter,
                    true,
                    result,
                ));
            }
            Some(Reply::Yes) => {
                // Second PromptReady call with the final exchange
                match prompt_role {
                    PromptRole::Lock => {
                        let service = self.service.clone();
                        let objects = objects.clone();

                        tokio::spawn(async move {
                            let _ = service.set_locked(true, &objects, true).await;
                        });
                    }
                    PromptRole::Unlock => todo!(),
                    PromptRole::CreateCollection => todo!(),
                }

                tokio::spawn(PrompterCallback::stop_prompting(
                    connection,
                    self.path.clone(),
                ));

                let signal_emitter = self.service.signal_emitter(prompt_path)?;
                let result = Value::new(objects).try_to_owned().unwrap();

                tokio::spawn(PrompterCallback::prompt_completed(
                    signal_emitter,
                    false,
                    result,
                ));
            }
            None => {
                // First PromptReady call
                let server_exchange = secret_exchange::begin(&self.public_key);
                *self.exchange.write().await = server_exchange.clone();

                let label = self.object_label(&objects).await.unwrap_or(String::new());
                let path = self.path.clone();

                let (properties, prompt_type) = match prompt_role {
                    PromptRole::Lock => (
                        Properties::for_lock(&label, &self.window_id),
                        PromptType::Confirm,
                    ),
                    PromptRole::Unlock => todo!(),
                    PromptRole::CreateCollection => todo!(),
                };

                tokio::spawn(PrompterCallback::perform_prompt(
                    connection.clone(),
                    path,
                    prompt_type,
                    properties,
                    server_exchange,
                ));
            }
        }

        Ok(())
    }
}
