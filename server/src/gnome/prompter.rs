// org.gnome.keyring.Prompter
// https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/org.gnome.keyring.Prompter.xml

use clap::error::Result;
use oo7::{dbus::ServiceError, Key};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zbus::{
    interface, proxy,
    zvariant::{DeserializeDict, NoneValue, Optional, OwnedObjectPath, SerializeDict, Type, Value},
};

use crate::{
    gnome::secret_exchange,
    prompt::{Prompt, PromptRole},
    service::Service,
};

#[derive(Debug, DeserializeDict, SerializeDict, Type)]
#[zvariant(signature = "dict")]
// GcrPrompt properties: https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-prompt.c#L95
pub struct Properties {
    title: Option<String>,
    message: Option<String>,
    description: Option<String>,
    warning: Option<String>,
    #[zvariant(rename = "password-new")]
    password_new: Option<bool>,
    #[zvariant(rename = "password-strength")]
    password_strength: Option<i32>,
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

    fn for_unlock(object: &str, warning: &str, window_id: &str) -> Self {
        Self {
            title: Some("Unlock Keyring".to_owned()),
            message: Some("Authentication required".to_owned()),
            description: Some(format!(
                "An application wants access to the keyring '{}', but it is locked",
                object
            )),
            warning: Some(warning.to_owned()),
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: Some(window_id.to_owned()),
            continue_label: Some("Unlock".to_owned()),
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

#[derive(Debug)]
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

        let prompter = PrompterProxy::new(connection).await?;
        let path = self.path.clone();
        let prompt_role = prompt.role();
        let prompt_path = prompt.path().clone();
        let prompt_objects = prompt.objects().to_owned();

        match *reply {
            Some(Reply::No) => {
                // Second PromptReady call and the prompt is dismissed
                tracing::debug!("Prompt is being dismissed.");

                tokio::spawn(async move { prompter.stop_prompting(path).await });

                let signal_emitter = self.service.signal_emitter(prompt_path)?;
                let result = Value::new::<Vec<OwnedObjectPath>>(vec![])
                    .try_to_owned()
                    .unwrap();

                tokio::spawn(async move { Prompt::completed(&signal_emitter, true, result).await });
            }
            Some(Reply::Yes) => {
                // Second PromptReady call with the final exchange
                let label = self
                    .object_label(&prompt_objects)
                    .await
                    .unwrap_or(String::new());

                match prompt_role {
                    PromptRole::Lock => {
                        let service = self.service.clone();
                        let objects = prompt_objects.clone();

                        tokio::spawn(async move {
                            let _ = service.set_locked(true, &objects, true).await;
                        });
                    }
                    PromptRole::Unlock => {
                        let Some(aes_key) = &*self.aes_key.read().await else {
                            return Err(ServiceError::ZBus(zbus::Error::FDO(Box::new(
                                zbus::fdo::Error::Failed(
                                    "Failed to retrieve AES key for SecretExchange.".to_string(),
                                ),
                            ))));
                        };

                        // Verify the secret
                        if let Some(secret) = secret_exchange::retrieve(exchange, aes_key) {
                            match oo7::file::Keyring::open(&label, secret).await {
                                Ok(_) => {
                                    tracing::debug!("{} keyring secret matches.", &label);
                                }
                                Err(oo7::file::Error::IncorrectSecret) => {
                                    tracing::error!("{} keyring incorrect secret.", &label);

                                    let properties = Properties::for_unlock(
                                        &label,
                                        "The unlock password was incorrect",
                                        &self.window_id,
                                    );
                                    let server_exchange = self.exchange.read().await.clone();

                                    tokio::spawn(async move {
                                        prompter
                                            .perform_prompt(
                                                path,
                                                PromptType::Password,
                                                properties,
                                                &server_exchange,
                                            )
                                            .await
                                    });

                                    return Ok(());
                                }
                                Err(err) => {
                                    return Err(ServiceError::ZBus(zbus::Error::FDO(Box::new(
                                        zbus::fdo::Error::Failed(format!(
                                            "Failed to unlock {label} Keyring: {err}."
                                        )),
                                    ))))
                                }
                            }
                        }

                        let service = self.service.clone();
                        let objects = prompt_objects.clone();

                        tokio::spawn(async move {
                            let _ = service.set_locked(false, &objects, true).await;
                        });
                    }
                    PromptRole::CreateCollection => todo!(),
                }

                tokio::spawn(async move { prompter.stop_prompting(path).await });

                let signal_emitter = self.service.signal_emitter(prompt_path)?;
                let result = Value::new(prompt_objects).try_to_owned().unwrap();

                tokio::spawn(async move {
                    tracing::debug!("Prompt completed.");
                    Prompt::completed(&signal_emitter, false, result).await
                });
            }
            None => {
                // First PromptReady call
                let server_exchange = secret_exchange::begin(&self.public_key);
                *self.exchange.write().await = server_exchange.clone();

                let label = self
                    .object_label(&prompt_objects)
                    .await
                    .unwrap_or(String::new());
                let path = self.path.clone();

                let (properties, prompt_type) = match prompt_role {
                    PromptRole::Lock => (
                        Properties::for_lock(&label, &self.window_id),
                        PromptType::Confirm,
                    ),
                    PromptRole::Unlock => {
                        let aes_key = secret_exchange::handshake(&self.private_key, exchange)
                            .map_err(|err| {
                                ServiceError::ZBus(zbus::Error::FDO(Box::new(
                                    zbus::fdo::Error::Failed(format!(
                                        "Failed to generate AES key for SecretExchange {err}."
                                    )),
                                )))
                            })?;
                        *self.aes_key.write().await = Some(aes_key);

                        (
                            Properties::for_unlock(&label, "", &self.window_id),
                            PromptType::Password,
                        )
                    }
                    PromptRole::CreateCollection => todo!(),
                };

                tokio::spawn(async move {
                    prompter
                        .perform_prompt(path, prompt_type, properties, &server_exchange)
                        .await
                });
            }
        }
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
}
