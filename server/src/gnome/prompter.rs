use std::sync::Arc;

use oo7::{Key, ashpd::WindowIdentifierType, dbus::ServiceError};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use zbus::zvariant::{self, ObjectPath, Optional, OwnedObjectPath, Type, as_value};

use super::secret_exchange;
use crate::{
    error::custom_service_error,
    prompt::{Prompt, PromptRole},
    service::Service,
};

#[derive(Debug, Serialize, Deserialize, Type, Default)]
#[zvariant(signature = "dict")]
#[serde(rename_all = "kebab-case")]
// GcrPrompt properties <https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-prompt.c#L95>
// This would fail to serialize till <https://gitlab.gnome.org/GNOME/gcr/-/merge_requests/169>
// is resolved.
pub struct Properties {
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    title: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    message: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    description: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    warning: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    password_new: Option<bool>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    password_strength: Option<u32>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    choice_label: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    choice_chosen: Option<bool>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    caller_window: Option<WindowIdentifierType>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    continue_label: Option<String>,
    #[serde(
        with = "as_value::optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    cancel_label: Option<String>,
}

impl Properties {
    fn for_lock(keyring: &str, window_id: Option<&WindowIdentifierType>) -> Self {
        Self {
            title: None,
            message: Some("Lock Keyring".to_owned()),
            description: Some(format!("Confirm locking '{keyring}' Keyring")),
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

    fn for_unlock(
        keyring: &str,
        warning: Option<&str>,
        window_id: Option<&WindowIdentifierType>,
    ) -> Self {
        Self {
            title: Some("Unlock Keyring".to_owned()),
            message: Some("Authentication required".to_owned()),
            description: Some(format!(
                "An application wants access to the keyring '{keyring}', but it is locked"
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

    fn for_create_collection(label: &str, window_id: Option<&WindowIdentifierType>) -> Self {
        Self {
            title: Some("New Keyring Password".to_owned()),
            message: Some("Choose password for new keyring".to_owned()),
            description: Some(format!(
                "An application wants to create a new keyring called '{label}'. Choose the password you want to use for it."
            )),
            warning: None,
            password_new: Some(true),
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some("Create".to_owned()),
            cancel_label: Some("Cancel".to_owned()),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Type)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
pub enum Reply {
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

#[derive(Deserialize, Serialize, Debug, Type, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
#[zvariant(signature = "s")]
pub enum PromptType {
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
    fn begin_prompting(&self, callback: &ObjectPath<'_>) -> Result<(), ServiceError>;

    fn perform_prompt(
        &self,
        callback: &ObjectPath<'_>,
        type_: PromptType,
        properties: Properties,
        exchange: &str,
    ) -> Result<(), ServiceError>;

    fn stop_prompting(&self, callback: &ObjectPath<'_>) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone)]
pub struct PrompterCallback {
    window_id: Option<WindowIdentifierType>,
    private_key: Arc<Key>,
    public_key: Arc<Key>,
    exchange: OnceCell<String>,
    service: Service,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: Optional<Reply>,
        _properties: Properties,
        exchange: &str,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), ServiceError> {
        let prompt_path = &self.prompt_path;
        let Some(prompt) = self.service.prompt(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Prompt '{prompt_path}' does not exist."
            )));
        };

        match *reply {
            // First PromptReady call
            None => {
                self.prompter_init(&prompt).await?;
            }
            // Second PromptReady call with final exchange
            Some(Reply::Yes) => {
                self.prompter_done(&prompt, exchange).await?;
            }
            // Dismissed prompt
            Some(Reply::No) => {
                self.prompter_dismissed(prompt.path().clone().into())
                    .await?;
            }
        };
        Ok(())
    }

    async fn prompt_done(&self) -> Result<(), ServiceError> {
        // This is only does check if the prompt is tracked on Service
        let path = &self.prompt_path;
        if let Some(prompt) = self.service.prompt(path).await {
            self.service
                .object_server()
                .remove::<Prompt, _>(path)
                .await?;
            self.service.remove_prompt(path).await;
        }
        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;

        Ok(())
    }
}

impl PrompterCallback {
    pub async fn new(
        window_id: Option<WindowIdentifierType>,
        service: Service,
        prompt_path: OwnedObjectPath,
    ) -> Result<Self, oo7::crypto::Error> {
        let index = service.prompt_index().await;
        let private_key = Arc::new(Key::generate_private_key()?);
        let public_key = Arc::new(crate::gnome::crypto::generate_public_key(&private_key)?);
        Ok(Self {
            window_id,
            public_key,
            private_key,
            exchange: Default::default(),
            path: OwnedObjectPath::try_from(format!("/org/gnome/keyring/Prompt/p{index}")).unwrap(),
            service,
            prompt_path,
        })
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    async fn prompter_init(&self, prompt: &Prompt) -> Result<(), ServiceError> {
        let connection = self.service.connection();
        let exchange = secret_exchange::begin(&self.public_key);
        self.exchange.set(exchange).unwrap();

        let (properties, prompt_type) = match prompt.role() {
            PromptRole::Lock => {
                let label = self
                    .object_label(prompt.objects())
                    .await
                    .unwrap_or_default();
                (
                    Properties::for_lock(&label, self.window_id.as_ref()),
                    PromptType::Confirm,
                )
            }
            PromptRole::Unlock => {
                let label = self
                    .object_label(prompt.objects())
                    .await
                    .unwrap_or_default();
                (
                    Properties::for_unlock(&label, None, self.window_id.as_ref()),
                    PromptType::Password,
                )
            }
            PromptRole::CreateCollection => {
                // Get the collection label from pending collections
                let label = self
                    .service
                    .pending_collection(&self.prompt_path)
                    .await
                    .map(|(label, _alias)| label)
                    .unwrap_or_default();

                (
                    Properties::for_create_collection(&label, self.window_id.as_ref()),
                    PromptType::Password,
                )
            }
        };

        let prompter = PrompterProxy::new(connection).await?;
        let path = self.path.clone();
        let exchange = self.exchange.get().unwrap().clone();
        tokio::spawn(async move {
            prompter
                .perform_prompt(&path, prompt_type, properties, &exchange)
                .await
        });
        Ok(())
    }

    async fn prompter_done(&self, prompt: &Prompt, exchange: &str) -> Result<(), ServiceError> {
        let prompter = PrompterProxy::new(self.service.connection()).await?;

        match prompt.role() {
            PromptRole::Lock => {
                let label = self
                    .object_label(prompt.objects())
                    .await
                    .unwrap_or_default();

                let service = self.service.clone();
                let objects = prompt.objects().to_owned();
                tokio::spawn(async move {
                    let _ = service.set_locked(true, &objects, true).await;
                });
            }
            PromptRole::Unlock => {
                let aes_key =
                    secret_exchange::handshake(&self.private_key, exchange).map_err(|err| {
                        custom_service_error(&format!(
                            "Failed to generate AES key for SecretExchange {err}."
                        ))
                    })?;

                let Some(secret) = secret_exchange::retrieve(exchange, &aes_key) else {
                    return Err(custom_service_error(
                        "Failed to retrieve keyring secret from SecretExchange.",
                    ));
                };
                let label = self
                    .object_label(prompt.objects())
                    .await
                    .unwrap_or_default();

                // TODO: this should check if the service has a keyring, check the secret
                // without opening it again.
                match oo7::file::Keyring::open(&label, secret).await {
                    Ok(_) => {
                        tracing::debug!("Keyring secret matches for {label}.");
                        // Unlock the collection after successful validation
                        let service = self.service.clone();
                        let objects = prompt.objects().to_owned();
                        tokio::spawn(async move {
                            let _ = service.set_locked(false, &objects, true).await;
                        });
                    }
                    Err(oo7::file::Error::IncorrectSecret) => {
                        tracing::error!("Keyring {label} failed to unlock, incorrect secret.");
                        let properties = Properties::for_unlock(
                            &label,
                            Some("The unlock password was incorrect"),
                            self.window_id.as_ref(),
                        );
                        let server_exchange = self
                            .exchange
                            .get()
                            .expect("Exchange cannot be empty at this stage")
                            .clone();
                        let path = self.path.clone();

                        tokio::spawn(async move {
                            prompter
                                .perform_prompt(
                                    &path,
                                    PromptType::Password,
                                    properties,
                                    &server_exchange,
                                )
                                .await
                        });

                        return Ok(());
                    }
                    Err(err) => {
                        return Err(custom_service_error(&format!(
                            "Failed to unlock {label} keyring: {err}."
                        )));
                    }
                }
            }
            PromptRole::CreateCollection => {
                // Compute AES key from client's public key in the final exchange
                let aes_key =
                    secret_exchange::handshake(&self.private_key, exchange).map_err(|err| {
                        custom_service_error(&format!(
                            "Failed to generate AES key for SecretExchange {err}."
                        ))
                    })?;

                let Some(secret) = secret_exchange::retrieve(exchange, &aes_key) else {
                    return Err(custom_service_error(
                        "Failed to retrieve keyring secret from SecretExchange.",
                    ));
                };

                // Create the collection with the provided secret
                let service = self.service.clone();

                match service
                    .complete_collection_creation(prompt.path(), secret)
                    .await
                {
                    Ok(collection_path) => {
                        tracing::info!("Collection created at: {}", collection_path);

                        let path = self.path.clone();
                        tokio::spawn(async move { prompter.stop_prompting(&path).await });

                        let signal_emitter =
                            self.service.signal_emitter(prompt.path().to_owned())?;
                        let result = zvariant::Value::new(collection_path)
                            .try_into_owned()
                            .unwrap();

                        tokio::spawn(async move {
                            tracing::debug!("CreateCollection prompt completed.");
                            Prompt::completed(&signal_emitter, false, result).await
                        });
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(custom_service_error(&format!(
                            "Failed to create collection: {err}."
                        )));
                    }
                }
            }
        }

        let path = self.path.clone();
        let prompt_path = OwnedObjectPath::from(prompt.path().clone());
        tokio::spawn(async move { prompter.stop_prompting(&path).await });

        let signal_emitter = self.service.signal_emitter(prompt_path)?;
        let result = zvariant::Value::new(prompt.objects())
            .try_into_owned()
            .unwrap();

        tokio::spawn(async move {
            tracing::debug!("Prompt completed.");
            Prompt::completed(&signal_emitter, false, result).await
        });
        Ok(())
    }

    async fn object_label(&self, objects: &[OwnedObjectPath]) -> Option<String> {
        debug_assert!(!objects.is_empty());
        // If at least one of the items is a Collection
        for object in objects {
            if let Some(collection) = self.service.collection_from_path(object).await {
                return Some(collection.label().await);
            }
        }
        // Get the collection path from the first item in the keyring as you cannot
        // unlock items from different collections I guess?
        let path = objects
            .first()
            .unwrap()
            .as_str()
            .rsplit_once('/')
            .map(|(parent, _)| parent)?;
        let collection = self
            .service
            .collection_from_path(&ObjectPath::try_from(path).unwrap())
            .await?;

        Some(collection.label().await)
    }

    async fn prompter_dismissed(&self, prompt_path: OwnedObjectPath) -> Result<(), ServiceError> {
        let path = self.path.clone();
        let prompter = PrompterProxy::new(self.service.connection()).await?;

        tokio::spawn(async move { prompter.stop_prompting(&path).await });
        let signal_emitter = self.service.signal_emitter(prompt_path)?;
        let result = zvariant::Value::new::<Vec<OwnedObjectPath>>(vec![])
            .try_into_owned()
            .unwrap();

        tokio::spawn(async move { Prompt::completed(&signal_emitter, true, result).await });
        Ok(())
    }
}
