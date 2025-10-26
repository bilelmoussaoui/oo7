use std::sync::Arc;

use gettextrs::gettext;
use oo7::{Key, ashpd::WindowIdentifierType, dbus::ServiceError};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use zbus::zvariant::{
    self, ObjectPath, Optional, OwnedObjectPath, Type, Value, as_value, serialized::Context,
    to_bytes,
};

use super::secret_exchange;
use crate::{
    error::custom_service_error,
    i18n::i18n_f,
    prompt::{Prompt, PromptRole},
    service::Service,
};

/// Custom serde module to handle GCR's double-Value wrapping bug
///
/// See: https://gitlab.gnome.org/GNOME/gcr/-/merge_requests/169
mod double_value_optional {
    use serde::ser::SerializeStruct;
    use zvariant::DynamicType;

    use super::*;

    struct DoubleValueSerialize<'a, T: Type + serde::Serialize + DynamicType>(pub &'a Option<T>);

    impl<T: Type + serde::Serialize + DynamicType> serde::Serialize for DoubleValueSerialize<'_, T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self.0 {
                Some(v) => {
                    struct InnerVariant<'a, U: Type + serde::Serialize + DynamicType>(&'a U);

                    impl<U: Type + serde::Serialize + DynamicType> serde::Serialize for InnerVariant<'_, U> {
                        fn serialize<S2>(&self, serializer: S2) -> Result<S2::Ok, S2::Error>
                        where
                            S2: serde::Serializer,
                        {
                            // Serialize as a Variant containing the value
                            let mut inner_structure = serializer.serialize_struct("Variant", 2)?;
                            let sig = self.0.signature().to_string();
                            inner_structure.serialize_field("signature", &sig)?;
                            inner_structure.serialize_field("value", self.0)?;
                            inner_structure.end()
                        }
                    }

                    let mut outer_structure = serializer.serialize_struct("Variant", 2)?;
                    outer_structure.serialize_field("signature", "v")?;
                    outer_structure.serialize_field("value", &InnerVariant(v))?;
                    outer_structure.end()
                }
                None => serializer.serialize_none(),
            }
        }
    }

    pub fn serialize<S, T>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: serde::Serialize + zvariant::Type + DynamicType,
    {
        DoubleValueSerialize(value).serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: TryFrom<Value<'de>> + zvariant::Type,
        T::Error: std::fmt::Display,
    {
        let outer_value = Value::deserialize(deserializer)?;

        // Try to downcast to check if it's double-wrapped
        let value_to_deserialize = match outer_value.downcast_ref::<Value>() {
            Ok(_) => outer_value.downcast::<Value>().map_err(|e| {
                serde::de::Error::custom(format!("Failed to unwrap double-wrapped Value: {e}"))
            })?,
            Err(_) => outer_value,
        };

        match T::try_from(value_to_deserialize) {
            Ok(val) => Ok(Some(val)),
            Err(_) => Ok(None),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Type, Default)]
#[zvariant(signature = "dict")]
#[serde(rename_all = "kebab-case")]
// GcrPrompt properties <https://gitlab.gnome.org/GNOME/gcr/-/blob/main/gcr/gcr-prompt.c#L95>
pub struct Properties {
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    title: Option<String>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    message: Option<String>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    description: Option<String>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    warning: Option<String>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    password_new: Option<bool>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    password_strength: Option<i32>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    choice_label: Option<String>,
    #[serde(
        with = "double_value_optional",
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
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    continue_label: Option<String>,
    #[serde(
        with = "double_value_optional",
        skip_serializing_if = "Option::is_none",
        default
    )]
    cancel_label: Option<String>,
}

impl Properties {
    fn for_lock(keyring: &str, window_id: Option<&WindowIdentifierType>) -> Self {
        Self {
            title: None,
            message: Some(gettext("Lock Keyring")),
            description: Some(i18n_f("Confirm locking '{}' Keyring", &[keyring])),
            warning: None,
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some(gettext("Lock")),
            cancel_label: Some(gettext("Cancel")),
        }
    }

    fn for_unlock(
        keyring: &str,
        warning: Option<&str>,
        window_id: Option<&WindowIdentifierType>,
    ) -> Self {
        Self {
            title: Some(gettext("Unlock Keyring")),
            message: Some(gettext("Authentication required")),
            description: Some(i18n_f(
                "An application wants access to the keyring '{}', but it is locked",
                &[keyring],
            )),
            warning: warning.map(ToOwned::to_owned),
            password_new: None,
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some(gettext("Unlock")),
            cancel_label: Some(gettext("Cancel")),
        }
    }

    fn for_create_collection(label: &str, window_id: Option<&WindowIdentifierType>) -> Self {
        Self {
            title: Some(gettext("New Keyring Password")),
            message: Some(gettext("Choose password for new keyring")),
            description: Some(i18n_f(
                "An application wants to create a new keyring called '{}'. Choose the password you want to use for it.",
                &[label],
            )),
            warning: None,
            password_new: Some(true),
            password_strength: None,
            choice_label: None,
            choice_chosen: None,
            caller_window: window_id.map(ToOwned::to_owned),
            continue_label: Some(gettext("Create")),
            cancel_label: Some(gettext("Cancel")),
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

        let label = prompt.label();
        let (properties, prompt_type) = match prompt.role() {
            PromptRole::Lock => (
                Properties::for_lock(label, self.window_id.as_ref()),
                PromptType::Confirm,
            ),
            PromptRole::Unlock => (
                Properties::for_unlock(label, None, self.window_id.as_ref()),
                PromptType::Password,
            ),
            PromptRole::CreateCollection => (
                Properties::for_create_collection(label, self.window_id.as_ref()),
                PromptType::Password,
            ),
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

        // Handle each role differently based on what validation/preparation is needed
        match prompt.role() {
            PromptRole::Lock => {
                let Some(action) = prompt.take_action().await else {
                    return Err(custom_service_error(
                        "Prompt action was already executed or not set",
                    ));
                };

                let result_value = action.execute(None).await?;

                let path = self.path.clone();
                let prompt_path = OwnedObjectPath::from(prompt.path().clone());
                tokio::spawn(async move { prompter.stop_prompting(&path).await });

                let signal_emitter = self.service.signal_emitter(prompt_path)?;
                tokio::spawn(async move {
                    tracing::debug!("Lock prompt completed.");
                    let _ = Prompt::completed(&signal_emitter, false, result_value).await;
                });
                Ok(())
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

                // Get the collection to validate the secret
                let collection = prompt.collection().expect("Unlock requires a collection");
                let label = prompt.label();

                // Validate the secret using the already-open keyring
                let keyring_guard = collection.keyring.read().await;
                let is_valid = keyring_guard
                    .as_ref()
                    .unwrap()
                    .validate_secret(&secret)
                    .await
                    .map_err(|err| {
                        custom_service_error(&format!(
                            "Failed to validate secret for {label} keyring: {err}."
                        ))
                    })?;
                drop(keyring_guard);

                if is_valid {
                    tracing::debug!("Keyring secret matches for {label}.");

                    let Some(action) = prompt.take_action().await else {
                        return Err(custom_service_error(
                            "Prompt action was already executed or not set",
                        ));
                    };

                    // Execute the unlock action after successful validation
                    let result_value = action.execute(Some(secret)).await?;

                    let path = self.path.clone();
                    let prompt_path = OwnedObjectPath::from(prompt.path().clone());
                    tokio::spawn(async move { prompter.stop_prompting(&path).await });

                    let signal_emitter = self.service.signal_emitter(prompt_path)?;
                    tokio::spawn(async move {
                        tracing::debug!("Unlock prompt completed.");
                        let _ = Prompt::completed(&signal_emitter, false, result_value).await;
                    });
                    Ok(())
                } else {
                    tracing::error!("Keyring {label} failed to unlock, incorrect secret.");
                    let properties = Properties::for_unlock(
                        label,
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

                    Ok(())
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

                let Some(action) = prompt.take_action().await else {
                    return Err(custom_service_error(
                        "Prompt action was already executed or not set",
                    ));
                };

                // Execute the collection creation action with the secret
                match action.execute(Some(secret)).await {
                    Ok(collection_path_value) => {
                        tracing::info!("CreateCollection action completed successfully");

                        let path = self.path.clone();
                        tokio::spawn(async move { prompter.stop_prompting(&path).await });

                        let signal_emitter =
                            self.service.signal_emitter(prompt.path().to_owned())?;

                        tokio::spawn(async move {
                            tracing::debug!("CreateCollection prompt completed.");
                            let _ =
                                Prompt::completed(&signal_emitter, false, collection_path_value)
                                    .await;
                        });
                        Ok(())
                    }
                    Err(err) => Err(custom_service_error(&format!(
                        "Failed to create collection: {err}."
                    ))),
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zvariant::{serialized::Context, to_bytes};

    use super::*;

    #[test]
    fn properties_serialization_roundtrip() {
        let props = Properties {
            title: Some("Test Title".to_string()),
            message: Some("Test Message".to_string()),
            ..Default::default()
        };

        // Serialize to bytes
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = to_bytes(ctxt, &props).expect("Failed to serialize");

        // Deserialize back to verify roundtrip works
        let decoded: Properties = encoded.deserialize().unwrap().0;

        assert_eq!(decoded.title, Some("Test Title".to_string()));
        assert_eq!(decoded.message, Some("Test Message".to_string()));
    }

    #[test]
    fn deserialize_properties() {
        let mut map: HashMap<String, Value> = HashMap::new();

        // Double-wrap: Value<Value<String>>
        map.insert(
            "title".to_string(),
            Value::new(Value::new("Unlock Keyring")),
        );

        map.insert(
            "message".to_string(),
            Value::new(Value::new("Authentication required")),
        );

        // Serialize the HashMap
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = to_bytes(ctxt, &map).expect("Failed to serialize test data");

        // Deserialize as Properties
        let props: Properties = encoded.deserialize().unwrap().0;

        assert_eq!(props.title, Some("Unlock Keyring".to_string()));
        assert_eq!(props.message, Some("Authentication required".to_string()));

        let mut map: HashMap<String, Value> = HashMap::new();

        // Single-wrap: Value<String> (the correct format)
        map.insert("title".to_string(), Value::new("Unlock Keyring"));
        map.insert("message".to_string(), Value::new("Authentication required"));

        // Serialize the HashMap
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = to_bytes(ctxt, &map).expect("Failed to serialize test data");

        // Deserialize as Properties - should also work
        let props: Properties = encoded.deserialize().unwrap().0;

        assert_eq!(props.title, Some("Unlock Keyring".to_string()));
        assert_eq!(props.message, Some("Authentication required".to_string()));

        let props = Properties {
            title: None,
            message: Some("Test".to_string()),
            ..Default::default()
        };

        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = to_bytes(ctxt, &props).expect("Failed to serialize");
        let decoded: Properties = encoded.deserialize().unwrap().0;

        assert_eq!(decoded.title, None);
        assert_eq!(decoded.message, Some("Test".to_string()));

        let props = Properties {
            password_new: Some(true),
            password_strength: Some(42),
            choice_chosen: Some(false),
            ..Default::default()
        };

        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let encoded = to_bytes(ctxt, &props).expect("Failed to serialize");
        let decoded: Properties = encoded.deserialize().unwrap().0;

        assert_eq!(decoded.password_new, Some(true));
        assert_eq!(decoded.password_strength, Some(42));
        assert_eq!(decoded.choice_chosen, Some(false));
    }
}
