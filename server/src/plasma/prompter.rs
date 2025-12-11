// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

use oo7::dbus::ServiceError;

use zbus::{
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedFd, OwnedObjectPath},
};

use crate::{
    error::custom_service_error,
    prompt::{Prompt, PromptRole},
    service::Service,
};
use tokio::io::AsyncReadExt;

use std::os::fd::AsFd;

#[zbus::proxy(
    default_service = "org.kde.secretprompter",
    interface = "org.kde.secretprompter",
    default_path = "/SecretPrompter",
    gen_blocking = false
)]
pub trait PlasmaPrompter {
    fn UnlockCollectionPrompt(
        &self,
        request: &ObjectPath<'_>,
        window_id: &str,
        activation_token: &str,
        collection_name: &str,
    ) -> Result<(), ServiceError>;
    fn CreateCollectionPrompt(
        &self,
        request: &ObjectPath<'_>,
        window_id: &str,
        activation_token: &str,
        collection_name: &str,
    ) -> Result<(), ServiceError>;
}

#[derive(Debug, Clone)]
pub struct PlasmaPrompterCallback {
    service: Service,
    prompt_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.kde.secretprompter.request")]
impl PlasmaPrompterCallback {
    pub async fn accepted(&self, result_fd: OwnedFd) -> Result<i32, ServiceError> {
        let prompt_path = &self.prompt_path;
        let Some(prompt) = self.service.prompt(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "Prompt '{prompt_path}' does not exist."
            )));
        };

        tracing::debug!("User accepted the prompt.");

        let secret = {
            let borrowed_fd = result_fd.as_fd();
            let std_stream = std::os::unix::net::UnixStream::from(
                borrowed_fd
                    .try_clone_to_owned()
                    .expect("Failed to clone fd"),
            );
            let mut stream = tokio::net::UnixStream::from_std(std_stream).unwrap();
            let mut buffer = String::new();
            stream
                .read_to_string(&mut buffer)
                .await
                .expect("error reading secret");
            buffer
        };

        self.on_reply(&prompt, &secret).await
    }

    pub async fn rejected(&self) -> Result<i32, ServiceError> {
        tracing::debug!("User rejected the prompt.");
        Ok(0) // simply dismiss without further action
    }

    pub async fn dismissed(&self) -> Result<(), ServiceError> {
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

    #[zbus(signal)]
    pub async fn retry(signal_emitter: &SignalEmitter<'_>, reason: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn dismiss(signal_emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

impl PlasmaPrompterCallback {
    pub async fn new(
        service: Service,
        prompt_path: OwnedObjectPath,
    ) -> Result<Self, oo7::crypto::Error> {
        let index = service.prompt_index().await;
        Ok(Self {
            path: OwnedObjectPath::try_from(format!("/org/plasma/keyring/Prompt/p{index}"))
                .unwrap(),
            service,
            prompt_path,
        })
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    // TODO: this is largely duplicated from the gnome prompter. should be shared somehow. not sure how.
    async fn on_reply(&self, prompt: &Prompt, reply: &str) -> Result<i32, ServiceError> {
        // Handle each role differently based on what validation/preparation is needed
        match prompt.role() {
            PromptRole::Unlock => {
                let secret = oo7::Secret::from(reply);

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

                    let result_value = action.execute(secret).await?;

                    let prompt_path = OwnedObjectPath::from(prompt.path().clone());
                    let signal_emitter = self.service.signal_emitter(prompt_path)?;
                    tokio::spawn(async move {
                        tracing::debug!("Unlock prompt completed.");
                        let _ = Prompt::completed(&signal_emitter, false, result_value).await;
                    });
                    Ok(0)
                } else {
                    tracing::error!("Keyring {label} failed to unlock, incorrect secret.");

                    let emitter = SignalEmitter::from_parts(
                        self.service.connection().clone(),
                        self.path().clone(),
                    );
                    PlasmaPrompterCallback::retry(&emitter, "The unlock password was incorrect")
                        .await?;

                    Ok(1)
                }
            }
            PromptRole::CreateCollection => {
                let secret = oo7::Secret::from(reply);

                let Some(action) = prompt.take_action().await else {
                    return Err(custom_service_error(
                        "Prompt action was already executed or not set",
                    ));
                };

                // Execute the collection creation action with the secret
                match action.execute(secret).await {
                    Ok(collection_path_value) => {
                        tracing::info!("CreateCollection action completed successfully");

                        let signal_emitter =
                            self.service.signal_emitter(prompt.path().to_owned())?;

                        tokio::spawn(async move {
                            tracing::debug!("CreateCollection prompt completed.");
                            let _ =
                                Prompt::completed(&signal_emitter, false, collection_path_value)
                                    .await;
                        });
                        Ok(0)
                    }
                    Err(err) => Err(custom_service_error(&format!(
                        "Failed to create collection: {err}."
                    ))),
                }
            }
        }
    }
}
