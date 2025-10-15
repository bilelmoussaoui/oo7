// org.freedesktop.Secret.Prompt

use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

use oo7::{Secret, dbus::ServiceError};
use tokio::sync::{Mutex, OnceCell};
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue},
};

use crate::{
    error::custom_service_error,
    gnome::prompter::{PrompterCallback, PrompterProxy},
    service::Service,
};

#[derive(Debug, Clone, Copy)]
pub enum PromptRole {
    Lock,
    Unlock,
    CreateCollection,
}

/// A boxed future that represents the action to be taken when a prompt
/// completes
pub type PromptActionFuture =
    Pin<Box<dyn Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static>>;

/// Represents the action to be taken when a prompt completes
/// The secret is optional because Lock prompts don't require secret validation
pub struct PromptAction {
    /// The async function to execute when the prompt is accepted
    action: Box<dyn FnOnce(Option<Secret>) -> PromptActionFuture + Send>,
}

impl PromptAction {
    /// Create a new prompt action from a closure that takes an optional secret
    /// and returns a future
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: FnOnce(Option<Secret>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static,
    {
        Self {
            action: Box::new(move |secret| Box::pin(f(secret))),
        }
    }

    /// Execute the action with the provided secret (None for Lock operations)
    pub async fn execute(self, secret: Option<Secret>) -> Result<OwnedValue, ServiceError> {
        (self.action)(secret).await
    }
}

#[derive(Clone)]
pub struct Prompt {
    service: Service,
    role: PromptRole,
    path: OwnedObjectPath,
    /// The label of the collection/keyring being prompted for
    label: String,
    /// The collection for Unlock prompts (needed for secret validation)
    collection: Option<crate::collection::Collection>,
    /// GNOME Specific
    callback: Arc<OnceCell<PrompterCallback>>,
    /// The action to execute when the prompt completes
    action: Arc<Mutex<Option<PromptAction>>>,
}

// Manual impl because OnceCell doesn't impl Debug
impl std::fmt::Debug for Prompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prompt")
            .field("service", &self.service)
            .field("role", &self.role)
            .field("path", &self.path)
            .field("label", &self.label)
            .field("collection", &self.collection)
            .finish()
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(&self, window_id: Optional<&str>) -> Result<(), ServiceError> {
        if self.callback.get().is_some() {
            return Err(custom_service_error(
                "A prompt callback is ongoing already.",
            ));
        };

        let callback = PrompterCallback::new(
            (*window_id).and_then(|w| ashpd::WindowIdentifierType::from_str(w).ok()),
            self.service.clone(),
            self.path.clone(),
        )
        .await
        .map_err(|err| {
            custom_service_error(&format!("Failed to create PrompterCallback {err}."))
        })?;

        let path = OwnedObjectPath::from(callback.path().clone());

        self.callback
            .set(callback.clone())
            .expect("A prompt callback is only set once");

        self.service.object_server().at(&path, callback).await?;
        tracing::debug!("Prompt `{}` created.", self.path);

        // Starts GNOME System Prompting.
        // Spawned separately to avoid blocking the early return of the current
        // execution.
        let prompter = PrompterProxy::new(self.service.connection()).await?;
        tokio::spawn(async move { prompter.begin_prompting(&path).await });

        Ok(())
    }

    pub async fn dismiss(&self) -> Result<(), ServiceError> {
        if let Some(_callback) = self.callback.get() {
            // TODO: figure out if we should destroy the un-export the callback
            // here?
        }

        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;
        self.service.remove_prompt(&self.path).await;

        Ok(())
    }

    #[zbus(signal, name = "Completed")]
    pub async fn completed(
        signal_emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

impl Prompt {
    pub async fn new(
        service: Service,
        role: PromptRole,
        label: String,
        collection: Option<crate::collection::Collection>,
    ) -> Self {
        let index = service.prompt_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                .unwrap(),
            service,
            role,
            label,
            collection,
            callback: Default::default(),
            action: Arc::new(Mutex::new(None)),
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn role(&self) -> PromptRole {
        self.role
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn collection(&self) -> Option<&crate::collection::Collection> {
        self.collection.as_ref()
    }

    /// Set the action to execute when the prompt completes
    pub async fn set_action(&self, action: PromptAction) {
        *self.action.lock().await = Some(action);
    }

    /// Take the action, consuming it so it can only be executed once
    pub async fn take_action(&self) -> Option<PromptAction> {
        self.action.lock().await.take()
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::TestServiceSetup;

    #[tokio::test]
    async fn prompt_called_twice_error() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Lock the collection to create a prompt scenario
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection.set_locked(true).await?;

        // Get a prompt path by calling unlock (which creates a prompt but doesn't
        // auto-trigger it)
        let (_unlocked, prompt_path) = setup
            .server
            .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
            .await?;

        // Verify we got a prompt path
        assert!(!prompt_path.is_empty(), "Should have a prompt path");

        // Create a Prompt proxy manually
        let prompt = oo7::dbus::api::Prompt::new(&setup.client_conn, prompt_path.as_ref())
            .await?
            .unwrap();

        // First call to prompt() should succeed
        prompt.prompt(None).await?;

        // Give the prompt a moment to register the callback
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Second call to prompt() should fail with "callback is ongoing already" error
        assert!(
            prompt.prompt(None).await.is_err(),
            "Second call to prompt() should fail"
        );
        Ok(())
    }

    #[tokio::test]
    async fn prompt_not_found_error() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Lock the collection to create a prompt scenario
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection.set_locked(true).await?;

        // Create a prompt using server API
        let (_unlocked, prompt_path) = setup
            .server
            .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
            .await?;

        assert!(!prompt_path.is_empty(), "Should have a prompt path");

        // Remove the prompt from the service before MockPrompter tries to process it
        setup.server.remove_prompt(&prompt_path).await;

        // Manually serve a callback to trigger the error path
        let callback = crate::gnome::prompter::PrompterCallback::new(
            None,
            setup.server.clone(),
            prompt_path.clone(),
        )
        .await?;

        let callback_path = super::OwnedObjectPath::from(callback.path().clone());
        setup
            .server
            .object_server()
            .at(&callback_path, callback.clone())
            .await?;

        // Now call prompt_ready which should fail because the prompt doesn't exist
        let result = callback
            .prompt_ready(
                zbus::zvariant::Optional::from(None),
                crate::gnome::prompter::Properties::default(),
                "",
                setup.server.connection(),
            )
            .await;

        assert!(result.is_err(), "Should fail when prompt doesn't exist");

        // Verify it's the specific error we expect
        assert!(
            matches!(result, Err(oo7::dbus::ServiceError::NoSuchObject(_))),
            "Should be NoSuchObject error"
        );

        Ok(())
    }

    #[tokio::test]
    async fn dismiss_prompt_cleanup() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestServiceSetup::plain_session(true).await?;

        // Lock the collection to create a prompt scenario
        let collection = setup
            .server
            .collection_from_path(setup.collections[0].inner().path())
            .await
            .expect("Collection should exist");
        collection.set_locked(true).await?;

        // Get a prompt path by calling unlock
        let (_unlocked, prompt_path) = setup
            .server
            .unlock(vec![setup.collections[0].inner().path().to_owned().into()])
            .await?;

        assert!(!prompt_path.is_empty(), "Should have a prompt path");

        // Verify prompt exists in service before dismissal
        let prompt_exists_before = setup.server.prompt(&prompt_path).await;
        assert!(
            prompt_exists_before.is_some(),
            "Prompt should exist in service before dismissal"
        );

        // Verify prompt is accessible via D-Bus
        let prompt = oo7::dbus::api::Prompt::new(&setup.client_conn, prompt_path.as_ref()).await?;
        assert!(
            prompt.is_some(),
            "Prompt should be accessible via D-Bus before dismissal"
        );

        // Dismiss the prompt
        prompt.unwrap().dismiss().await?;

        // Give it a moment to process the dismissal
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify prompt is removed from service
        let prompt_exists_after = setup.server.prompt(&prompt_path).await;
        assert!(
            prompt_exists_after.is_none(),
            "Prompt should be removed from service after dismissal"
        );

        Ok(())
    }
}
