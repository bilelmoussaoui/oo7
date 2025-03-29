// org.freedesktop.Secret.Prompt

use std::sync::Arc;

use oo7::dbus::ServiceError;
use tokio::sync::OnceCell;
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{Optional, OwnedObjectPath, OwnedValue},
};

use crate::{
    gnome::prompter::{PrompterCallback, PrompterProxy},
    service::Service,
};

#[derive(Debug, Clone, Copy)]
pub enum PromptRole {
    Lock,
    Unlock,
    #[allow(unused)]
    CreateCollection,
}

#[derive(Clone)]
pub struct Prompt {
    service: Service,
    // Objects to lock/unlock
    objects: Vec<OwnedObjectPath>,
    role: PromptRole,
    path: OwnedObjectPath,
    /// GNOME Specific
    callback: Arc<OnceCell<PrompterCallback>>,
}

// Manual impl because OnceCell doesn't impl Debug
impl std::fmt::Debug for Prompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prompt")
            .field("service", &self.service)
            .field("objects", &self.objects)
            .field("role", &self.role)
            .field("path", &self.path)
            .finish()
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(&self, window_id: Optional<&str>) -> Result<(), ServiceError> {
        if self.callback.get().is_some() {
            return Err(ServiceError::ZBus(zbus::Error::FDO(Box::new(
                zbus::fdo::Error::Failed(format!("A prompt callback is ongoing already.")),
            ))));
        };

        let callback = PrompterCallback::new(*window_id, self.service.clone(), self.path.clone())
            .await
            .map_err(|err| {
                ServiceError::ZBus(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                    format!("Failed to create PrompterCallback {err}."),
                ))))
            })?;

        let path = callback.path().clone();

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
    pub async fn new(service: Service, objects: Vec<OwnedObjectPath>, role: PromptRole) -> Self {
        let index = service.prompt_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                .unwrap(),
            service,
            objects,
            role,
            callback: Default::default(),
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }

    pub fn role(&self) -> PromptRole {
        self.role
    }

    pub fn objects(&self) -> &[OwnedObjectPath] {
        &self.objects
    }
}
