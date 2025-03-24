// org.freedesktop.Secret.Prompt

use oo7::dbus::ServiceError;
use zbus::{interface, object_server::SignalEmitter, zvariant::{OwnedObjectPath, OwnedValue}};

use crate::service::Service;

#[derive(Debug, Clone, Copy)]
pub enum PromptRole {
    Lock,
    Unlock,
    CreateCollection,
}

#[derive(Debug, Clone)]
pub struct Prompt {
    service: Service,
    // Objects to lock/unlock
    objects: Vec<OwnedObjectPath>,
    role: PromptRole,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(&self, _window_id: &str) -> Result<(), ServiceError> {
        todo!()
    }

    pub async fn dismiss(&self) -> Result<(), ServiceError> {
        todo!()
    }

    #[zbus(signal, name = "Completed")]
    async fn completed(
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
