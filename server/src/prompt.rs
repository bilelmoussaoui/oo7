// org.freedesktop.Secret.Prompt

use oo7::dbus::ServiceError;
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::{
    gnome::prompter::{PrompterCallback, PrompterProxy},
    service::Service,
};

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum PromptRole {
    Lock,
    Unlock,
    CreateCollection,
}

#[derive(Debug, Clone)]
pub struct Prompt {
    service: Service,
    objects: Vec<OwnedObjectPath>,
    role: PromptRole,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(
        &self,
        // TODO: Replace with ashpd::WindowIdentifierType
        window_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        let callback =
            PrompterCallback::new(window_id, self.service.clone(), self.path.clone()).await;
        let path = callback.path().clone();
        let connection = connection.clone();

        object_server.at(&path, callback).await?;
        tracing::debug!("Prompt `{}` created.", self.path);

        tokio::spawn(async move {
            let prompter = PrompterProxy::new(&connection).await.unwrap();
            prompter.begin_prompting(&path).await.unwrap();
        });

        Ok(())
    }

    pub async fn dismiss(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        object_server.remove::<Self, _>(&self.path).await?;
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
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }

    pub fn role(&self) -> &PromptRole {
        &self.role
    }

    pub fn objects(&self) -> &Vec<OwnedObjectPath> {
        &self.objects
    }
}
