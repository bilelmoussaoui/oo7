// org.freedesktop.Secret.Prompt

use oo7::dbus::ServiceError;
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::{prompter_callback::PrompterCallback, Service};

#[derive(Debug, Clone)]
pub struct Prompt {
    service: Service,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        let callback = PrompterCallback::new(self.service.clone()).await;
        object_server.at(callback.path().clone(), callback).await?;

        Ok(())
    }

    pub async fn dismiss(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(), ServiceError> {
        object_server.remove::<Self, _>(&self.path).await?;

        Ok(())
    }

    #[zbus(signal, name = "Completed")]
    async fn completed(
        signal_emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

impl Prompt {
    pub async fn new(service: Service) -> Self {
        let index = service.prompt_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                .unwrap(),
            service,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
