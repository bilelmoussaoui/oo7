// org.freedesktop.Secret.Prompt

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oo7::portal::{Keyring, Secret};
use serde::{Serialize, Serializer};
use tokio::{self, sync::RwLock};
use zbus::{
    fdo, interface,
    message::Header,
    proxy,
    zvariant::{self, DeserializeDict, ObjectPath, OwnedObjectPath, SerializeDict, Type, Value},
    Connection, SignalContext,
};

use super::{
    collection::Collection,
    prompter::{PrompterCallback, PrompterProxy},
    secret_exchange::SecretExchange,
    service_manager::ServiceManager,
};
use crate::{LOGIN_KEYRING, LOGIN_KEYRING_PATH, SECRET_PROMPT_PREFIX};

#[derive(Clone, Debug)]
pub enum PromptSource {
    Unlock,
    NewCollection,
}

#[derive(Clone, Debug, zvariant::Type)]
#[zvariant(signature = "o")]
pub struct Prompt {
    manager: Arc<Mutex<ServiceManager>>,
    source: PromptSource,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(
        &self,
        window_id: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<()> {
        tracing::info!("Prompt created: {}", self.path());

        let callback: PrompterCallback =
            if header.path().unwrap().as_str().to_string().contains("/u") {
                PrompterCallback::for_unlock(Arc::clone(&self.manager))
            } else {
                PrompterCallback::for_new_collection(Arc::clone(&self.manager))
            };
        object_server
            .at(callback.path().to_owned(), callback.to_owned())
            .await
            .unwrap();

        let connection = Arc::new(connection.to_owned());

        // calling begin_prompting which start the UI Prompt
        tokio::spawn(async move {
            let prompter = PrompterProxy::new(&connection).await.unwrap();
            prompter.begin_prompting(&callback.path()).await.unwrap();
        });

        Ok(())
    }

    pub async fn dismiss(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> fdo::Result<()> {
        tracing::info!("Prompt dismissed: {}", self.path);

        object_server.remove::<Self, _>(&self.path).await?;
        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(
        ctxt: &SignalContext<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

impl Prompt {
    pub fn for_unlock(manager: Arc<Mutex<ServiceManager>>) -> Self {
        let counter = manager.lock().unwrap().update_prompts_counter();

        Self {
            path: OwnedObjectPath::try_from(format!("{}{}{}", SECRET_PROMPT_PREFIX, "u", counter))
                .unwrap(),
            source: PromptSource::Unlock,
            manager,
        }
    }

    pub fn for_new_collection(manager: Arc<Mutex<ServiceManager>>) -> Self {
        let counter = manager.lock().unwrap().update_prompts_counter();

        Self {
            path: OwnedObjectPath::try_from(format!("{}{}{}", SECRET_PROMPT_PREFIX, "p", counter))
                .unwrap(),
            source: PromptSource::NewCollection,
            manager,
        }
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}
