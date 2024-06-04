// org.freedesktop.Secret.Prompt

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use oo7::portal::{Keyring, Secret};
use serde::{Serialize, Serializer};
use zbus::{
    fdo, interface, proxy,
    zvariant::{self, DeserializeDict, ObjectPath, OwnedObjectPath, SerializeDict, Type, Value},
    SignalContext,
};

use super::{
    prompter::{PrompterCallback, PrompterProxy, Properties},
    secret_exchange::{get_secret, SecretExchange},
    service_manager::ServiceManager,
};
use crate::{LOGIN_KEYRING, LOGIN_KEYRING_PATH, SECRET_PROMPT_PREFIX};

#[derive(Default, DeserializeDict, Debug, Type, SerializeDict)]
#[zvariant(signature = "dict")]
pub struct PromptResult {
    path: OwnedObjectPath,
}

#[derive(Clone, Debug, Default, zvariant::Type)]
#[zvariant(signature = "o")]
pub struct Prompt {
    manager: Arc<Mutex<ServiceManager>>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(
        &self,
        window_id: &str,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        // implementation : WIP
        let callback = PrompterCallback::new();
        object_server
            .at(callback.path().to_owned(), callback.to_owned())
            .await
            .unwrap();

        let prompter = PrompterProxy::new(&connection).await?;
        prompter.begin_prompting(&callback.path()).await?;

        let mut properties = Properties::default();
        let se = SecretExchange::new();
        let exchange = se.secret_exchange_begin();

        callback
            .prompt_ready("yes", properties.to_owned(), &exchange)
            .await?;
        prompter
            .perform_prompt(&callback.path(), "password", &properties, &exchange)
            .await?;
        callback
            .prompt_ready("yes", properties.to_owned(), &exchange)
            .await?;

        let secret = Secret::from(get_secret(&exchange).unwrap().into_bytes());

        // do we need a way to identify what is the purpose of each prompt?
        // for an example, if a prompt generated for Service:Unlock
        // we can try to verify the secret (input) by calling Keyring::load

        match Keyring::load(LOGIN_KEYRING_PATH, secret).await {
            Ok(_) => todo!(),
            Err(_) => todo!(),
        }

        prompter.stop_prompting(&callback.path()).await?;

        Ok(())
    }

    pub async fn dismiss(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
    ) -> fdo::Result<()> {
        object_server.remove::<Self, _>(&self.path).await?;

        // signal
        Self::completed(&ctxt).await?;

        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(ctxt: &SignalContext<'_>) -> zbus::Result<()> {
        // TODO: return values:
        // OUT Boolean dismissed, OUT Variant result
        let dismissed = true;
        let result = PromptResult::default();

        Ok(())
    }
}

impl Prompt {
    pub fn new(manager: Arc<Mutex<ServiceManager>>, prompts_counter: i32) -> Self {
        Self {
            path: OwnedObjectPath::try_from(format!(
                "{}p{}",
                SECRET_PROMPT_PREFIX, prompts_counter
            ))
            .unwrap(),
            manager,
        }
    }

    pub fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }
}

impl Serialize for Prompt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OwnedObjectPath::serialize(&self.path, serializer)
    }
}
