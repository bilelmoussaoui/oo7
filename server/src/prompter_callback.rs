// org.gnome.keyring.internal.Prompter.Callback
// https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/org.gnome.keyring.Prompter.xml

use std::collections::HashMap;

use oo7::dbus::ServiceError;
use zbus::{
    interface,
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::Service;

#[derive(Clone, Debug)]
pub struct PrompterCallback {
    service: Service,
    path: OwnedObjectPath,
}

#[interface(name = "org.gnome.keyring.internal.Prompter.Callback")]
impl PrompterCallback {
    pub async fn prompt_ready(
        &self,
        reply: &str,
        properties: HashMap<&str, OwnedValue>,
    ) -> Result<(), ServiceError> {
        Ok(())
    }

    pub async fn prompt_done(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}

impl PrompterCallback {
    pub async fn new(service: Service) -> Self {
        let index = service.session_index().await;
        Self {
            path: OwnedObjectPath::try_from(format!("/org/gnome/keyring/Prompt/p{index}")).unwrap(),
            service,
        }
    }

    pub fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}
