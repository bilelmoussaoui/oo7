use std::sync::Mutex;

use oo7::zbus::{
    self, dbus_interface,
    zvariant::{self, ObjectPath, Type},
};
use serde::Serialize;

#[derive(Serialize, PartialEq, Eq, Debug, Type)]
pub enum ResponseType {
    Success = 0,
    Cancelled = 1,
    Other = 2,
}

pub struct Request {
    handle_path: zvariant::ObjectPath<'static>,
    sender: Mutex<Option<futures_channel::oneshot::Sender<()>>>,
}

impl Request {
    pub fn new(
        handle_path: &ObjectPath<'static>,
        sender: futures_channel::oneshot::Sender<()>,
    ) -> Self {
        tracing::debug!("Request `{:?}` exported", handle_path.as_str());
        Self {
            handle_path: handle_path.clone(),
            sender: Mutex::new(Some(sender)),
        }
    }
}

#[dbus_interface(name = "org.freedesktop.impl.portal.Request")]
impl Request {
    async fn close(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("Request `{}` closed", self.handle_path);
        server.remove::<Self, _>(&self.handle_path).await?;

        if let Ok(mut guard) = self.sender.lock() {
            if let Some(sender) = (*guard).take() {
                // This will Err out if the receiver has been dropped.
                let _ = sender.send(());
            }
        }

        Ok(())
    }
}
