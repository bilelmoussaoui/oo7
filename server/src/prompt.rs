// org.freedesktop.Secret.Prompt

use oo7::dbus::ServiceError;
use zbus::{interface, object_server::SignalEmitter, zvariant::OwnedValue};

#[derive(Debug)]
pub struct Prompt {}

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
