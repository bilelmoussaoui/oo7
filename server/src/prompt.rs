// org.freedesktop.Secret.Prompt

use oo7::dbus::ServiceError;
use zbus::interface;

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
}
