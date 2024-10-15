// org.freedesktop.Secret.Prompt

use zbus::interface;

use super::Result;

#[derive(Debug)]
pub struct Prompt {}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(&self, _window_id: &str) -> Result<()> {
        todo!()
    }

    pub async fn dismiss(&self) -> Result<()> {
        todo!()
    }
}
