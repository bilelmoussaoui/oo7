// org.freedesktop.Secret.Session

use zbus::interface;

use super::Result;

#[derive(Debug)]
pub struct Session {}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    pub async fn close(&self) -> Result<()> {
        todo!()
    }
}
