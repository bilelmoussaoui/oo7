use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use zvariant::{Type, serialized::Context, to_bytes};

#[derive(Debug, Serialize, Deserialize, Type, Zeroize, ZeroizeOnDrop)]
pub struct PamMessage {
    pub username: String,
    pub secret: Vec<u8>,
}

impl PamMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        to_bytes(ctxt, self).map(|data| data.to_vec())
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, zvariant::Error> {
        let ctxt = Context::new_dbus(zvariant::LE, 0);
        let data = zvariant::serialized::Data::new(bytes, ctxt);
        data.deserialize().map(|(msg, _)| msg)
    }
}
