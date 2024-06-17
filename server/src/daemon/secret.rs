use oo7::{crypto, Key};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::session::Session;

#[allow(dead_code)]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    #[zeroize(skip)]
    session: Session,
    parameters: Vec<u8>,
    value: Vec<u8>,
    #[zeroize(skip)]
    content_type: String,
}

impl Secret {
    pub fn new(session: Session, secret: impl AsRef<[u8]>, content_type: &str) -> Self {
        Self {
            session,
            parameters: vec![],
            value: secret.as_ref().to_vec(),
            content_type: content_type.to_owned(),
        }
    }

    pub fn new_encrypted(
        session: Session,
        secret: impl AsRef<[u8]>,
        content_type: &str,
        aes_key: &Key,
    ) -> Self {
        let iv = crypto::generate_iv();
        let secret = crypto::encrypt(secret.as_ref(), aes_key, &iv);
        Self {
            session,
            parameters: iv,
            value: secret,
            content_type: content_type.to_owned(),
        }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
