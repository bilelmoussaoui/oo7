use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret used to unlock the keyring.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl From<Vec<u8>> for Secret {
    fn from(secret: Vec<u8>) -> Self {
        Self(secret)
    }
}

impl std::ops::Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Secret {
    pub fn random() -> Self {
        Self(rand::thread_rng().gen::<[u8; 8]>().to_vec())
    }
}
