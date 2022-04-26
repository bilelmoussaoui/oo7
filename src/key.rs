use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key(pub(crate) Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
