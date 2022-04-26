pub(crate) const SALT_SIZE: usize = 32;
pub(crate) const ITERATION_COUNT: u32 = 100000;

pub(crate) const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
pub(crate) const FILE_HEADER_LEN: usize = FILE_HEADER.len();

pub(crate) const MAJOR_VERSION: u8 = 1;
pub(crate) const MINOR_VERSION: u8 = 0;

pub(crate) type MacAlg = hmac::Hmac<sha2::Sha256>;
pub(crate) type EncAlg = cbc::Encryptor<aes::Aes128>;
pub(crate) type DecAlg = cbc::Decryptor<aes::Aes128>;

mod attribute_value;
mod error;
mod keyring;

pub use attribute_value::AttributeValue;
pub use error::Error;
pub use keyring::{EncryptedItem, Item, Key, Keyring};
mod secret;

pub(crate) use secret::retrieve;
