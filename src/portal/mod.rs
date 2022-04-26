mod error;
mod keyring;

pub use error::Error;
pub use keyring::{EncryptedItem, Item, Key, Keyring};
mod secret;

pub(crate) use secret::retrieve;
