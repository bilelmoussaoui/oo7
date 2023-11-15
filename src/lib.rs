#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
#[cfg(all(all(feature = "tokio", feature = "async-std"), not(doc)))]
compile_error!("You can't enable both async-std & tokio features at once");

mod error;
mod key;
mod migration;

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub use key::Key;
#[cfg(not(feature = "unstable"))]
pub(crate) use key::Key;

mod crypto;
pub mod dbus;
pub mod portal;

mod helpers;
mod keyring;

pub use error::{Error, Result};
pub use keyring::{Item, Keyring};
pub use migration::migrate;
pub use zbus;

/// Checks whether the application is sandboxed or not.
pub async fn is_sandboxed() -> bool {
    helpers::is_flatpak().await || helpers::is_snap().await
}
