#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
#![cfg_attr(feature = "docs", feature(doc_auto_cfg))]
#[cfg(all(all(feature = "tokio", feature = "async-std"), not(doc)))]
compile_error!("You can't enable both async-std & tokio features at once");

mod error;
mod key;
mod migration;

#[cfg(feature = "unstable")]
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

/// Checks whether the application is sandboxed or not.
pub async fn is_sandboxed() -> bool {
    crate::helpers::is_flatpak().await || crate::helpers::is_snap().await
}
