#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
#![cfg_attr(feature = "docs", feature(doc_auto_cfg))]

mod error;
mod key;

#[cfg(feature = "unstable")]
pub use key::Key;
#[cfg(not(feature = "unstable"))]
pub(crate) use key::Key;

pub mod dbus;

/// A [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) compatible
/// implementation.
pub mod portal;

pub use error::{Error, Result};
