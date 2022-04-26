#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]

mod error;
mod key;
pub use key::Key;

pub mod dbus;

/// A [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) compatible
/// implementation.
#[allow(unused)]
pub mod portal;

pub use error::{Error, Result};
