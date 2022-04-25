#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
pub mod dbus;

mod error;
/// A [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) compatible
/// implementation.
#[allow(unused)]
pub mod portal;

pub use error::{Error, Result};
