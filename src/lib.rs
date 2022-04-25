#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
mod algorithm;
pub mod dbus;

mod error;
/// A [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) compatible
/// implementation.
#[allow(unused)]
pub mod portal;
mod utils;

pub use algorithm::Algorithm;
pub use error::{Error, Result};
