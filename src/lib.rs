#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]
mod algorithm;
pub mod dbus;
mod error;

pub use algorithm::Algorithm;
pub use error::{Error, Result};
