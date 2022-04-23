pub(crate) static DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) static PATH: &str = "/org/freedesktop/secrets";

mod algorithm;
mod collection;
mod error;
mod item;
mod prompt;
mod secret;
mod service;
mod session;

pub use algorithm::Algorithm;
pub use collection::Collection;
pub use error::{Error, Result};
pub use item::Item;
pub use prompt::Prompt;
pub use secret::Secret;
pub use service::Service;
pub use session::Session;
