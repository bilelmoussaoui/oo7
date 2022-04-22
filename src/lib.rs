pub(crate) static DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) static PATH: &str = "/org/freedesktop/secrets";

mod collection;
mod error;
mod item;
mod service;
mod session;
mod prompt;

pub use collection::Collection;
pub use error::{Error, Result};
pub use item::Item;
pub use service::Service;
pub use session::Session;
pub use prompt::Prompt;
