pub(crate) static DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) static PATH: &str = "/org/freedesktop/secrets";

mod collection;
mod error;
mod item;
mod prompt;
mod service;
mod session;

pub use collection::Collection;
pub use error::{Error, Result};
pub use item::Item;
pub use prompt::Prompt;
pub use service::Service;
pub use session::Session;
