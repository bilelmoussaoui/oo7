pub(crate) static DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) static PATH: &str = "/org/freedesktop/secrets";

mod collection;
mod item;
mod prompt;
mod secret;
mod service;
mod session;

pub use collection::Collection;
pub use item::Item;
pub(crate) use prompt::Prompt;
pub use secret::Secret;
pub use service::Service;
pub use session::Session;
