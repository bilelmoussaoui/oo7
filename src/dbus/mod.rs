pub(crate) static DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) static PATH: &str = "/org/freedesktop/secrets";

/// A common trait implemented by objects that can be
/// locked or unlocked. Like [`Collection`] or [`Item`].
pub trait Unlockable: serde::Serialize + zbus::zvariant::Type {}

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
