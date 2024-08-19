pub(crate) const DESTINATION: &str = "org.freedesktop.secrets";
pub(crate) const PATH: &str = "/org/freedesktop/secrets";

/// A common trait implemented by objects that can be
/// locked or unlocked. Like [`Collection`] or [`Item`].
pub trait Unlockable: serde::Serialize + zbus::zvariant::Type {}

impl<'a> Unlockable for zbus::zvariant::ObjectPath<'a> {}
impl Unlockable for zbus::zvariant::OwnedObjectPath {}
impl<'a> Unlockable for &zbus::zvariant::ObjectPath<'a> {}
impl Unlockable for &zbus::zvariant::OwnedObjectPath {}

mod collection;
mod item;
mod prompt;
mod properties;
mod secret;
mod service;
mod session;

pub use collection::Collection;
pub use item::Item;
pub(crate) use prompt::Prompt;
#[cfg(not(feature = "unstable"))]
pub(crate) use properties::Properties;
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub use properties::Properties;
pub use secret::Secret;
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub use secret::SecretInner;
pub use service::Service;
pub use session::Session;
