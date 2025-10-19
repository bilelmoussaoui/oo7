//! File backend implementation that can be backed by the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
//!
//! ```no_run
//! use oo7::file::UnlockedKeyring;
//!
//! # async fn run() -> oo7::Result<()> {
//! let keyring = UnlockedKeyring::load_default().await?;
//! keyring
//!     .create_item("My Label", &[("account", "alice")], "My Password", true)
//!     .await?;
//!
//! let items = keyring.search_items(&[("account", "alice")]).await?;
//! assert_eq!(items[0].secret(), oo7::Secret::blob("My Password"));
//!
//! keyring.delete(&[("account", "alice")]).await?;
//! #   Ok(())
//! # }
//! ```

#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub mod api;
#[cfg(not(feature = "unstable"))]
mod api;

pub(crate) use api::AttributeValue;

mod error;
mod locked_keyring;
mod unlocked_item;
mod unlocked_keyring;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use locked_keyring::LockedKeyring;
pub use unlocked_item::UnlockedItem;
pub use unlocked_keyring::UnlockedKeyring;
