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
mod locked_item;
mod locked_keyring;
mod unlocked_item;
mod unlocked_keyring;

pub use error::{Error, InvalidItemError, WeakKeyError};
pub use locked_item::LockedItem;
pub use locked_keyring::LockedKeyring;
pub use unlocked_item::UnlockedItem;
pub use unlocked_keyring::UnlockedKeyring;

use crate::Secret;

#[derive(Debug)]
pub enum Item {
    Locked(LockedItem),
    Unlocked(UnlockedItem),
}

impl Item {
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_))
    }

    pub fn as_unlocked(&self) -> &UnlockedItem {
        match self {
            Self::Unlocked(item) => item,
            _ => panic!("The item is locked"),
        }
    }

    pub fn as_mut_unlocked(&mut self) -> &mut UnlockedItem {
        match self {
            Self::Unlocked(item) => item,
            _ => panic!("The item is locked"),
        }
    }

    pub fn as_locked(&self) -> &LockedItem {
        match self {
            Self::Locked(item) => item,
            _ => panic!("The item is unlocked"),
        }
    }
}

#[derive(Debug)]
pub enum Keyring {
    Locked(LockedKeyring),
    Unlocked(UnlockedKeyring),
}

impl Keyring {
    /// Validate that a secret can decrypt the items in this keyring.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, secret)))]
    pub async fn validate_secret(&self, secret: &Secret) -> Result<bool, Error> {
        match self {
            Self::Locked(keyring) => keyring.validate_secret(secret).await,
            Self::Unlocked(keyring) => keyring.validate_secret(secret).await,
        }
    }

    pub async fn items(&self) -> Result<Vec<Result<Item, InvalidItemError>>, Error> {
        match self {
            Self::Locked(keyring) => keyring.items().await,
            Self::Unlocked(keyring) => keyring.items().await,
        }
    }

    /// Return the associated file if any.
    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Locked(keyring) => keyring.path(),
            Self::Unlocked(keyring) => keyring.path(),
        }
    }

    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked(_))
    }

    pub fn as_unlocked(&self) -> &UnlockedKeyring {
        match self {
            Self::Unlocked(unlocked_keyring) => unlocked_keyring,
            _ => panic!("The keyring is locked"),
        }
    }

    pub fn as_locked(&self) -> &LockedKeyring {
        match self {
            Self::Locked(locked_keyring) => locked_keyring,
            _ => panic!("The keyring is unlocked"),
        }
    }
}
