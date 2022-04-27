//! A [Secret Service](https://specifications.freedesktop.org/secret-service/latest/index.html) implementation.
//!
//! That is usually done with
//! ```ignore
//! let service = Service::new(Algorithm::Plain).await?;
//!
//! let mut attributes = std::collections::HashMap::new();
//! attributes.insert("type", "password");
//! attributes.insert("user_id", "some_other_identifier");
//!
//! if let Some(collection) = service.default_collection().await? {
//!     // Store a secret
//!     collection
//!         .create_item(
//!             "My App's secret",
//!             attributes.clone(),
//!             b"password",
//!             true,
//!             "text/plain",
//!         )
//!         .await?;
//!
//!     // Retrieve it later thanks to it attributes
//!     let item = collection.search_items(attributes).await?.first().unwrap();
//!     assert_eq!(item.secret().await?, b"password");
//! }
//! ```

/// The default collection alias.
///
/// In general, you are supposed to use [`Service::default_collection`].
pub static DEFAULT_COLLECTION: &str = "default";

/// A session collection.
///
/// The collection is cleared when the user ends the session.
pub static SESSION_COLLECTION: &str = "session";

/// Barebone DBus API of the Secret Service specifications.
///
/// The API is not supposed to be used by the applications in general unless
/// the wrapper API doesn't provide functionality you need.
#[cfg(feature = "unstable")]
pub mod api;

#[cfg(not(feature = "unstable"))]
#[allow(unused)]
mod api;

mod algorithm;
pub use algorithm::Algorithm;
mod item;
pub use item::Item;
mod error;
mod service;
pub use error::Error;
pub use service::Service;
mod collection;
pub use collection::Collection;
mod utils;
