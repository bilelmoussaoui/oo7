/// The default collection alias.
/// 
/// In general, you are supposed to use [`Service::default_collection`]
pub static DEFAULT_COLLECTION: &str = "default";

/// Barebone DBus API of the secret service specifications.
///
/// The API is not supposed to be used by the applications in general unless
/// the wrapper API doesn't provide functionality you need.
pub mod api;

mod item;
pub use item::Item;
mod service;
pub use service::Service;
mod collection;
pub use collection::Collection;
