mod collection;
mod error;
mod item;
mod prompt;
mod service;
mod session;

pub use self::service::Service;
pub type Result<T> = std::result::Result<T, error::ServiceError>;
