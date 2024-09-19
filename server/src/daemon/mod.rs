mod collection;
mod error;
mod item;
mod prompt;
mod prompter;
mod secret;
mod secret_exchange;
mod service;
mod service_manager;
mod session;

pub use self::service::Service;
pub type Result<T> = std::result::Result<T, error::ServiceError>;
