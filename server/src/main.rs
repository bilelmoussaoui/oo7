mod collection;
mod item;
mod prompt;
mod service;
mod service_manager;
mod session;

use service::{Result, Service};

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting {}", BINARY_NAME);

    let service = Service::new().await?;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
