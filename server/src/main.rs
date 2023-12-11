mod daemon;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

#[tokio::main]
async fn main() -> daemon::Result<()> {
    tracing_subscriber::fmt::init();

    tracing::info!("Starting {}", BINARY_NAME);

    let service = daemon::Service::new().await;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
