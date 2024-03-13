mod daemon;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
#[cfg(debug_assertions)]
const SERVICE_NAME: &str = "org.freedesktop.secrets.Devel";
#[cfg(debug_assertions)]
const SECRET_SESSION_PREFIX: &str = "/org/freedesktop/secrets.Devel/session/";
#[cfg(not(debug_assertions))]
const SECRET_SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
#[cfg(debug_assertions)]
const SECRET_COLLECTION_PREFIX: &str = "/org/freedesktop/secrets.Devel/collection/";
#[cfg(not(debug_assertions))]
const SECRET_COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";

#[tokio::main]
async fn main() -> daemon::Result<()> {
    tracing_subscriber::fmt::init();

    tracing::info!("Starting {}", BINARY_NAME);

    let service = daemon::Service::new().await;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
