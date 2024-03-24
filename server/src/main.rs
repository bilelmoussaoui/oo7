use clap::Parser;

mod daemon;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const LOGIN_KEYRING: &str = "login";
const LOGIN_KEYRING_PATH: &str = "Downloads/default.keyring";
// const LOGIN_KEYRING_PATH: &str = ".local/share/keyrings/login.keyring";
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value_t = false)]
    login: bool,
}

#[tokio::main]
async fn main() -> daemon::Result<()> {
    let args = Args::parse();
    let mut password = String::new();
    tracing_subscriber::fmt::init();

    if args.login {
        password = rpassword::prompt_password("Enter the login password: ").unwrap();
    }

    tracing::info!("Starting {}", BINARY_NAME);

    let service = daemon::Service::new(password).await;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
