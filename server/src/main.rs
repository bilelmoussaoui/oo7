use clap::Parser;

mod daemon;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
#[cfg(debug_assertions)]
const LOGIN_KEYRING: &str = "test";
#[cfg(not(debug_assertions))]
const LOGIN_KEYRING: &str = "login";
#[cfg(debug_assertions)]
const LOGIN_KEYRING_PATH: &str = ".local/share/keyrings/test.keyring";
#[cfg(not(debug_assertions))]
const LOGIN_KEYRING_PATH: &str = ".local/share/keyrings/login.keyring";
#[cfg(not(debug_assertions))]
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
#[cfg(debug_assertions)]
const SERVICE_PATH: &str = "/org/freedesktop/secrets_Devel";
#[cfg(debug_assertions)]
const SERVICE_NAME: &str = "org.freedesktop.secrets_Devel";
#[cfg(debug_assertions)]
const SECRET_SESSION_PREFIX: &str = "/org/freedesktop/secrets_Devel/session/";
#[cfg(not(debug_assertions))]
const SECRET_SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
#[cfg(debug_assertions)]
const SECRET_COLLECTION_PREFIX: &str = "/org/freedesktop/secrets_Devel/collection/";
#[cfg(not(debug_assertions))]
const SECRET_COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";
#[cfg(debug_assertions)]
const SECRET_PROMPT_PREFIX: &str = "/org/freedesktop/secrets_Devel/prompt/";
#[cfg(not(debug_assertions))]
const SECRET_PROMPT_PREFIX: &str = "/org/freedesktop/secrets/prompt/";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value_t = false)]
    login: bool,
}

#[tokio::main]
async fn main() -> daemon::Result<()> {
    let args = Args::parse();
    let mut password: Vec<u8> = Vec::new();
    tracing_subscriber::fmt::init();

    if args.login {
        password = match rpassword::prompt_password("Enter the login password: ") {
            Ok(pwd) => pwd.into_bytes(),
            Err(err) => panic!("{}", err),
        };
    }

    tracing::info!("Initializing {BINARY_NAME} {}", env!("CARGO_PKG_VERSION"));

    let service = daemon::Service::new(password).await;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
