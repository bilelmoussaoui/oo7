mod collection;
mod error;
mod item;
mod prompt;
mod service;
mod service_manager;
mod session;

use clap::Parser;
use oo7::portal::Secret;
use service::Service;

use crate::error::Error;

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

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short = 'l',
        long,
        default_value_t = false,
        help = "Read a password from stdin, and use it to unlock the login keyring."
    )]
    login: bool,
    #[arg(short, long, help = "Replace a running instance.")]
    replace: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut secret = None;

    if args.login {
        let password = rpassword::prompt_password("Enter the login password: ")?;
        if password.is_empty() {
            tracing::error!("Login password can't be empty.");
            return Err(Error::EmptyPassword);
        }
        secret = Some(Secret::from(password.into_bytes()));
    }

    let mut flags = zbus::fdo::RequestNameFlags::AllowReplacement.into();
    if args.replace {
        flags |= zbus::fdo::RequestNameFlags::ReplaceExisting;
    }

    if args.login {
        password = match rpassword::prompt_password("Enter the login password: ") {
            Ok(pwd) => pwd.into_bytes(),
            Err(err) => panic!("{}", err),
        };
    }

    tracing::info!("Initializing {BINARY_NAME} {}", env!("CARGO_PKG_VERSION"));

    Service::run(secret, flags).await?;

    std::future::pending::<()>().await;

    Ok(())
}
