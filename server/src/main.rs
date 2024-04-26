<<<<<<< HEAD
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
=======
use clap::Parser;

mod daemon;
>>>>>>> a718499 (Adds --login option to pass the login keyring password to the daemon)

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");
const LOGIN_KEYRING: &str = "login";
const LOGIN_KEYRING_PATH: &str = "Downloads/default.keyring";
// const LOGIN_KEYRING_PATH: &str = ".local/share/keyrings/login.keyring";
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
    let mut secret: Option<Secret> = None;

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
        password = rpassword::prompt_password("Enter the login password: ").unwrap();
    }

    tracing::info!("Starting {}", BINARY_NAME);

<<<<<<< HEAD
    Service::run(secret, flags).await?;
=======
    let service = daemon::Service::new(password).await;
    service.run().await?;
>>>>>>> a718499 (Adds --login option to pass the login keyring password to the daemon)

    std::future::pending::<()>().await;

    Ok(())
}
