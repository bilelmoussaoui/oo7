mod collection;
mod error;
mod item;
mod prompt;
mod service;
mod session;

use clap::Parser;
use oo7::file::Secret;
use service::Service;

use crate::error::Error;

const BINARY_NAME: &str = env!("CARGO_BIN_NAME");

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

    tracing::info!("Starting {}", BINARY_NAME);

    Service::run(secret, flags).await?;

    std::future::pending::<()>().await;

    Ok(())
}
