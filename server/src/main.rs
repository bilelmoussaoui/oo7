mod capability;
mod collection;
mod error;
#[allow(unused)]
mod gnome;
mod item;
mod prompt;
mod service;
mod session;

use clap::Parser;
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
    capability::drop_unnecessary_capabilities()?;

    let args = Args::parse();
    let mut secret = None;

    if args.login {
        let password = rpassword::prompt_password("Enter the login password: ")?;
        if password.is_empty() {
            tracing::error!("Login password can't be empty.");
            return Err(Error::EmptyPassword);
        }
        secret = Some(oo7::Secret::text(password));
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
