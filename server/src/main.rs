mod capability;
mod collection;
mod error;
#[allow(unused)]
mod gnome;
mod item;
mod prompt;
mod service;
mod session;

use std::io::{IsTerminal, Read};

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
    #[arg(
        short = 'v',
        long = "verbose",
        help = "Print debug information during command processing."
    )]
    is_verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    if args.is_verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
            .init();
        tracing::debug!("Running in verbose mode");
    } else {
        tracing_subscriber::fmt::init();
    }

    capability::drop_unnecessary_capabilities()?;

    let secret = if args.login {
        let mut stdin = std::io::stdin().lock();
        if stdin.is_terminal() {
            let password = rpassword::prompt_password("Enter the login password: ")?;
            if password.is_empty() {
                tracing::error!("Login password can't be empty.");
                return Err(Error::EmptyPassword);
            }

            Some(oo7::Secret::text(password))
        } else {
            let mut buff = vec![];
            stdin.read_to_end(&mut buff)?;

            Some(oo7::Secret::from(buff))
        }
    } else {
        None
    };

    let mut flags =
        zbus::fdo::RequestNameFlags::AllowReplacement | zbus::fdo::RequestNameFlags::DoNotQueue;
    if args.replace {
        flags |= zbus::fdo::RequestNameFlags::ReplaceExisting;
    }

    tracing::info!("Starting {BINARY_NAME}");

    Service::run(secret, flags).await.inspect_err(|err| {
        if let Error::Zbus(zbus::Error::NameTaken) = err {
            tracing::error!(
                "There is an instance already running. Run with --replace to replace it."
            );
        }
    })?;

    tracing::debug!("Starting loop");

    std::future::pending::<()>().await;

    Ok(())
}
