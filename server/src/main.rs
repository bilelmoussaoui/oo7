mod collection;
mod item;
mod prompt;
mod service;
mod service_manager;
mod session;

use clap::Parser;
use oo7::portal::Secret;
use service::{Result, Service};

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut secret: Option<Secret> = None;
    tracing_subscriber::fmt::init();

    if args.login {
        match rpassword::prompt_password("Enter the login password: ") {
            Ok(password) => {
                if password.is_empty() {
                    panic!("Login password can't be empty");
                } else {
                    secret = Some(Secret::from(password.into_bytes()))
                }
            }
            Err(err) => panic!("{}", err),
        };
    }

    tracing::info!("Starting {}", BINARY_NAME);

    let service = Service::new(secret).await;
    service.run().await?;

    std::future::pending::<()>().await;

    Ok(())
}
