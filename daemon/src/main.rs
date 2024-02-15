pub mod service;

use std::{future::pending, sync::OnceLock};

use oo7::portal::Keyring;
use zbus::Result;

use crate::service::service::Service;

pub static KEYRING: OnceLock<Keyring> = OnceLock::new();
// TODO remove this and use service::keyring()

#[tokio::main]
async fn main() -> Result<()> {
    let service = Service::new().await;
    service.run().await?;

    pending::<()>().await;

    Ok(())
}
