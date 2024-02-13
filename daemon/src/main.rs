pub mod service;

use std::{future::pending, sync::OnceLock};

use oo7::portal::Keyring;
use zbus::{ConnectionBuilder, Result};

const SECRET_SERVICE_OBJECTPATH: &str = "/org/freedesktop/secrets_";

use crate::service::service::Service;

pub static KEYRING: OnceLock<Keyring> = OnceLock::new();
// TODO remove this and use service::keyring()

#[tokio::main]
async fn main() -> Result<()> {
    let service = Service::new().await;

    let _service = ConnectionBuilder::session()?
        .name("org.freedesktop.secrets_")?
        .serve_at(SECRET_SERVICE_OBJECTPATH, service)?
        .build()
        .await?;

    pending::<()>().await;

    Ok(())
}
