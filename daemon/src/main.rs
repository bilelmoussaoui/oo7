pub mod service;

use std::{future::pending, sync::OnceLock};

use oo7::portal::Keyring;
use zbus::{ConnectionBuilder, Result};

const SECRET_SERVICE_OBJECTPATH: &str = "/org/freedesktop/secrets_";
// const SECRET_COLLECTION_OBJECTPATH: &str =
// "/org/freedesktop/secrets_/collection"; const SECRET_SESSION_OBJECTPATH: &str
// = "/org/freedesktop/secrets_/session";

use crate::service::service::Service;

pub static KEYRING: OnceLock<Keyring> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<()> {
    let secret_service = Service {
        collections: Vec::new(),
    };

    // let collection = Collection::default();
    // let session = Session {
    // path: ObjectPath::default().into(),
    // };

    let _service = ConnectionBuilder::session()?
        .name("org.freedesktop.secrets_")?
        .serve_at(SECRET_SERVICE_OBJECTPATH, secret_service)?
        //.serve_at(SECRET_COLLECTION_OBJECTPATH, collection)?
        //.serve_at(SECRET_SESSION_OBJECTPATH, session)?
        .build()
        .await?;

    let _keyring = match Keyring::load_default().await {
        Ok(keyring) => KEYRING.set(keyring),
        Err(_) => todo!(), // call some init to create default keyring
    };

    pending::<()>().await;

    Ok(())
}
