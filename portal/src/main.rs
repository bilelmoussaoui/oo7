use std::{collections::HashMap, future::pending, os::unix::net::UnixStream};
mod error;

use ashpd::{
    async_trait,
    zbus::{self, zvariant::OwnedValue},
    AppID,
};
use clap::Parser;
pub use error::Result;
use oo7::dbus::Service;
use tokio::io::AsyncWriteExt;

const PORTAL_SECRET_SIZE: usize = 64;
const PORTAL_NAME: &str = "org.freedesktop.impl.portal.desktop.oo7";

struct Secret;

#[async_trait::async_trait]
impl ashpd::backend::request::RequestImpl for Secret {
    async fn close(&self) {}
}

#[async_trait::async_trait]
impl ashpd::backend::secret::SecretImpl for Secret {
    async fn retrieve(
        &self,
        app_id: ashpd::AppID,
        fd: std::os::fd::OwnedFd,
    ) -> ashpd::backend::Result<HashMap<String, OwnedValue>> {
        tracing::debug!("Request from app: {app_id}");
        send_secret_to_app(&app_id, fd)
            .await
            .map_err(|e| ashpd::PortalError::Failed(format!("Could not retrieve secret {e}")))?;
        Ok(Default::default())
    }
}

fn generate_secret() -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut secret = [0; PORTAL_SECRET_SIZE];
    // Equivalent of `ring::rand::SecureRandom`
    getrandom::getrandom(&mut secret)?;
    Ok(zeroize::Zeroizing::new(secret.to_vec()))
}

/// Generates, stores and send the secret back to the fd stream
async fn send_secret_to_app(app_id: &AppID, fd: std::os::fd::OwnedFd) -> Result<()> {
    let service = Service::new().await?;
    let collection = match service.default_collection().await {
        Err(oo7::dbus::Error::NotFound(_)) => {
            service
                .create_collection("Default", Some(oo7::dbus::DEFAULT_COLLECTION), None)
                .await
        }
        e => e,
    }?;
    let attributes = HashMap::from([("app_id", app_id)]);

    let secret = if let Some(item) = collection.search_items(&attributes).await?.first() {
        item.secret().await?
    } else {
        tracing::debug!("Could not find secret for {app_id}, creating one");
        let secret = generate_secret()?;

        collection
            .create_item(
                &format!("Secret Portal token for {app_id}"),
                &attributes,
                &secret,
                true,
                // TODO Find a better one.
                "text/plain",
                None,
            )
            .await?;

        secret
    };

    // Write the secret to the FD.
    let mut stream = tokio::net::UnixStream::from_std(UnixStream::from(fd))?;
    stream.write_all(&secret).await?;

    Ok(())
}

/// A backend implementation for org.freedesktop.impl.portal.Secret.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Replace a running instance
    #[arg(short, long)]
    replace: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

    tracing::info!(
        "Initializing {} {}",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let cnx = zbus::Connection::session().await?;

    let portal = ashpd::backend::secret::SecretInterface::new(Secret, cnx.clone());
    tracing::debug!("Serving `org.freedesktop.impl.portal.Secret`");
    cnx.object_server().at(ashpd::DESKTOP_PATH, portal).await?;

    let mut flags = zbus::fdo::RequestNameFlags::AllowReplacement.into();
    if args.replace {
        flags |= zbus::fdo::RequestNameFlags::ReplaceExisting;
    }
    cnx.request_name_with_flags(PORTAL_NAME, flags).await?;

    loop {
        pending::<()>().await;
    }
}
