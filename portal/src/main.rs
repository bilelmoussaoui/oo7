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

/// Generates, stores and send the secret back to the fd stream
async fn send_secret_to_app(app_id: &AppID, fd: std::os::fd::OwnedFd) -> Result<()> {
    let service = Service::new().await?;
    let collection = service.default_collection().await?;
    // Generic schema, used by gnome-keyring-daemon and used for backward
    // compatibility purposes TODO: figure out if kwallet or other portal
    // implementations make use of it, or if it is even useful
    const GENERIC_SCHEMA_VALUE: &str = "org.freedesktop.Secret.Generic";

    let attributes = HashMap::from([
        (oo7::XDG_SCHEMA_ATTRIBUTE, GENERIC_SCHEMA_VALUE),
        ("app_id", app_id),
    ]);

    // Write the secret to the FD.
    let std_stream = UnixStream::from(fd);
    std_stream.set_nonblocking(true)?;
    let mut stream = tokio::net::UnixStream::from_std(std_stream)?;

    if let Some(item) = collection.search_items(&attributes).await?.first() {
        stream.write_all(&item.secret().await?).await?;
    } else {
        tracing::debug!("Could not find secret for {app_id}, creating one");
        let secret = oo7::Secret::random().unwrap();

        collection
            .create_item(
                &format!("Secret Portal token for {app_id}"),
                &attributes,
                secret.clone(),
                true,
                None,
            )
            .await?;

        stream.write_all(&secret).await?;
    }

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

    let mut flags = zbus::fdo::RequestNameFlags::AllowReplacement.into();
    if args.replace {
        flags |= zbus::fdo::RequestNameFlags::ReplaceExisting;
    }

    ashpd::backend::Builder::new(PORTAL_NAME)?
        .secret(Secret)
        .with_flags(flags)
        .build()
        .await?;

    loop {
        pending::<()>().await;
    }
}
