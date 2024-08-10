mod error;
mod request;

use std::{collections::HashMap, future::pending, os::unix::net::UnixStream};

use futures_util::FutureExt;
use oo7::dbus::Service;
use ring::rand::SecureRandom;
use tokio::io::AsyncWriteExt;
use zbus::{
    zvariant::{self, OwnedObjectPath},
    ProxyDefault,
};

use crate::{
    error::Error,
    request::{Request, ResponseType},
};

const PORTAL_VERSION: u32 = 1;
const PORTAL_SECRET_SIZE: usize = 64;
const PORTAL_NAME: &str = "org.freedesktop.impl.portal.desktop.oo7";

struct Secret;

#[zbus::interface(name = "org.freedesktop.impl.portal.Secret")]
impl Secret {
    #[dbus_interface(property, name = "version")]
    fn version(&self) -> u32 {
        PORTAL_VERSION
    }

    #[dbus_interface(out_args("response", "results"))]
    async fn retrieve_secret(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        handle: OwnedObjectPath,
        app_id: &str,
        fd: zvariant::OwnedFd,
        options: HashMap<&str, zvariant::Value<'_>>,
    ) -> Result<(ResponseType, HashMap<&str, zvariant::OwnedValue>), Error> {
        tracing::debug!("Request from app: {app_id} with options: {options:?}");

        let (sender, receiver) = futures_channel::oneshot::channel();
        let request = Request::new(&handle, sender);
        object_server.at(&handle, request).await?;

        let fut_1 = async move {
            let res = match send_secret_to_app(app_id, fd).await {
                Ok(_) => ResponseType::Success,
                Err(err) => {
                    tracing::error!("could not retrieve secret: {err}");
                    ResponseType::Other
                }
            };

            // We do not accept Close request anymore here.
            tracing::debug!("Request {handle} handled");
            object_server.remove::<Request, _>(&handle).await.unwrap();

            Ok((res, HashMap::new()))
        };

        let fut_2 = async move {
            receiver.await.unwrap();
            Ok((ResponseType::Cancelled, HashMap::new()))
        };

        let t1 = fut_1.fuse();
        let t2 = fut_2.fuse();

        futures_util::pin_mut!(t1, t2);

        futures_util::select! {
            fut_1_res = t1 => fut_1_res,
            fut_2_res = t2 => fut_2_res,
        }
    }
}

fn generate_secret() -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut secret = [0; PORTAL_SECRET_SIZE];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(&mut secret)?;
    Ok(zeroize::Zeroizing::new(secret.to_vec()))
}

/// Generates, stores and send the secret back to the fd stream
async fn send_secret_to_app(app_id: &str, fd: zvariant::OwnedFd) -> Result<(), Error> {
    let service = Service::new().await?;
    let collection = match service.default_collection().await {
        Err(oo7::dbus::Error::NotFound(_)) => {
            service
                .create_collection("Default", Some(oo7::dbus::DEFAULT_COLLECTION))
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
            )
            .await?;

        secret
    };

    // Write the secret to the FD.
    let mut stream =
        tokio::net::UnixStream::from_std(UnixStream::from(std::os::fd::OwnedFd::from(fd)))?;
    stream.write_all(&secret).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), zbus::Error> {
    tracing_subscriber::fmt::init();

    tracing::info!(
        "Initializing {} {}",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let backend = Secret;
    let cnx = zbus::ConnectionBuilder::session()?
        .serve_at(oo7::portal::SecretProxy::PATH.unwrap(), backend)?
        .build()
        .await?;
    // NOTE For debugging.
    let flags = zbus::fdo::RequestNameFlags::ReplaceExisting
        | zbus::fdo::RequestNameFlags::AllowReplacement;
    cnx.request_name_with_flags(PORTAL_NAME, flags).await?;

    loop {
        pending::<()>().await;
    }
}
