//! Secret portal implementation code.
//!
//! It is a modified copy from ASHPD.
use std::{collections::HashMap, io::Read, os::unix::prelude::AsRawFd};

use futures::StreamExt;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use zbus::zvariant::{Fd, ObjectPath, OwnedValue, SerializeDict, Type};

use super::Error;

#[derive(SerializeDict, Type, Debug)]
/// Specified options for a [`SecretProxy::retrieve_secret`] request.
#[zvariant(signature = "dict")]
struct RetrieveOptions {
    handle_token: String,
}

impl Default for RetrieveOptions {
    fn default() -> Self {
        let mut rng = thread_rng();
        let token: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        Self {
            handle_token: format!("oo7_{}", token),
        }
    }
}

#[derive(Debug)]
pub struct SecretProxy<'a>(zbus::Proxy<'a>);

impl<'a> SecretProxy<'a> {
    /// Create a new instance of [`SecretProxy`].
    pub async fn new(connection: &zbus::Connection) -> Result<SecretProxy<'a>, Error> {
        let proxy = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.portal.Secret")?
            .path("/org/freedesktop/portal/desktop")?
            .destination("org.freedesktop.portal.Desktop")?
            .build()
            .await?;
        Ok(Self(proxy))
    }

    /// Retrieves a master secret for a sandboxed application.
    ///
    /// # Arguments
    ///
    /// * `fd` - Writable file descriptor for transporting the secret.
    #[doc(alias = "RetrieveSecret")]
    pub async fn retrieve_secret(&self, fd: &impl AsRawFd) -> Result<(), Error> {
        let options = RetrieveOptions::default();
        let cnx = self.0.connection();

        let unique_name = cnx.unique_name().unwrap();
        let unique_identifier = unique_name.trim_start_matches(':').replace('.', "_");
        let path = ObjectPath::try_from(format!(
            "/org/freedesktop/portal/desktop/request/{}/{}",
            unique_identifier, options.handle_token
        ))
        .unwrap();

        let request_proxy: zbus::Proxy = zbus::ProxyBuilder::new_bare(cnx)
            .interface("org.freedesktop.portal.Request")?
            .destination("org.freedesktop.portal.Desktop")?
            .path(path)?
            .build()
            .await?;

        let mut signal_stream = request_proxy.receive_signal("Response").await?;

        futures::try_join!(
            async {
                let message = signal_stream.next().await.unwrap();
                let (response, _details) = message.body::<(u32, HashMap<String, OwnedValue>)>()?;
                if response == 0 {
                    Ok(())
                } else {
                    Err(Error::CancelledPortalRequest)
                }
            },
            async {
                self.0
                    .call_method("RetrieveSecret", &(Fd::from(fd.as_raw_fd()), &options))
                    .await?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

pub async fn retrieve() -> Result<Vec<u8>, Error> {
    let connection = zbus::Connection::session().await?;
    let proxy = SecretProxy::new(&connection).await?;

    let (mut x1, x2) = std::os::unix::net::UnixStream::pair()?;
    proxy.retrieve_secret(&x2).await?;
    drop(x2);
    let mut buf = Vec::new();
    x1.read_to_end(&mut buf)?;

    Ok(buf)
}
