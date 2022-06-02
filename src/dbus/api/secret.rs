use std::sync::Arc;

use serde::{ser::SerializeTuple, Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Session;
use crate::{crypto, dbus::Error, Key};

#[derive(Debug, Serialize, Deserialize, Type)]
#[zvariant(signature = "(oayays)")]
pub(crate) struct SecretInner(pub OwnedObjectPath, pub Vec<u8>, pub Vec<u8>, pub String);

#[derive(Debug, Type, Zeroize, ZeroizeOnDrop)]
#[zvariant(signature = "(oayays)")]
pub struct Secret<'a> {
    #[zeroize(skip)]
    pub(crate) session: Arc<Session<'a>>,
    pub(crate) parameters: Vec<u8>,
    pub(crate) value: Vec<u8>,
    #[zeroize(skip)]
    pub(crate) content_type: String,
}

impl<'a> Secret<'a> {
    pub(crate) fn new<P: AsRef<[u8]>>(
        session: Arc<Session<'a>>,
        secret: P,
        content_type: &str,
    ) -> Self {
        Self {
            session,
            parameters: vec![],
            value: secret.as_ref().to_vec(),
            content_type: content_type.to_owned(),
        }
    }

    pub(crate) fn new_encrypted<P: AsRef<[u8]>>(
        session: Arc<Session<'a>>,
        secret: P,
        content_type: &str,
        aes_key: &Key,
    ) -> Self {
        let iv = crypto::generate_iv();
        let secret = crypto::encrypt(secret.as_ref(), aes_key, &iv);
        Self {
            session,
            parameters: iv.to_vec(),
            value: secret,
            content_type: content_type.to_owned(),
        }
    }

    pub(crate) async fn from_inner(
        cnx: &zbus::Connection,
        inner: SecretInner,
    ) -> Result<Secret<'_>, Error> {
        let secret = Secret {
            session: Arc::new(Session::new(cnx, inner.0).await?),
            parameters: inner.1,
            value: inner.2,
            content_type: inner.3,
        };
        Ok(secret)
    }

    /// Session used to encode the secret
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Algorithm dependent parameters for secret value encoding
    pub fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    /// Possibly encoded secret value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Content type of the secret
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

impl<'a> Serialize for Secret<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple_serializer = serializer.serialize_tuple(4)?;
        tuple_serializer.serialize_element(self.session().inner().path())?;
        tuple_serializer.serialize_element(self.parameters())?;
        tuple_serializer.serialize_element(self.value())?;
        tuple_serializer.serialize_element(self.content_type())?;
        tuple_serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature() {
        assert_eq!(Secret::signature(), "(oayays)");
    }
}
