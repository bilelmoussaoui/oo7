use std::sync::Arc;

use serde::{ser::SerializeTuple, Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};

use super::Session;
use crate::{dbus::Algorithm, dbus::utils, Result};

#[derive(Debug, Serialize, Deserialize, Type)]
#[zvariant(signature = "(oayays)")]
pub(crate) struct SecretInner(pub OwnedObjectPath, pub Vec<u8>, pub Vec<u8>, pub String);

#[derive(Debug, Type)]
#[zvariant(signature = "(oayays)")]
pub struct Secret<'a> {
    pub(crate) session: Arc<Session<'a>>,
    pub(crate) parameters: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) content_type: String,
}

impl<'a> Secret<'a> {
    pub(crate) fn new(
        algorithm: Arc<Algorithm>,
        session: Arc<Session<'a>>,
        secret: &[u8],
        content_type: &str,
    ) -> Self {
        let (value, parameters) = match algorithm.as_ref() {
            Algorithm::Plain => (secret.to_vec(), vec![]),
            Algorithm::Encrypted(aes_key) => utils::encrypt(secret, aes_key).unwrap(),
        };
        Self {
            session,
            parameters,
            value,
            content_type: content_type.to_owned(),
        }
    }

    pub(crate) async fn from_inner(
        cnx: &zbus::Connection,
        inner: SecretInner,
    ) -> Result<Secret<'_>> {
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
