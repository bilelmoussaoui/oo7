use crate::Session;

pub struct Secret<'a> {
    session: Session<'a>,
    parameteres: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

impl <'a> Secret<'a> {
    /// Session used to encode the secret
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Algorithm dependant parameters for secret value encoding
    pub fn parameters(&self) -> &[u8] {
        &self.parameteres
    }

    /// Possibily encoded secret value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Content type of the secret
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}