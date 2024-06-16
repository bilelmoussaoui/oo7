// SecretExchange: Exchange secrets between processes in an unexposed way.

// Initial C implementation: https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/gcr-secret-exchange.c

// The initial implementation of SecretExchange/GCRSecretExchange uses a KeyFile
// to encode/parse the payload. And in this implementation the payload is based
// on a HashMap.
// Before any transit operations the payload is base64 encoded and parsed into a
// String.

use std::collections::HashMap;

use base64::prelude::*;
use oo7::{crypto, Key};

const SECRET: &str = "secret";
const PUBLIC: &str = "public";
const IV: &str = "iv";
const PROTOCOL: &str = "[sx-aes-1]\n";

#[derive(Debug)]
pub struct SecretExchange {
    private_key: Key,
    public_key: Key,
}

impl SecretExchange {
    // Creates the initial payload containing caller public_key
    pub fn begin(&self) -> String {
        let map = HashMap::from([(PUBLIC, self.public_key.as_ref())]);

        encode(&map)
    }

    // Decrypt and retrieve secret
    pub fn receive(&self, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();
        let mut encrypted: Vec<u8> = Vec::new();
        let mut map: HashMap<&str, &[u8]> = HashMap::new();

        let secret = decoded.get(SECRET);
        if secret.is_some() {
            let secret = secret.unwrap();
            let public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
            let iv = decoded.get(IV).unwrap();

            let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
            encrypted = crypto::decrypt(secret, &aes_key, &iv).to_vec();

            map.insert(SECRET, &encrypted);
        }
        map.insert(PUBLIC, self.public_key.as_ref());

        encode(&map)
    }

    // Send Secret and perform encryption
    pub fn send(&self, secret: &str, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();

        let public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
        let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
        let iv = crypto::generate_iv();

        let secret = crypto::encrypt(secret, &aes_key, &iv);

        let map = HashMap::from([
            (PUBLIC, self.public_key.as_ref()),
            (SECRET, secret.as_ref()),
            (IV, iv.as_ref()),
        ]);

        encode(&map)
    }

    pub fn new() -> Self {
        let private_key = Key::generate_private_key();
        let public_key = Key::generate_public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }
}

// Convert a HashMap into a payload String
fn encode(map: &HashMap<&str, &[u8]>) -> String {
    let mut exchange = map
        .iter()
        .map(|(k, v)| format!("{}={}", k, BASE64_STANDARD.encode(v)))
        .collect::<Vec<_>>()
        .join("\n");
    exchange.insert_str(0, PROTOCOL); // to add PROTOCOL prefix

    exchange
}

// Convert a payload String into a HashMap
fn decode(exchange: &str) -> Result<HashMap<&str, Vec<u8>>, base64::DecodeError> {
    let (_, exchange) = exchange.split_once(PROTOCOL).unwrap(); // to remove PROTOCOL prefix
    let pairs = exchange.split("\n").collect::<Vec<_>>();
    let mut map: HashMap<&str, Vec<u8>> = HashMap::new();
    let mut encoded: Vec<u8> = Vec::new();

    for pair in pairs {
        let (key, value) = pair.split_once("=").unwrap();
        encoded = BASE64_STANDARD.decode(value)?;
        map.insert(key, encoded);
    }

    Ok(map)
}

// Retrieve secret from the payload
pub fn get_secret(exchange: &str) -> Result<String, std::str::Utf8Error> {
    let decoded = decode(&exchange).unwrap();
    let secret = std::str::from_utf8(&decoded.get(SECRET).unwrap().to_vec())?
        .to_string()
        .to_owned();

    Ok(secret)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secret_exchange() {
        let secret = "password";
        let caller = SecretExchange::new();
        let callee = SecretExchange::new();
        let exchange = begin();
        let exchange = receive(&exchange);
        let exchange = send(secret, &exchange);
        let exchange = receive(&exchange);

        assert_eq!(get_secret(&exchange).unwrap(), secret);
    }
}
