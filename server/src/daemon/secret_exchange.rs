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
use zeroize::Zeroizing;

const SECRET: &str = "secret";
const PUBLIC: &str = "public";
const PRIVATE: &str = "private";
const IV: &str = "iv";
const PROTOCOL: &str = "[sx-aes-1]\n";
const CIPHER_TEXT_LEN: usize = 16;
const IV_LEN: usize = 16;

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

    // Creates the shared secret: an AES key
    pub fn create_shared_secret(&self, exchange: &str) -> String {
        let decoded = decode(exchange).unwrap();
        let server_public_key = Key::new(decoded.get(PUBLIC).unwrap().to_vec());
        let aes_key =
            Key::generate_aes_key_for_secret_exchange(&self.private_key, &server_public_key);
        let map = HashMap::from([(PRIVATE, aes_key.as_ref())]);

        encode(&map)
    }

    pub fn new() -> Self {
        let private_key = Key::generate_private_key();
        let public_key = Key::generate_public_key_for_secret_exchange(&private_key);

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
        if pair.is_empty() {
            // to avoid splitting an empty line (last new line)
            break;
        }
        let (key, value) = pair.split_once("=").unwrap();
        encoded = BASE64_STANDARD.decode(value)?;
        map.insert(key, encoded);
    }

    Ok(map)
}

// Retrieves the secret from final secret exchange string
pub(crate) fn retrieve_secret(exchange: &str, aes_key: &str) -> Option<Zeroizing<Vec<u8>>> {
    let decoded = decode(exchange).unwrap();
    let secret = decoded.get(SECRET);
    if secret.is_none() {
        // if we cancel an ongoing prompt call, the final exchange won't have the secret
        // or iv. this check is implemented to avoid `Option::unwrap()` on a `None`
        // value
        return None;
    }
    let secret = secret.unwrap();
    let iv = decoded.get(IV).unwrap();

    if iv.len() != IV_LEN {
        panic!("Invalid IV");
    }

    if secret.len() != CIPHER_TEXT_LEN {
        panic!("Invalid length for cipher text");
    }

    let decoded = decode(aes_key).unwrap();
    let aes_key = Key::new(decoded.get(PRIVATE).unwrap().to_vec());

    Some(crypto::decrypt(secret, &aes_key, iv))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_retrieve_secret() {
        let exchange = "[sx-aes-1]
public=/V6FpknNXlOGJwPqXtN0RaED2bS5JyYbftv7WbD0gWiVTMoNgxkAuOX2g+zUO/4TdfBJ6viPRcNdYV+KcxskGvhYouFXs+IgKqNO0MF0CNnWra1I6G56SM4Bgstkx9M5J+1f83l/BTAxlLsAppeLkqEEVSQoy9jXhPOrl5XlIzF2DvriYh+FInB7SFz4VzE3KVq40p7tA9+iAVQg1o9qkQHLazFb1DfbWRgvhDVhwNkk1fIlepIeM426gdmHIAxP
secret=DBeLBvEgGuGygDm+XnkxyQ==
iv=8e3N+gx553PgQlfTKRK3JA==";

        let aes_key = "[sx-aes-1]
private=zDWLKDent/C//LquHCTlGg==";

        let decrypted = retrieve_secret(exchange, aes_key).unwrap();
        assert_eq!(b"password".to_vec(), decrypted.to_vec());
    }
}
