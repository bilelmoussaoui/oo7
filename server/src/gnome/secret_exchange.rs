// SecretExchange: Exchange secrets between processes in an unexposed way.

// Initial C implementation: https://gitlab.gnome.org/GNOME/gcr/-/blob/master/gcr/gcr-secret-exchange.c

// The initial implementation of SecretExchange/GCRSecretExchange uses a KeyFile
// to encode/parse the payload. In this implementation the payload is based
// on a HashMap.
// Before any transit operations the payload is base64 encoded and parsed into a
// String.

use std::collections::HashMap;

use base64::prelude::*;
use oo7::{crypto, Key};
use zeroize::Zeroize;

const SECRET: &str = "secret";
const PUBLIC: &str = "public";
const PRIVATE: &str = "private";
const IV: &str = "iv";
const PROTOCOL: &str = "[sx-aes-1]\n";
const CIPHER_TEXT_LEN: usize = 16;

#[derive(Debug, Zeroize)]
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
    pub fn create_shared_secret(&self, exchange: &str) -> Result<String, crypto::Error> {
        let decoded = decode(exchange)
            .expect("SecretExchange decode error: failed to decode exchange string");
        let server_public_key = Key::new(
            decoded
                .get(PUBLIC)
                .expect("SecretExchange decode error: PUBLIC parameter is empty")
                .to_vec(),
        );
        // Above two calls should never fail during SecretExchange
        let aes_key =
            crate::gnome::crypto::generate_aes_key(&self.private_key, &server_public_key)?;
        let map = HashMap::from([(PRIVATE, aes_key.as_ref())]);

        Ok(encode(&map))
    }

    // Retrieves the secret from final secret exchange string
    pub fn retrieve_secret(exchange: &str, aes_key: &str) -> Option<oo7::Secret> {
        let decoded = decode(exchange)?;

        // If we cancel an ongoing prompt call, the final exchange won't have the secret
        // or IV. The following is to avoid `Option::unwrap()` on a `None` value
        let secret = decoded.get(SECRET)?;

        if secret.len() != CIPHER_TEXT_LEN {
            // To avoid a short secret/cipher-text causing an UnpadError during decryption
            let false_secret = vec![0, 1];
            return Some(oo7::Secret::from(false_secret));
        }

        let iv = decoded.get(IV)?;
        let decoded = decode(aes_key)?;
        let aes_key = Key::new(decoded.get(PRIVATE)?.to_vec());

        match crypto::decrypt(secret, &aes_key, iv) {
            Ok(decrypted) => Some(oo7::Secret::from(decrypted)),
            Err(err) => {
                tracing::error!("Failed to do crypto decrypt: {}", err);
                None
            }
        }
    }

    pub fn new() -> Result<Self, crypto::Error> {
        let private_key = Key::generate_private_key()?;
        let public_key = crate::gnome::crypto::generate_public_key(&private_key)?;

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

// Converts a HashMap into a payload String
fn encode(map: &HashMap<&str, &[u8]>) -> String {
    let mut exchange = map
        .iter()
        .map(|(key, value)| format!("{}={}", key, BASE64_STANDARD.encode(value)))
        .collect::<Vec<_>>()
        .join("\n");
    exchange.insert_str(0, PROTOCOL); // Add PROTOCOL prefix

    exchange
}

// Converts a payload String into a HashMap
fn decode(exchange: &str) -> Option<HashMap<&str, Vec<u8>>> {
    let (_, exchange) = exchange.split_once(PROTOCOL)?; // Remove PROTOCOL prefix
    let pairs = exchange.split("\n").collect::<Vec<_>>();
    let mut map: HashMap<&str, Vec<u8>> = HashMap::new();

    for pair in pairs {
        if pair.is_empty() {
            // To avoid splitting an empty line (last new line)
            break;
        }
        let (key, value) = pair.split_once("=")?;
        let encoded = BASE64_STANDARD.decode(value).unwrap_or(vec![]);
        if encoded.is_empty() {
            return None;
        }
        map.insert(key, encoded);
    }

    Some(map)
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

        let decrypted = SecretExchange::retrieve_secret(exchange, aes_key).unwrap();
        assert_eq!(b"password".to_vec(), decrypted.to_vec());
    }

    #[test]
    fn test_secret_exchange() {
        let peer_1 = SecretExchange::new().unwrap();
        let peer_1_exchange = peer_1.begin();
        let peer_2 = SecretExchange::new().unwrap();
        let peer_2_exchange = peer_2.begin();
        let peer_1_aes_key = peer_1.create_shared_secret(&peer_2_exchange).unwrap();
        let peer_2_aes_key = peer_2.create_shared_secret(&peer_1_exchange).unwrap();

        let decoded_pub = decode(&peer_2_exchange).unwrap();
        let pub_key = Key::new(decoded_pub.get(PUBLIC).unwrap().to_vec());

        let decoded_aes = decode(&peer_2_aes_key).unwrap();
        let aes_key = Key::new(decoded_aes.get(PRIVATE).unwrap().to_vec());
        let iv = crypto::generate_iv().unwrap();
        let encrypted = crypto::encrypt(b"password".to_vec(), &aes_key, &iv).unwrap();

        let map = HashMap::from([
            (PUBLIC, pub_key.as_ref()),
            (SECRET, encrypted.as_ref()),
            (IV, iv.as_ref()),
        ]);

        let final_exchange = encode(&map);

        let decrypted = SecretExchange::retrieve_secret(&final_exchange, &peer_1_aes_key).unwrap();
        assert_eq!(b"password".to_vec(), decrypted.to_vec());
    }
}
