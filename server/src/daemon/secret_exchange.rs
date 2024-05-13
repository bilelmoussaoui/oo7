// SecretExchange — Exchange secrets between processes in an unexposed way

// In this implementation the payload is a HashMap.
// Initial implementation uses a KeyFile.
// Secret components (key, iv, ...) are base64 encoded before transit.

use std::collections::HashMap;

use base64::prelude::*;
use oo7::{crypto, Key};

const SECRET: &str = "secret";
const PUBLIC: &str = "public";
const IV: &str = "iv";

#[derive(Debug)]
pub struct SecretExchange {
    private_key: Key,
    public_key: Key,
}

impl SecretExchange {
    pub fn secret_exchange_begin(&self) -> HashMap<&str, String> {
        let mut exchange: HashMap<&str, String> = HashMap::new();
        exchange.insert(PUBLIC, BASE64_STANDARD.encode(&self.public_key));

        exchange
    }

    pub fn secret_exchange_receive(
        &self,
        exchange_in: HashMap<&str, String>,
    ) -> Result<HashMap<&str, String>, base64::DecodeError> {
        let mut exchange_out: HashMap<&str, String> = HashMap::new();
        let secret = exchange_in.get(SECRET);
        if !secret.is_none() {
            let secret = BASE64_STANDARD.decode(secret.unwrap())?;
            let public_key = BASE64_STANDARD.decode(exchange_in.get(PUBLIC).unwrap())?;
            let public_key = Key::new(public_key);
            let iv = BASE64_STANDARD.decode(exchange_in.get(IV).unwrap())?;

            let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
            let secret = crypto::decrypt(secret, &aes_key, &iv).to_vec();

            let secret = std::str::from_utf8(&secret).unwrap().to_string();

            exchange_out.insert(SECRET, secret);
        }
        exchange_out.insert(PUBLIC, BASE64_STANDARD.encode(&self.public_key));

        Ok(exchange_out)
    }

    pub fn secret_exchange_send(
        &self,
        secret: &str,
        exchange: HashMap<&str, String>,
    ) -> Result<HashMap<&str, String>, base64::DecodeError> {
        let public_key = BASE64_STANDARD.decode(exchange.get(PUBLIC).unwrap())?;
        let public_key = Key::new(public_key);

        let aes_key = Key::generate_aes_key(&self.private_key, &public_key);
        let iv = crypto::generate_iv();
        let secret = crypto::encrypt(secret, &aes_key, &iv);

        let mut exchange: HashMap<&str, String> = HashMap::new();
        exchange.insert(SECRET, BASE64_STANDARD.encode(secret));
        exchange.insert(PUBLIC, BASE64_STANDARD.encode(&self.public_key));
        exchange.insert(IV, BASE64_STANDARD.encode(iv));

        Ok(exchange)
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

pub fn get_secret(exchange: HashMap<&str, String>) -> String {
    exchange.get(SECRET).unwrap().to_owned()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secret_exchange() {
        let secret = "password";
        let caller = SecretExchange::new();
        let callee = SecretExchange::new();
        let exchange = caller.secret_exchange_begin();
        let exchange = caller.secret_exchange_receive(exchange);
        let exchange = callee.secret_exchange_send(secret, exchange.unwrap());
        let exchange = caller.secret_exchange_receive(exchange.unwrap());

        assert_eq!(get_secret(exchange.unwrap()), secret);
    }
}
