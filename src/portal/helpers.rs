use std::collections::HashMap;

use super::api::Item;
use super::{Error, Keyring};

pub async fn password_store(
    label: &str,
    attributes: HashMap<&str, &str>,
    password: &[u8],
    replace: bool,
) -> Result<(), Error> {
    let storage = Keyring::load_default().await?;
    storage
        .create_item(label, attributes, password, replace)
        .await?;
    storage.write().await
}

pub async fn password_lookup(attributes: HashMap<&str, &str>) -> Result<Vec<Item>, Error> {
    let storage = Keyring::load_default().await?;
    storage.search_items(attributes).await
}

pub async fn password_clear(attributes: HashMap<&str, &str>) -> Result<(), Error> {
    let storage = Keyring::load_default().await?;
    storage.delete(attributes).await?;
    storage.write().await
}
