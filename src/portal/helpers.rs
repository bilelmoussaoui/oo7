use std::collections::HashMap;

use super::api::Item;
use super::{Error, Keyring};

pub async fn insert_replace(item: &Item) -> Result<(), Error> {
    let mut storage = Keyring::load_default().await?;
    storage
        .keyring
        .remove_items(item.attributes().clone(), &storage.key)?;
    storage.keyring.items.push(item.encrypt(&storage.key)?);
    storage.write().await
}

pub async fn lookup(
    attributes: HashMap<impl AsRef<str>, impl AsRef<str>>,
) -> Result<Vec<Item>, Error> {
    let storage = Keyring::load_default().await?;
    storage.keyring.search_items(attributes, &storage.key)
}

pub async fn remove(attributes: HashMap<impl AsRef<str>, impl AsRef<str>>) -> Result<(), Error> {
    let mut storage = Keyring::load_default().await?;
    storage.keyring.remove_items(attributes, &storage.key)?;
    storage.write().await
}
