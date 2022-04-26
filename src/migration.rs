use std::collections::HashMap;

use crate::{dbus::Service, portal::Keyring, Result};

/// Helper to migrate your secrets from the host Secret Service
/// to the sandboxed file backend.
pub async fn migrate(attributes: Vec<HashMap<&str, &str>>, replace: bool) -> Result<()> {
    let service = Service::new(crate::dbus::Algorithm::Encrypted).await?;
    let file_backend = Keyring::load_default().await?;

    let collection = service.default_collection().await?;
    let mut all_items = Vec::default();

    for attrs in attributes {
        let items = collection.search_items(attrs).await?;
        all_items.extend(items);
    }
    let mut new_items = Vec::with_capacity(all_items.capacity());

    for item in all_items.iter() {
        let attributes = item.attributes().await?;
        let label = item.label().await?;
        let secret = item.secret().await?;

        new_items.push((label, attributes, secret, replace));
    }

    file_backend.create_items(new_items).await?;

    Ok(())
}
