use std::collections::HashMap;

use crate::{dbus::Service, portal::Keyring, Result};

/// Helper to migrate your secrets from the host Secret Service
/// to the sandboxed file backend.
pub async fn migrate(attributes: HashMap<&str, &str>, replace: bool) -> Result<()> {
    let service = Service::new(crate::dbus::Algorithm::Encrypted).await?;
    let file_backend = Keyring::load_default().await?;

    let collection = service.default_collection().await?;
    let items = collection.search_items(attributes).await?;

    let mut new_items = Vec::with_capacity(items.capacity());

    for item in items.iter() {
        let attributes = item.attributes().await?;
        let label = item.label().await?;
        let secret = item.secret().await?;

        new_items.push((label, attributes, secret, replace));
    }

    file_backend.create_items(new_items).await?;

    Ok(())
}
