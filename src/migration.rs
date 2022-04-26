use std::collections::HashMap;

use crate::{dbus::Service, portal::Keyring, Result};

/// Helper to migrate your secrets from the host Secret service
/// to the sandboxed file backend.
pub async fn migrate(attributes: HashMap<&str, &str>, replace: bool) -> Result<()> {
    let service = Service::new(crate::dbus::Algorithm::Encrypted).await?;
    let file_backend = Keyring::load_default().await?;

    let collection = service.default_collection().await?;
    let items = collection.search_items(attributes).await?;

    for item in items {
        let attributes = item.attributes().await?;
        let attributes = attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        file_backend
            .create_item(
                &item.label().await?,
                attributes,
                &item.secret().await?,
                replace,
            )
            .await?
    }

    Ok(())
}
