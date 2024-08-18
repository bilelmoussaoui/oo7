use crate::{dbus::Service, portal::Keyring, AsAttributes, Result};

/// Helper to migrate your secrets from the host Secret Service
/// to the sandboxed file backend.
///
/// If the migration is successful, the items are removed from the host
/// Secret Service.
pub async fn migrate(attributes: Vec<impl AsAttributes>, replace: bool) -> Result<()> {
    let service = Service::new().await?;
    let file_backend = match Keyring::load_default().await {
        Ok(portal) => Ok(portal),
        Err(crate::portal::Error::PortalNotAvailable) => {
            #[cfg(feature = "tracing")]
            tracing::debug!("Portal not available, no migration to do");
            return Ok(());
        }
        Err(err) => Err(err),
    }?;

    let collection = service.default_collection().await?;
    let mut all_items = Vec::default();

    for attrs in attributes {
        let items = collection.search_items(&attrs).await?;
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

    for item in all_items.iter() {
        item.delete(None).await?;
    }

    Ok(())
}
