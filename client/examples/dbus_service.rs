use std::collections::HashMap;

use oo7::dbus::Service;

#[async_std::main]
async fn main() -> oo7::Result<()> {
    let service = Service::new().await?;

    let mut attributes = HashMap::new();
    attributes.insert("type", "token");
    let collection = service.default_collection().await?;
    let items = collection.search_items(&attributes).await?;
    for item in items {
        println!("{}", item.label().await?);
        println!("{}", item.is_locked().await?);
        println!("{:#?}", item.created().await?);
        println!("{:#?}", item.modified().await?);
        println!("{:#?}", item.attributes().await?);
        println!("{:#?}", item.secret().await?);
    }
    Ok(())
}
