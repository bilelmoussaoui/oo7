use std::collections::HashMap;

use oo7::Service;

#[tokio::main]
async fn main() -> oo7::Result<()> {
    let cnx = zbus::ConnectionBuilder::session()?.build().await?;
    let service = Service::new(&cnx).await?;
    let collections = service.collections().await?;

    for collection in collections {
        println!("{}", collection.label().await?);
        println!("{}", collection.is_locked().await?);
        println!("{:#?}", collection.created().await?);
        println!("{:#?}", collection.modified().await?);

        let mut attributes = HashMap::new();
        attributes.insert("type", "token");
        let items = collection.search_items(attributes).await?;
        for item in items {
            println!("{}", item.label().await?);
            println!("{}", item.is_locked().await?);
            println!("{:#?}", item.created().await?);
            println!("{:#?}", item.modified().await?);
            println!("{:#?}", item.attributes().await?);
        }
    }

    Ok(())
}
