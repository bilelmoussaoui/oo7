use std::collections::HashMap;

use oo7::Keyring;

#[tokio::main]
async fn main() -> oo7::Result<()> {
    let keyring = Keyring::new().await?;
    let attributes = HashMap::from([("attr", "value")]);
    keyring
        .create_item("Some Label", &attributes, b"secret", true)
        .await?;

    let items = keyring.search_items(&attributes).await?;

    for item in items {
        println!("{}", item.label().await?);
        println!("{:#?}", item.attributes().await?);
        println!("{:#?}", item.secret().await?);
    }

    Ok(())
}
