use std::collections::HashMap;

use oo7::Keyring;

#[async_std::main]
async fn main() -> oo7::Result<()> {
    let keyring = Keyring::new().await?;
    keyring
        .create_item(
            "Some Label",
            HashMap::from([("attr", "value")]),
            b"secret",
            true,
        )
        .await?;

    let items = keyring
        .search_items(&HashMap::from([("attr", "value")]))
        .await?;

    for item in items {
        println!("{}", item.label().await?);
        println!("{:#?}", item.attributes().await?);
        println!("{:#?}", item.secret().await?);
    }

    Ok(())
}
