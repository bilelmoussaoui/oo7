use std::collections::HashMap;

use once_cell::sync::OnceCell;
use oo7::Keyring;

static KEYRING: OnceCell<Keyring> = OnceCell::new();

#[async_std::main]
async fn main() -> oo7::Result<()> {
    let keyring = Keyring::new().await?;
    KEYRING.set(keyring).unwrap();

    KEYRING
        .get()
        .unwrap()
        .create_item(
            "Some Label",
            HashMap::from([("attr", "value")]),
            b"secret",
            true,
        )
        .await?;

    let items = KEYRING
        .get()
        .unwrap()
        .search_items(&HashMap::from([("attr", "value")]))
        .await?;

    for item in items {
        println!("{}", item.label().await?);
        println!("{:#?}", item.attributes().await?);
        println!("{:#?}", item.secret().await?);
    }

    Ok(())
}
