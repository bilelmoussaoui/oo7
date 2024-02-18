# OO7

[![docs](https://docs.rs/oo7/badge.svg)](https://docs.rs/oo7/) [![crates.io](https://img.shields.io/crates/v/oo7)](https://crates.io/crates/oo7) ![CI](https://github.com/bilelmoussaoui/oo7/workflows/CI/badge.svg)

James Bond went on a new mission and this time as a [Secret Service provider](https://specifications.freedesktop.org/secret-service/latest/).

The library consists of two modules:

- An implementation of the Secret Service specifications using [zbus](https://lib.rs/zbus). Which sends the secrets to a DBus implementation of the `org.freedesktop.Secrets` interface that stores them somewhere safe.

- A file backend using the `org.freedesktop.portal.Secrets` portal to retrieve the service's key to encrypt the file with.
The file format is compatible with [libsecret](https://gitlab.gnome.org/GNOME/libsecret/).

Sandboxed applications should prefer using the file backend as it doesn't expose the application secrets to other sandboxed applications if they can talk to the `org.freedesktop.Secrets` service.

The library provides helper methods to store and retrieve secrets and uses either the DBus interface or the file backend based on whether the application is sandboxed or not.

## Goals

- Async only API
- Ease to use
- Integration with the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html) if sandboxed
- Provide API to migrate from host secrets to sandboxed ones

## Examples

### Basic usage

```rust,no_run
use std::collections::HashMap;

async fn run() -> oo7::Result<()> {
    let keyring = oo7::Keyring::new().await?;
    let attributes = HashMap::from([("attribute", "attribute_value")]);

    // Store a secret
    keyring
        .create_item("Item Label", &attributes, b"secret", true).await?;

    // Find a stored secret
    let items = keyring.search_items(&attributes).await?;

    // Delete a stored secret
    keyring.delete(&attributes).await?;

    // Unlock the collection if the Secret Service is used
    keyring.unlock().await?;

    // Lock the collection if the Secret Service is used
    keyring.lock().await?;
    Ok(())
}
```

If your application makes heavy usage of the keyring like a password manager. You could store an instance of the `Keyring` in a `OnceCell` / `OnceLock` / `Lazy`

```rust,ignore
use std::sync::OnceLock;
use std::collections::HashMap;

static KEYRING: OnceLock<oo7::Keyring> = OnceLock::new();

fn main() {
    // SOME_RUNTIME could be a tokio/async-std/glib runtime
    SOME_RUNTIME.block_on(async {
        let keyring = oo7::Keyring::new()
            .await
            .expect("Failed to start Secret Service");
        KEYRING.set(keyring);
    });

    // Then to use it
    SOME_RUNTIME.spawn(async {
        let items = KEYRING
            .get()
            .unwrap()
            .search_items(&HashMap::from([("attribute", "attribute_value")]))
            .await;
    });
}
```

### Migrating your secrets to the file backend

The library also comes with API to migrate your secrets from the host Secret Service to the sandboxed file backend. Note that the items are removed from the host keyring if they are migrated successfully.

```rust,ignore
use std::collections::HashMap;

// SOME_RUNTIME could be a tokio/async-std/glib runtime
SOME_RUNTIME.block_on(async {
    match oo7::migrate(vec![HashMap::from([("attribute", "attribute_value")])], true).await {
        Ok(_) => {
            // Store somewhere the migration happened, to avoid re-doing it at every startup
        }
        Err(err) => log::error!("Failed to migrate secrets {err}"),
    }
});
```

## Optional features

| Feature | Description | Default |
| ---     | ----------- | ------ |
| `tracing` | Record various debug information using the `tracing` library | No |
| `async-std` | Use `async-std` APIs for IO/filesystem operations | Yes |
| `tokio` | Use `tokio` APIs for IO/Filesystem operations | No |
| `native_crypto` | Use Rust Crypto crates for cryptographic primitives | Yes |
| `openssl_crypto` | Use `openssl` crate for cryptographic primitives | No |
| `unstable` | Unlock internal APIs | No |

## How does it compare to other libraries?

- [libsecret-rs](https://gitlab.gnome.org/World/Rust/libsecret-rs) provides Rust bindings of the C library [libsecret](https://gitlab.gnome.org/GNOME/libsecret/). The current main pain point with it is that
it does assume things for you so it will either use the host or the sandbox file-based keyring which makes migrating your secrets
to inside the sandbox a probably impossible task. There are also issues like <https://gitlab.gnome.org/GNOME/libsecret/-/issues/58>
that makes it not usable inside the Flatpak sandbox.

- [secret-service-rs](https://github.com/hwchen/secret-service-rs/) uses [zbus](https://lib.rs/zbus) internally as well but does provide a sync only API, hasn't seen an update in a while, doesn't integrate with [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html) if sandboxed.

## License

The project is released under the MIT license.

## Credits

- [secret-service-rs](https://github.com/hwchen/secret-service-rs/) for the encrypted Secret Service implementation.
