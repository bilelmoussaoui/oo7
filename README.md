# OO7

[![docs](https://docs.rs/oo7/badge.svg)](https://docs.rs/oo7/) [![crates.io](https://img.shields.io/crates/v/oo7)](https://crates.io/crates/oo7) ![CI](https://github.com/bilelmoussaoui/oo7/workflows/CI/badge.svg)

James Bond went on a new mission and this time as a [Secret Service provider](https://specifications.freedesktop.org/secret-service-spec/latest/).

The repository consists of the following projects:

- [cargo-credential](./cargo-credential/): a [cargo credential](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#registry-authentication) provider
- [cli](./cli/): a secret-tool replacement
- [client](./client/): the client side library
- [portal](./portal/): [org.freedesktop.impl.portal.Secret](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html) implementation
- [server](./server/): [org.freedesktop.secrets](https://specifications.freedesktop.org/secret-service-spec/latest/) server implementation

## License

The project is released under the MIT license.
