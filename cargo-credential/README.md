
# cargo-credential-oo7

[![crates.io](https://img.shields.io/crates/v/cargo-credential-oo7)](https://crates.io/crates/cargo-credential-oo7)

A [cargo credential provider](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#registry-authentication) built using oo7 instead of [libsecret](https://github.com/rust-lang/cargo/tree/master/credential/cargo-credential-libsecret).


## Installation

1 - `cargo install cargo-credential-oo7`

2 - Set as the default [credential provider](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html)

```toml
[registry]
global-credential-providers = ["cargo-credential-oo7"]
```

## License

The project is released under the MIT license.
