# OO7

![CI](https://github.com/bilelmoussaoui/oo7/workflows/CI/badge.svg)

WIP!

James Bond went on a new mission and this time as a [secret service provider](https://specifications.freedesktop.org/secret-service/latest/).

The library consists of a Rust implementation of the Secret Sevice specifications using [zbus](https://lib.rs/zbus).


## Goals

- Async only API
- Ease to use
- Integration with the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) if sandboxed
- Provide API to migrate from host secrets to sandboxed ones

## How does it compare to other libraries?

- `libsecret-rs` provides Rust bindings of the C library `libsecret`. The current main pain point with it is that
it does assume things for you so it will either use the host or the sandbox file-based keyring which makes migrating your secrets
to inside the sandbox a probably impossible task. There are also issues like <https://gitlab.gnome.org/GNOME/libsecret/-/issues/58>
that makes it not usable inside the Flatpak sandbox.

- `secret-service-rs` uses zbus internally as well but does provide a sync only API, hasn't seen an update in a while, doesn't integrate with [Secret portal](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) if sandboxed

# License

To be figured out

