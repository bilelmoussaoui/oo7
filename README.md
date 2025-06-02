# OO7

[![docs](https://docs.rs/oo7/badge.svg)](https://docs.rs/oo7/) [![crates.io](https://img.shields.io/crates/v/oo7)](https://crates.io/crates/oo7) ![CI](https://github.com/bilelmoussaoui/oo7/workflows/CI/badge.svg)

James Bond went on a new mission and this time as a [Secret Service provider](https://specifications.freedesktop.org/secret-service-spec/latest/).

The repository consists of the following projects:

- [cargo-credential](./cargo-credential/): a [cargo credential](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#registry-authentication) provider
- [cli](./cli/): a secret-tool replacement
- [client](./client/): the client side library
- [portal](./portal/): [org.freedesktop.impl.portal.Secret](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html) implementation
- [server](./server/): [org.freedesktop.secrets](https://specifications.freedesktop.org/secret-service-spec/latest/) server implementation

## Hacking on oo7 services

The oo7-daemon and oo7-portal services can be tested using
[systemd-sysext][systemd-sysext].

First build the services on each subdirectory with

```sh
meson setup --prefix=/usr _build
meson compile -C _build
DESTDIR=oo7-extension meson install -C _build
```

which will create a `oo7-extension` directory under `_build`, which can be moved
to `/run/extensions`, afterwards extensions can be reloaded via

```sh
systemd-sysext refresh --force
```

**WARNING**: In Fedora Silverblue one needs to disable SELinux via `setenforce
0` before loading any system extensions.

The daemon can be then simply started with:
```sh
/usr/libexec/oo7-daemon --replace --verbose
```

In order to load the portal, one needs a [portals.conf][portals.conf] file at
`/etc/xdg-desktop-portal/portals.conf`. This can be achieved with
`systemd-confext` by adding a file to the extension at
`_build/oo7-extension/etc/xdg-desktop-portal/portals.conf` with contents:

```toml
[preferred]
default=gnome;gtk;  # replace `gnome` if using a different DE
org.freedesktop.impl.portal.Secret=oo7-portal;
```

and restart `xdg-desktop-portal` with

```sh
systemd-confext refresh --force
systemctl restart --user xdg-desktop-portal
```

If more output is required, the later can be replaced with:

```sh
/usr/libexec/xdg-desktop-portal --replace --verbose
```

## License

The project is released under the MIT license.

[portals.conf]: https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html
[systemd-sysext]: https://www.freedesktop.org/software/systemd/man/latest/systemd-sysext.html
