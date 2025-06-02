# oo7-server

![CI](https://github.com/bilelmoussaoui/oo7/workflows/CI/badge.svg)

The new D-Bus Secret Service provider. Replacement of the `gnome-keyring-daemon`

## Unlocking the session keyring

The session keyring is generally encrypted with the user's password. In order to
unlock it the daemon has to be started with the `--login` flag.

Alternatively, the daemon will try to load a
[credential](https://systemd.io/CREDENTIALS/) named
`oo7.keyring-encryption-password` and use it to unlock the session keyring.

At the moment, this requires systemd v258 or newer to load the credential from
the user's credstore when starting the service. In such a case the credential
can be stored as an encrypted blob in the user's credstore via

``` sh
mkdir -p ${XDG_CONFIG_HOME:-~/.config}/credstore.encrypted
systemd-ask-password -n | systemd-creds encrypt --user --name=oo7.keyring-encryption-password - ${XDG_CONFIG_HOME:-~/.config}/credstore.encrypted/oo7.keyring-encryption-password
```

**WARNING**: Any user capable of reading this file and with access to the TPM
(e.g the `root` user) can decrypt this blob. This can be mitigated if using an
encrypted home with [systemd-homed](https://systemd.io/HOME_DIRECTORY/).

See the manual page `systemd.exec(5)` for more details.

## License

The project is released under the MIT license.
