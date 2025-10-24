# oo7 PAM Module

A PAM (Pluggable Authentication Modules) module that integrates with the oo7 Secret Service daemon to automatically unlock keyrings during user authentication.

## Building

Build the PAM module as a shared library:

```bash
cargo build --release -p pam_oo7
```

The resulting library will be at: `target/release/libpam_oo7.so`

## Installation

### 1. Copy the PAM module

```bash
sudo cp target/release/libpam_oo7.so /usr/lib64/security/pam_oo7.so
# or on some systems:
sudo cp target/release/libpam_oo7.so /lib/x86_64-linux-gnu/security/pam_oo7.so
```

### 2. Configure PAM

Add the module to your PAM configuration. For example, in `/etc/pam.d/system-auth` or `/etc/pam.d/common-auth`:

```
auth       optional     pam_oo7.so
```

**Important**: Use `optional` so that authentication doesn't fail if the oo7 daemon is not running.

### Example PAM configuration for GDM

In `/etc/pam.d/gdm-password`:

```
#%PAM-1.0
auth       required     pam_env.so
auth       required     pam_unix.so
auth       optional     pam_oo7.so
account    required     pam_unix.so
password   required     pam_unix.so
session    required     pam_unix.so
session    optional     pam_systemd.so
```

## Configuration

### Environment Variables

- `OO7_PAM_SOCKET`: Path to the Unix domain socket for daemon communication
  - Default: `/run/oo7/pam.sock`

## License

The project is released under the MIT license.
