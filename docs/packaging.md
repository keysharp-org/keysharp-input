# Packaging and installation policy

This document covers packaging integration, the portable-versus-distribution
installation rules, and removal policy. For ordinary build and install steps see
the [README](../README.md).

## Packaged installs

Packaging installs that use `DESTDIR` must run the following from their post-install step:

```bash
keysharp-inputd --install-input-access
```

The setup command returns a bitmask: bit `1` means persistent configuration
files could not be installed and bit `2` means live udev/module/systemd
activation was incomplete. Debian upgrades tolerate bit `2` with a warning so
the installed files remain usable after the host-side issue is corrected; file
installation failures remain fatal.

The setup owns `/etc/modules-load.d/keysharp-input.conf`; it never overwrites or
deletes the generic `uinput.conf`, which may belong to another application or
the administrator. A distribution package's rule in `/usr/lib/udev/rules.d` is
authoritative. Portable installs create the equivalent `/etc/udev/rules.d`
rule, while package setup removes only an exact stale portable copy and keeps a
modified administrator override.

Tagged releases publish these assets for both x64 and arm64:

- `keysharp-input-<version>-linux-<arch>.tar.gz`
- `keysharp-input_<version>_<deb-arch>.deb`
- `SHA256SUMS` and GitHub artifact attestations

Tar and Debian releases do not depend on Nix and remain publishable without a
`flake.lock`. To enable the Nix CI check, generate and commit `flake.lock` on a
machine with Nix, run `nix flake check --no-write-lock-file`, and review the
pinned revision and content hash. Do not hand-author a `narHash`. Until that
reviewed file is committed, CI reports that it skipped Nix validation; it never
creates or updates a lock implicitly.

Package and source installs expose the public C wire contract at
`include/keysharp-inputd/protocol.h` and install the protocol, identity,
permission-store, and physical-test documentation below the component's
standard documentation directory. The portable archive carries the same
header and `docs/` tree and installs them below `/usr/local`.


## Portable archives and distribution packages

Release binaries are built natively on Ubuntu 22.04 and target its glibc 2.35
baseline. Newer compatible distributions can use the portable archive; Debian
packages additionally declare their resolved shared-library dependencies.

The portable archive has a root `install.sh`. Integrators that merely need a
compatible broker can use `sudo ./install.sh --skip-if-compatible`; it probes
`keysharp-inputd --info`, verifies that the systemd service launches that
binary in system-service mode, and requires the exact socket settings, polkit
policy, tmpfiles declaration, and uaccess rule to be complete
before leaving a protocol-1.2 installation untouched. It refuses to
layer `/usr/local` files over a distribution- or
Nix-managed installation; an incomplete managed installation must be repaired
through its package or declarative configuration. The portable uninstaller
likewise refuses to remove files while another installation root is present.
The Debian package makes the inverse transition equally explicit: its preinstall
script refuses to unpack over a distinct `/usr/local/bin/keysharp-inputd` or
non-package units at the portable paths in `/etc/systemd/system`. Any such unit
would shadow the package's unit even if its contents had been modified. Remove
the portable installation with
`sudo /usr/local/share/doc/keysharp-input/uninstall.sh` before installing the
package. A `/usr/local/bin/keysharp-inputd` symlink that resolves to the
packaged `/usr/bin/keysharp-inputd` is not treated as a portable binary.
Before copying files, a fresh install verifies that the bundled
binary can load its libudev/libevdev dependencies and that `/usr/bin/pkcheck` is
available. The installer keeps a separate uninstaller at
`/usr/local/share/doc/keysharp-input/uninstall.sh`. Removing an application that
uses the broker must not invoke it: the broker can have other clients. Run it
only after checking that no other application uses the component. It always
preserves the shared permission namespace.

Distribution client packages should express their relationship to
`keysharp-input` through the package manager (`Depends`, `Recommends`, or the
equivalent appropriate to whether input features are optional). They must not
run this uninstaller from their own removal scripts. The package manager can
then retain the broker while any installed client still needs it; ordinary
package removal and package purge both preserve shared grants. Revoke grants
through the authenticated permission CLI instead.

Each installation carries its own identically scoped `tmpfiles.d` declaration
for `/var/lib/keysharp-permissions/v1` and `/run/keysharp-permissions`. Removing
one declaration leaves both directories and the other component's declaration
untouched. The shared paths intentionally are not a service `StateDirectory`
or `RuntimeDirectory`: `systemctl clean` on one stopped service can remove such
directories even while another broker still uses them.

