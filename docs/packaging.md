# Packaging

The 0.2.0 package contains one executable, one shared client library, its public
headers, and two systemd units:

```text
/usr/bin/keysharp-input
/usr/lib/libkeysharp-input.so.0.2.0
/usr/lib/libkeysharp-input.so.0 -> libkeysharp-input.so.0.2.0
/usr/lib/libkeysharp-input.so -> libkeysharp-input.so.0
/usr/include/keysharp_input/client.h
/usr/include/keysharp_input/constants.h
/usr/lib/pkgconfig/keysharp-input.pc
/usr/lib/cmake/KeysharpInput/
/usr/lib/systemd/system/keysharp-input.service
/usr/lib/systemd/system/keysharp-input.socket
```

The package also installs one polkit policy, one udev rule, and one tmpfiles
declaration. The service socket is
`/run/keysharp-input/keysharp-input.sock`.

Debian metadata provides `keysharp-input-client-abi-0` with version `0.<minor>`
derived from the public header, independent of the product release. Consumers can
require an additive API with a versioned dependency. Applications depend on
the client ABI; the daemon protocol is private to the matching client library.

After a staged package install, run:

```bash
keysharp-input daemon --install-input-access
```

This loads uinput, refreshes udev, reloads systemd, and starts the service. The
command returns bit 1 for persistent configuration failure and bit 2 for live
activation failure.

## Release artifacts

Tags publish x64 and arm64 archives and Debian packages:

```text
keysharp-input-<version>-linux-<x64|arm64>.tar.gz
keysharp-input_<version>_<amd64|arm64>.deb
SHA256SUMS
```

Archives contain the executable, SONAME library, public headers, pkg-config and
CMake metadata, service files, policy, rule, installer, and standalone docs.

`install.sh --skip-if-compatible` leaves an installed package or portable copy
untouched when its public client ABI and required runtime resources are
compatible and complete. The portable installer refuses to overwrite a
package-managed installation. Debian pre-install similarly refuses to shadow a
portable binary, SONAME library, or unit below `/usr/local` and
`/etc/systemd/system`.

The portable uninstaller removes only its known `/usr/local` files and exact
service support files. It never removes `/var/lib/keysharp-permissions` or
`/run/keysharp-permissions`. Another application's uninstaller must not invoke
it; package-manager dependency tracking decides when the broker is unused.

## NixOS

The flake exports a package and `nixosModules.default`:

```nix
{
  services.keysharp-input.enable = true;
}
```

The module loads uinput, enables polkit, installs the device rule, and starts
`keysharp-input.service` with its socket.
