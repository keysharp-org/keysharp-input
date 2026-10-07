# Packaging

The package contains one executable, one shared client library, its public
headers, and two systemd units:

```text
/usr/bin/keysharp-input
/usr/lib/libkeysharp-input.so.<product-version>
/usr/lib/libkeysharp-input.so.<abi-major> -> libkeysharp-input.so.<product-version>
/usr/lib/libkeysharp-input.so -> libkeysharp-input.so.<abi-major>
/usr/include/keysharp_input/client.h
/usr/include/keysharp_input/constants.h
/usr/include/keysharp_input/devices.h
/usr/lib/pkgconfig/keysharp-input.pc
/usr/lib/cmake/KeysharpInput/
/usr/lib/systemd/system/keysharp-input.service
/usr/lib/systemd/system/keysharp-input.socket
```

The package also installs one polkit policy, one udev rule, and one tmpfiles
declaration. The service socket is
`/run/keysharp-input/keysharp-input.sock`.

Debian metadata provides `keysharp-input-client-abi-<major>` with version `<major>.<minor>`
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
CMake metadata, service files, policy, installer, and standalone docs.

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

## Launchpad PPA

Each release is also uploaded to `ppa:descolada/keysharp`, which carries Keysharp
and keysharp-desktop as well, for the Ubuntu series listed in `PPA_SERIES` in the
release workflow. `packaging/debian/` is the single package definition: CPack takes
its maintainer scripts, and Launchpad builds the same package from a source upload
that `packaging/ppa/build-source.sh` makes of the tagged tree and its submodule.
Both builds read the client ABI capability from the public header.

Launchpad accepts each version once, so the workflow first builds every series and
architecture from that upload with `packaging/ppa/rehearse.sh`: in a clean container
of the series, offline and unprivileged, as Launchpad does. Rerunning the workflow
uploads only what the PPA lacks. Each signed upload is attempted up to three times,
with 10 and 20 second delays between failures; signed files stay identical across
attempts, and an accepted version is skipped before trying again.

Dispatch the Release workflow from `main` with `ppa_only=true` to build, rehearse
and upload PPA packages for a release tag. Set `RELEASE_TAG` to that tag and
`PPA_REVISION` to the packaging revision:

```bash
gh workflow run release.yml --repo keysharp-org/keysharp-input --ref main \
  -f tag="$RELEASE_TAG" -f ppa_only=true -f ppa_revision="$PPA_REVISION"
```

The package version is `<version>-1~<series><revision>`. Use revision `1` for
the first upload and a higher unused revision for a new upload of the same release.
Launchpad reuses the accepted upstream tarball for that product version;
upstream source changes require a new product version and release tag.
The tagged tree supplies upstream source, Debian packaging and rehearsal tools;
the workflow revision supplies signing and upload tooling.

To rehearse locally, with Docker installed:

```bash
SERIES=noble bash packaging/ppa/build-source.sh
bash packaging/ppa/rehearse.sh dist/ppa/keysharp-input_*~noble1.dsc noble
```

Uploads are signed with the organization secrets `PPA_GPG_PRIVATE_KEY`, the
armored secret key of a GPG identity registered with the PPA owner's Launchpad
account, and `PPA_GPG_PASSPHRASE` when that key has a passphrase.

## NixOS

Add the input to your host flake:

```nix
inputs.keysharp-input.url = "github:keysharp-org/keysharp-input";
```

Include `keysharp-input` in the `outputs` arguments and add these entries to your
host's `nixosSystem.modules` list:

```nix
keysharp-input.nixosModules.default
{ services.keysharp-input.enable = true; }
```

The module loads uinput, enables polkit, installs the device rule, and starts
`keysharp-input.service` with its socket. It selects the flake's package for the host
architecture; override `services.keysharp-input.package` to use a custom build.
