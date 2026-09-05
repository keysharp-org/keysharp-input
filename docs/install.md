# Installation and development

Download a release for your architecture from [GitHub Releases](https://github.com/keysharp-org/keysharp-input/releases).
Debian packages use `amd64` or `arm64`; archives use `x64` or `arm64`.

## Install

On Debian or Ubuntu:

```sh
sudo apt install ./keysharp-input_<version>_<arch>.deb
```

On another systemd distribution:

```sh
tar xf keysharp-input-<version>-linux-<arch>.tar.gz
cd keysharp-input-<version>-linux-<arch>
sudo ./install.sh
```

The archive installer checks runtime dependencies before copying files. If needed,
it installs them through apt, dnf, zypper or pacman. They are libudev, libevdev,
polkit, udev, kmod and systemd. A running systemd system manager is required.
`./check-runtime.sh` checks without changing anything; `sudo ./check-runtime.sh --install`
installs missing dependencies. Other distributions must supply these dependencies
through their own package manager. Archives target glibc 2.35 or newer.

Both routes install the library, CLI and service, configure the virtual input
devices, and enable the service. Applications receive access through grants;
ordinary applications are not added to the input group.

## Check and repair

```sh
keysharp-input info
systemctl status keysharp-input.socket keysharp-input.service
keysharp-input probe
```

`info` reports the local library version and ABI without connecting to the service.
Run `probe` as your graphical user to check the service connection. The service may
be inactive until its socket receives a connection. To repair disabled units:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now keysharp-input.socket
```

For missing libraries, policy files or device rules, rerun the installer from the
same channel, or reinstall the package. Do not layer a tar installation over a
package. Inspect `journalctl -u keysharp-input.service` for device or authorization
failures. Holding **Backspace+Escape+Enter** releases grabs, hooks and input blocking.

## Upgrade and remove

Install a newer release using the same command and channel. Downloaded `.deb` files
do not configure an update repository. Check releases for updates, including
security fixes; ABI compatibility alone does not mean a release is current.

Remove a package through its package manager. Remove the default source/archive
installation with:

```sh
sudo /usr/local/share/doc/keysharp-input/uninstall.sh
```

Uninstall keeps the shared grants under `/var/lib/keysharp-permissions/v1`.
Revoke unwanted grants with `keysharp-input permissions revoke` before removal.

## Build from source

```sh
git clone --recurse-submodules https://github.com/keysharp-org/keysharp-input
cd keysharp-input
sudo apt install cmake build-essential pkg-config libudev-dev libevdev-dev polkitd
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

The install step runs the same service/device setup as the package. The source
`install.sh` wraps configure, build and install; install development dependencies
first. `PREFIX` and `BUILD_DIR` select its destination and build directory.
Only the default `/usr/local` installation has the standalone uninstaller.

For file-only staging, configure with `-DKEYSHARP_INPUT_SETUP_ON_INSTALL=OFF` or
install under `DESTDIR`. Use `-DKEYSHARP_PERMISSIONS_SOURCE_DIR=/absolute/path`
to develop against another permissions checkout instead of the pinned submodule.
See [packaging](packaging.md) for distribution and Nix integration.
