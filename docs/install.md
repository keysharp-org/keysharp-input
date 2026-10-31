# Installation and development

## Install

On Ubuntu 24.04 or 26.04 and distributions based on those releases, use Keysharp's
Launchpad PPA to install the package and receive updates:

```sh
sudo apt install software-properties-common
sudo add-apt-repository ppa:descolada/keysharp
sudo apt update
sudo apt install keysharp-input
```

For a downloaded package on Debian or Ubuntu, choose your architecture's release from
[GitHub Releases](https://github.com/keysharp-org/keysharp-input/releases).
Debian packages use `amd64` or `arm64`; archives use `x64` or `arm64`.

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

These routes install the library, CLI and service, configure the virtual input
devices, and enable the service. Applications receive access through grants;
ordinary applications are not added to the input group.

Source and archive installs register their library directory in
`/etc/ld.so.conf.d/keysharp-input.conf` before refreshing the linker cache and
starting the service. This also makes the client library discoverable to other
applications on distributions that do not search `/usr/local/lib` by default.
An edited file at that path is preserved; remove it and rerun the installer to
restore the generated configuration.

## Authentication prompts

Graphical permission prompts need a polkit authentication agent running in the
requesting user's session; installing polkit alone does not provide a dialog.
Debian and PPA packages recommend `mate-polkit | polkit-1-auth-agent`, allowing
an existing desktop provider to satisfy the recommendation.

For source/archive installs or packages installed with `--no-install-recommends`,
use your desktop's agent or install one through your distribution's package manager.
Configure it to start as your normal user with the graphical session. If your
desktop manages autostart, log out and back in after installation. Source and
archive installers only print a reminder; agent selection and startup belong to
the session. Existing grants can be used without an agent. If a new request needs
authentication and no agent is available, the service returns an error explaining
that an agent must be installed and started before retrying.

## Check and repair

```sh
keysharp-input info
systemctl status keysharp-input.socket keysharp-input.service
keysharp-input probe
```

`info` reports the local library version and ABI without connecting to the service.
Run `probe` as your graphical user to check the service connection. It requests no
grants, so it does not test authentication prompts. If a grant request fails without
a dialog, check the [authentication agent](#authentication-prompts) in that session.
The installer keeps the resident service enabled and active so it can register input devices
before a client connects. To repair disabled units:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now keysharp-input.service
```

For missing libraries, policy files or device rules, rerun the installer from the
same channel, or reinstall the package. The source and archive installers do not
overwrite an edited `/etc/udev/rules.d/70-keysharp-input-uaccess.rules`; remove
it and rerun the installer to restore the shipped rule. Do not layer a tar
installation over a package. Inspect `journalctl -u keysharp-input.service` for device or authorization
failures. Holding **Backspace+Escape+Enter** releases grabs, hooks and input blocking;
a client that requests blocking again afterwards blocks input again.

## Upgrade and remove

Install a newer release using the same command and channel. Downloaded `.deb` files
do not configure an update repository; the PPA does. Check releases for updates, including
security fixes; ABI compatibility alone does not mean a release is current.

To switch a source/archive installation to Debian or PPA packages, run the portable
uninstaller first.

Remove a package through its package manager. Remove the default source/archive
installation with:

```sh
sudo /usr/local/share/doc/keysharp-input/uninstall.sh
```

Uninstall keeps the shared grants under `/var/lib/keysharp-permissions/v1`.
It removes the linker configuration only when its contents still match the
generated `/usr/local/lib` entry, and preserves other linker configuration files.
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
