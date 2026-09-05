# keysharp-input

A Linux service and C library for global keyboard and mouse hooks, input synthesis,
blocking and physical input-state queries. The same API works on X11 and Wayland.
Applications use `libkeysharp-input.so.0`; the root service owns evdev and uinput access.

## Install

Download your architecture's release from [GitHub Releases](https://github.com/keysharp-org/keysharp-input/releases).
On Debian or Ubuntu:

```sh
sudo apt install ./keysharp-input_<version>_<arch>.deb
```

Other systemd distributions can extract the release archive and run `sudo ./install.sh`.
It checks and installs missing runtime dependencies before installing the service.
For source builds, upgrades, uninstalling and troubleshooting, see [installation](docs/install.md).
Keysharp users can install both brokers with [Keysharp's Linux setup](https://github.com/keysharp-org/Keysharp#linux).

## Use it

```sh
cc examples/type-keys.c $(pkg-config --cflags --libs keysharp-input) -o type-keys
```

Or link `KeysharpInput::client` after `find_package(KeysharpInput 0.2 CONFIG REQUIRED)`.
Complete examples demonstrate [typing keys](examples/type-keys.c) and
[watching and suppressing a key](examples/suppress-key.c). These examples interact
with your desktop when run.
The [passive observer](examples/observe.c) demonstrates monitoring without suppressing input.

Initialize each public options/result/error structure with its `ksi_*_init` function.
Check each returned status, and use a connection from one thread at a time.
Connect without requested scopes to inspect `available_operations` without a dialog.
That mask describes implemented operations; missing hardware can still make a call unavailable.
See the [integration guide](docs/integrating.md) for the full API and callback rules.

## Capabilities and permissions

| Capability | Permission |
| --- | --- |
| Passive observer streams, synchronous hooks, arbitrary key/button state | Input Monitoring |
| Synthesis, blocking, suppressing or replacing events | Input Control |
| Modifier/lock state, cursor position, idle time | None |

Passive observers receive events without the grab/replay overhead of suppressible hooks.
Device metadata and high-resolution wheel events are available to integrations.
Touchpad gestures are interpreted by the compositor and are not equivalent to mouse hooks.
Unicode entry using Ctrl+Shift+U depends on the target application. The service supports
seat0 with logind; see the integration guide for device and session limitations.

A new executable identity requests permanent scopes through polkit. Grants persist
until revoked; updated executable content needs a new grant. Input Control is shared
with a **system-installed** `keysharp-desktop`, so granting or revoking it affects both
services. See [permissions](docs/permissions.md) and the [security model](docs/security-model.md).

Holding **Backspace+Escape+Enter** releases grabs, hooks and input blocking.

## Diagnose

```sh
keysharp-input info
keysharp-input probe
systemctl status keysharp-input.socket keysharp-input.service
```

`info` reads local version/ABI metadata. Run `probe` as your graphical user to check
service access. [Repair instructions](docs/install.md#check-and-repair) explain failures.
Manage grants with `keysharp-input permissions list` and `keysharp-input permissions revoke`.

## Project and distribution

Applications use the public client library; the socket protocol is private.
Product releases are independent of Keysharp. The Debian capability
`keysharp-input-client-abi-0` identifies the client ABI; its provided version records
the ABI major and minor. Applications should require or recommend the needed minor
according to whether input features are optional. An application's
uninstaller must leave this shared service installed.

- [Build and install](docs/install.md#build-from-source)
- [Client integration](docs/integrating.md)
- [Packaging and Nix](docs/packaging.md)
- [Service protocol](docs/protocol.md)

MIT licensed.
