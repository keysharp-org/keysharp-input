# keysharp-input

`keysharp-input` is a standalone privileged Linux input broker. Its supervised
daemon, `keysharp-inputd`, owns physical input devices and virtual input
synthesis, while unprivileged clients reach it over a Unix socket. Any
application can use it; it has no dependency on the project it was extracted
from.

It provides global keyboard and mouse hooks that can pass, block, or replace
events, keyboard and mouse synthesis, `BlockInput`, and key/button state
queries — on both X11 and Wayland, where a compositor normally makes these
impossible for an ordinary application.

Client users do not need to be in the `input` group. Access is authorized
per application through polkit and recorded as a permanent, revocable grant.

## Requirements

| Package | Purpose |
|---|---|
| `cmake` (3.16+), `ninja` or `make` | build system |
| `gcc` or `clang`, libc headers | C11 compiler |
| `pkg-config` | library discovery |
| `libudev` | device hotplug |
| `libevdev` | evdev event decoding |
| `polkit` | interactive authorization at first grant |

```bash
# Debian/Ubuntu
sudo apt install cmake ninja-build build-essential pkg-config libudev-dev libevdev-dev polkitd

# Fedora
sudo dnf install cmake gcc make pkgconf-pkg-config systemd-devel libevdev-devel polkit

# Arch
sudo pacman -S cmake base-devel pkgconf systemd libevdev polkit

# openSUSE
sudo zypper install cmake gcc make pkg-config systemd-devel libevdev-devel polkit
```

## Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

Useful options: `-DBUILD_TESTING=OFF` omits the test targets,
`-DKEYSHARP_INPUTD_BUILD_HOOKTEST=OFF` omits the diagnostic tool, and
`-DCMAKE_INSTALL_PREFIX=` selects the installation root.

## Test

```bash
ctest --test-dir build --output-on-failure
```

The suite is deterministic and needs no privileges or devices. Privileged
end-to-end evdev/uinput checks are opt-in and separate; see
[docs/physical-live-tests.md](docs/physical-live-tests.md).

## Install

```bash
sudo cmake --install build
```

This installs the binary, its systemd units, and the polkit policy, then runs
`keysharp-inputd --install-input-access` to configure device access and enable
the service. The daemon starts at boot and stays resident. While idle it holds
no input grabs and creates no virtual devices: privileged uinput devices are
created only when an identified client requests hooks, synthesis, or
`BlockInput`.

Distribution packages install to `/usr`; source and portable installs use
`/usr/local` so they never overwrite package-manager files. Packaging that
installs through `DESTDIR`, and the rules for moving between portable and
packaged installations, are covered in
[docs/packaging.md](docs/packaging.md).

### Verify

```bash
keysharp-inputd --info
systemctl status keysharp-inputd.socket keysharp-inputd.service
```

For interactive diagnosis against an installed daemon, `build/keysharp-inputd-hooktest --help`
can observe hooks, pass/block/modify events, inject keys or Unicode, release
stuck modifiers, and trigger the emergency passthrough.

## NixOS

The flake exports `packages.<system>.default` (also named `keysharp-input`) and
`nixosModules.default`:

```nix
{
  inputs.keysharp-input.url = "github:keysharp-org/keysharp-input";
  outputs = { nixpkgs, keysharp-input, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        keysharp-input.nixosModules.default
        { services.keysharp-input.enable = true; }
      ];
    };
  };
}
```

The module enables polkit, loads `uinput`, installs the narrow udev rule, and
exposes `services.keysharp-input.package` for overrides.

## Service management

```bash
# Status and logs
systemctl status keysharp-inputd.socket keysharp-inputd.service
journalctl -u keysharp-inputd.service -f

# Restart the daemon (keeps the socket; active clients reconnect)
systemctl restart keysharp-inputd.service

# Stop, and prevent restart on new connections
systemctl stop keysharp-inputd.socket keysharp-inputd.service

# Start again (the service starts its required socket)
systemctl start keysharp-inputd.service
```

After reinstalling the binary, run `sudo systemctl daemon-reload` and restart
the service. If capability requests stop opening a polkit dialog after an
upgrade, reinstall, reload systemd, and restart.

## Development run

A manually launched daemon uses a private socket under `$XDG_RUNTIME_DIR` and
accepts only the daemon's own uid:

```bash
build/keysharp-inputd --foreground
build/keysharp-inputd --socket /tmp/keysharp-test.sock
```

## Using it from your own application

Clients speak the protocol directly over the Unix socket. The wire contract is
the installed header `keysharp-inputd/protocol.h`, and
[docs/protocol.md](docs/protocol.md) documents the handshake, message set,
hook dispatch, and status codes. `tools/hooktest.c` is a complete worked client.

A client sends `CLIENT_HELLO` with the operations it needs
(`KSI_CAP_HOOK_KEYBOARD`, `KSI_CAP_HOOK_MOUSE`, `KSI_CAP_SYNTH_KEYBOARD`,
`KSI_CAP_SYNTH_MOUSE`, `KSI_CAP_BLOCK_INPUT`) and receives the subset it was
granted. Hooks map to the durable Input Monitoring scope; synthesis and
`BlockInput` map to Input Control. A suppressing hook therefore needs both. See
[docs/security-model.md](docs/security-model.md).

Distribution packages that ship a client should express the relationship
through the package manager (`Depends` or `Recommends`, according to whether
input features are optional) rather than installing or removing the broker
themselves.

## Permissions

Grants are permanent until revoked, and are inspected and removed without root
through the authenticated daemon connection:

```bash
keysharp-inputd permissions list
keysharp-inputd permissions revoke <hash>
keysharp-inputd permissions revoke --pid <pid>
keysharp-inputd permissions revoke --all
```

Cursor position, modifier state, and lock-toggle state are permission-free and
never consult the grant store.

## Uninstall

```bash
sudo /usr/local/share/doc/keysharp-input/uninstall.sh
```

The broker can have other clients, so an application's own uninstaller must
never run this. Run it only after establishing that no other application uses
the component. It always preserves the shared permission namespace.

## Architecture

```
client process  ──► IPC  ──► keysharp-inputd  ──► platform backend  ──► evdev/udev/uinput
```

**Daemon owns:** device discovery and hotplug, exclusive evdev grabs, virtual
input devices, event suppression/replay/synthesis, injected-event tagging,
multiple hook clients, bounded hook dispatch and timeouts, emergency ungrab.

**Clients own:** application policy, callback lifecycle, and pass/block/replace
decisions for hooked input.

## Documentation

| Document | Contents |
|---|---|
| [docs/protocol.md](docs/protocol.md) | IPC protocol: framing, messages, status codes |
| [docs/security-model.md](docs/security-model.md) | Authentication, authorization, enforcement |
| [docs/permission-store.md](docs/permission-store.md) | Shared on-disk grant contract |
| [docs/app-identity.md](docs/app-identity.md) | Executable-identity algorithm and test vectors |
| [docs/packaging.md](docs/packaging.md) | Packaging, portable installs, removal policy |
| [docs/physical-live-tests.md](docs/physical-live-tests.md) | Opt-in privileged device test matrix |

Report defects and request support through the
[issue tracker](https://github.com/keysharp-org/keysharp-input/issues).

## License

MIT. See [LICENSE](LICENSE) and [PROVENANCE.md](PROVENANCE.md).
