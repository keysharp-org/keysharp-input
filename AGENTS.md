# keysharp-input — Claude Code Guide

## Project overview

keysharp-input is a standalone Linux input broker: a root service that takes exclusive
evdev grabs and replays through uinput, plus a C client library that applications link
against. It gives an unprivileged application global keyboard and mouse hooks, input
synthesis, `BlockInput`, and arbitrary key/button state, on X11 and Wayland alike,
without handing it raw device access.

Three things ship together:

- `keysharp-input` — the CLI and the service binary (`daemon`, `probe`, `info`,
  `permissions`).
- `libkeysharp-input.so.0` — the public client library, header `keysharp_input/client.h`.
- systemd units, a polkit action, and a uaccess udev rule.

The public client ABI is 0.1. The socket wire protocol is private and is an
implementation detail of that ABI; `docs/protocol.md` documents it for service
maintainers, not for clients.

## Relationship to Keysharp

This is an independent project. [Keysharp](https://github.com/keysharp-org/Keysharp)
is currently its main consumer, but it is a consumer like any other, and nothing here
may assume Keysharp is the caller.

- **The contract is the client ABI**, expressed as `libkeysharp-input.so.0`, the
  pkg-config/CMake package, and the Debian capability `keysharp-input-client-abi-0`.
  Product versions select release artifacts; the client ABI decides compatibility.
- **Releases are independent.** This project versions and releases on its own cadence.
  Keysharp resolves it at install time from this repository's own releases, so a
  release here does not need a Keysharp release to reach users.
- **The dependency runs one way.** Nothing in this repository reads Keysharp's
  configuration, links its assemblies, special-cases its process, or is built from its
  tree. A feature that only makes sense for Keysharp belongs in Keysharp.
- **Keysharp degrades without it.** Keysharp runs when this service is absent; its
  privileged input features are unavailable until it is installed. Keep that true:
  every client-side failure mode is a normal runtime condition, not a fatal error.
- `keysharp-permissions` is a pinned submodule, shared with `keysharp-desktop`, so a
  grant recorded by either is visible to both. Moving the pin here means moving it in
  `keysharp-desktop` too, where CI asserts the reviewed revision, and updating the
  `keysharp-permissions` flake input in both.

## Repository structure

```
src/
├── main.c                  # CLI entry, --install-input-access setup
├── daemon.c, daemon/*.inc  # the service: admission, hook lanes, grab leases
├── client.c                # libkeysharp-input.so — the whole public ABI
├── platform/               # evdev device discovery, uinput synthesis, VK⇄evdev table
├── internal/               # private headers, including the wire protocol contract
└── permissions_cli.c       # `keysharp-input permissions` subcommands
include/keysharp_input/     # client.h and constants.h — the public surface
packaging/                  # install-release.sh (archive installer), debian/
tests/                      # ctest sources; packaging_*.{cmake,sh} are policy checks
docs/                       # integrating, security-model, packaging, protocol
```

`src/platform/vk_evdev.c` is a second copy of the VK⇄evdev table that Keysharp also
carries in managed code. Both sides are covered by tests; a new mapping goes in both.

## Build and test

Needs CMake 3.16+, a C11 compiler, libudev and libevdev. Clone recursively for the
`keysharp-permissions` submodule.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

The install step finishes the job: it refreshes the linker cache, creates the permission
store, and runs `keysharp-input daemon --install-input-access`. Configure with
`-DKEYSHARP_INPUT_SETUP_ON_INSTALL=OFF` to install files only, which is what packaging
does. `sudo ./install.sh` wraps the same three commands and adds the distribution
dependencies.

Use `-DKEYSHARP_PERMISSIONS_SOURCE_DIR=/path/to/keysharp-permissions` to develop against
a sibling checkout instead of the submodule.

## Permissions

Two durable scopes, `KSI_SCOPE_INPUT_MONITORING` and `KSI_SCOPE_INPUT_CONTROL`. Polkit
authenticates the first interactive request; the grant persists until revoked. Modifier
state, lock-toggle state, cursor position and idle time are ungated.

`ksi_connect` names the scopes an application wants; `ksi_authorize` with
`KSI_AUTH_REQUEST` is what opens the dialog. Connecting with no scopes reads
`available_operations` without prompting.

Holding **Backspace+Escape+Enter** releases every grab, hook and input block, so a
client that stops answering cannot lock the user out. Keep that path working.

## Conventions

- C11, four-space indent, `ksi_` prefix on everything public.
- Every public struct is size-tagged and has a matching `_init`; every fallible function
  returns `ksi_status` and takes an optional `ksi_error`.
- The hook read/reply path uses fixed buffers and allocates nothing per event.
- Comments explain why, in one to three lines. Do not restate the code, describe what it
  replaced, or capitalise words for emphasis.
- Shell lifecycle scripts are POSIX `sh`, and CI shellchecks
  `install.sh uninstall.sh packaging/install-release.sh packaging/debian/*`.
- Public API changes need `include/keysharp_input/client.h`, `docs/integrating.md`, and
  the README's worked examples updated together. The README's C blocks are meant to
  compile as written.

## Traps worth knowing

- **A build sandbox is not a system.** `nix flake check` runs ctest inside nix's sandbox,
  where coreutils is one multi-call binary chosen by `argv[0]`, `/bin` holds only `sh`,
  `/etc` has no `os-release`, `HOME` points nowhere, and no uid reads as root. Anything
  in a test that copies a coreutils tool under a new name, sources a script that hardens
  `PATH` to system directories, or asserts a path is root-owned fails there and nowhere
  else.
- **nixpkgs' cmake hook makes every `CMAKE_INSTALL_*DIR` absolute**, which bakes the
  prefix into exported CMake targets and would produce `${prefix}//nix/store/...` in the
  `.pc`. `nix/package.nix` sets them back to relative values, and the `.pc.in` uses
  `@CMAKE_INSTALL_FULL_LIBDIR@` rather than composing `${prefix}` itself.
- **The installed binary has no RPATH** and links the client library, so anything that
  runs it during install must come after `ldconfig`.
- **The permission store refuses any parent a third party can write to.** That rules out
  `/tmp` for test fixtures, and it means a checkout under a world-writable mount fails
  the permission tests.

## Useful entry points

| Task | Start here |
|------|-----------|
| Public API change | `include/keysharp_input/client.h`, `src/client.c` |
| Hook delivery or decisions | `src/daemon/hook_*.inc` |
| Device discovery or filtering | `src/platform/linux_devices.c`, `linux_device_filter.h` |
| Synthesis | `src/platform/linux_synth.c` |
| Key-code mapping | `src/platform/vk_evdev.c` (mirror it in Keysharp) |
| Permission storage | the `keysharp-permissions` submodule |
| Install layout or channels | `CMakeLists.txt` install rules, `packaging/install-release.sh` |
| Release artifacts | `.github/workflows/release.yml`, `docs/packaging.md` |
