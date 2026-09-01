# keysharp-input

`keysharp-input` is a standalone Linux service for global keyboard and mouse
hooks, input synthesis, input blocking, and physical input state queries. It
uses the same API on X11 and Wayland.

Applications use the stable C library in `keysharp_input/client.h`. The library
connects to a root-owned, systemd-supervised service and never gives clients
direct access to evdev or uinput devices.

## Permissions

The service manages two durable scopes:

| Scope | Required for |
|---|---|
| Input Monitoring | hooks and arbitrary key or button state |
| Input Control | synthesis, blocking, and suppressing or replacing hook events |

Modifier, lock-toggle, cursor-position, and idle-time queries need no durable
permission. Polkit handles an application's first interactive request. A grant
remains until the user revokes it.

## Build

The build needs CMake 3.16+, a C11 compiler, libudev, and libevdev. Initialize
the permission-library submodule before configuring.

```bash
git submodule update --init --recursive
sudo apt install cmake ninja-build build-essential pkg-config \
  libudev-dev libevdev-dev polkitd
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

For local development against a sibling checkout, pass
`-DKEYSHARP_PERMISSIONS_SOURCE_DIR=/path/to/keysharp-permissions`.

## Install

Prefer a distribution package.

`./install.sh` in this checkout configures, builds, and installs under
`/usr/local`, then finishes input-access setup. `PREFIX` and `BUILD_DIR`
override the destination and the build directory.

```bash
sudo ./install.sh
```

A release archive carries its own `install.sh`, which installs the prebuilt
payload rather than building it. An application installer may use it to leave a
compatible system installation in place:

```bash
sudo ./install.sh --skip-if-compatible
```

The Debian package contains the service, CLI, shared client library, headers,
and build metadata. It provides `keysharp-input-client-abi-0`.

## CLI

```text
keysharp-input version
keysharp-input info
keysharp-input probe [--socket PATH]
keysharp-input daemon [--socket PATH | --system-service] [--verbose]
keysharp-input permissions list [--socket PATH]
keysharp-input permissions revoke (--hash HASH | --pid PID | --all) \
  [input-monitoring|input-control|all] [--socket PATH]
```

With no arguments, the command prints help. `info` uses stable `key=value`
keys, including `client_abi_major` and `client_abi_minor`. Permission hashes are
lowercase SHA-256 values; revoke defaults to both input scopes and performs one
atomic daemon request.

The installed socket is `/run/keysharp-input/keysharp-input.sock`. Clients can
override it with `KEYSHARP_INPUT_SOCKET` or the C connect options.

## Integrate

Use `pkg-config --cflags --libs keysharp-input` or the CMake target
`KeysharpInput::client`. The shared object has SONAME
`libkeysharp-input.so.0`; the first public ABI is 0.1. A minimal connection is:

```c
#include <keysharp_input/client.h>

ksi_connect_options options;
ksi_service_info info;
ksi_error error;
ksi_connection *connection = NULL;

ksi_connect_options_init(&options);
ksi_service_info_init(&info);
ksi_error_init(&error);
if (ksi_connect(&options, &connection, &info, &error) == KSI_STATUS_OK) {
    /* Use typed query, authorization, synthesis, or hook functions. */
    ksi_disconnect(connection);
}
```

Do not hand-pack socket frames in applications or language bindings. The private
protocol is documented for service maintainers and diagnostics in
[docs/protocol.md](docs/protocol.md).
Callback streams support synchronous nested hook dispatch: register a nested
handler before issuing synthesis from a hook connection.

An application package should depend on the client ABI virtual package when
the service is required, or recommend it when privileged input is optional.
Application uninstallers must not remove this package because other clients may
still use it.

## Operation

```bash
keysharp-input probe
systemctl status keysharp-input.socket keysharp-input.service
journalctl -u keysharp-input.service -f
```

Holding Backspace+Escape+Enter releases grabs, hooks, and input blocking even
when a client is unresponsive.

Remove a distribution package with its package manager. A portable install has
its own uninstaller:

```bash
sudo /usr/local/share/doc/keysharp-input/uninstall.sh
```

Removal keeps the shared permission store.

Further details are in [docs/integrating.md](docs/integrating.md),
[docs/security-model.md](docs/security-model.md), and
[docs/packaging.md](docs/packaging.md).

## License

MIT. The sole contributor is Descolada.
