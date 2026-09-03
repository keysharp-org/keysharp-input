# keysharp-input

A Linux service for global keyboard and mouse hooks, input synthesis, input
blocking, and physical input-state queries. The same API works on X11 and
Wayland.

Applications link a small C library (`keysharp_input/client.h`) that talks to a
root-owned, systemd-supervised service over a Unix socket. Clients get no
direct access to evdev or uinput devices, and the service asks polkit before an
application may monitor or control input.

## Install

Three routes, in order of preference. Each one leaves the service enabled and
input access configured.

### Debian package

Download the `.deb` for your architecture from the [releases page][releases]:

```bash
sudo apt install ./keysharp-input_<version>_<arch>.deb
```

It installs the service, CLI, client library, headers, and build metadata, and
its post-install step configures input access for you. The package provides the
virtual package `keysharp-input-client-abi-0`, which is the name applications
depend on.

### Portable archive

For distributions without a package. The archive carries a prebuilt payload and
its own installer, so nothing is compiled:

```bash
tar xf keysharp-input-<version>-linux-<arch>.tar.gz
cd keysharp-input-<version>-linux-<arch>
sudo ./install.sh
```

An application installer that should leave an existing, compatible system
installation alone can pass `--skip-if-compatible`.

### From source

You need CMake 3.16+, a C11 compiler, libudev, and libevdev; polkit is needed at
run time for authorization prompts. The `keysharp-permissions` dependency is a
submodule, so clone recursively:

```bash
git clone --recurse-submodules https://github.com/keysharp-org/keysharp-input
cd keysharp-input
sudo apt install cmake build-essential pkg-config \
  libudev-dev libevdev-dev polkitd
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
sudo cmake --install build
```

The install step finishes the job: it refreshes the linker cache, creates the
permission store, and runs `keysharp-input daemon --install-input-access`, which
loads the uinput module, installs the udev rule that lets your session read the
service's virtual devices, reloads systemd, and starts the service. Nothing has
to be run afterwards.

`sudo ./install.sh` does the same thing and additionally installs the distribution
packages listed above; `PREFIX` and `BUILD_DIR` move the destination and the
build tree. To build and test without installing anything, stop after `ctest`:

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Configure with `-DKEYSHARP_INPUT_SETUP_ON_INSTALL=OFF` to install the files
without touching udev or systemd, which is what packaging does. To develop
against a sibling `keysharp-permissions` checkout instead of the submodule, use
`-DKEYSHARP_PERMISSIONS_SOURCE_DIR=/path/to/keysharp-permissions`.

### Check the install

```bash
keysharp-input probe
systemctl status keysharp-input.socket keysharp-input.service
```

### Uninstall

Remove a packaged install with your package manager. A source or portable
install under `/usr/local` carries its own uninstaller:

```bash
sudo /usr/local/share/doc/keysharp-input/uninstall.sh
```

Removal keeps the grants in `/var/lib/keysharp-permissions/v1`, because other
services grant against the same store.

## Permissions

The service manages two durable scopes:

| Scope | Required for |
|---|---|
| Input Monitoring | hooks and arbitrary key or button state |
| Input Control | synthesis, blocking, and suppressing or replacing hook events |

Modifier, lock-toggle, cursor-position, and idle-time queries need no durable
permission.

Polkit authenticates an interactive request that no existing grant already
satisfies, and the result remains until it is revoked. Grants live in the
shared permission store outside this project's install prefix, so they survive
an upgrade or a reinstall.

### Input Control is one grant shared with keysharp-desktop

A grant marker is keyed by uid, executable identity, and one scope bit. It
carries no service name, and every authority reads the same directory, so Input
Control is a single grant rather than one grant per service.

`keysharp-desktop` manages the same bit for its pointer calls. An application
granted Input Control there already holds it here: `ksi_synthesize` and
`ksi_set_block_input` go through with no second prompt, because the request
path rechecks the store under the shared prompt lock and never reaches
`pkcheck`. The reverse holds too.

Revocation crosses the same way. `keysharp-input permissions revoke` defaults
to both input scopes, so a revoke with no scope argument also stops that
application's `keysharp-desktop` pointer calls, and `revoke --all` does it for
every application of the calling uid. Pass `input-monitoring` to revoke only
the scope nothing else shares.

Input Monitoring is this service's alone. `keysharp-desktop` accepts it for
neither a grant nor a revocation, so a hook grant survives anything done there.

## Use it from an application

Build against the client library:

```bash
cc my-app.c $(pkg-config --cflags --libs keysharp-input)
```

or, from CMake:

```cmake
find_package(KeysharpInput 0.2 CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE KeysharpInput::client)
```

Every call takes an initialized `ksi_error` and returns a `ksi_status`, so the
two examples below are complete programs. Key numbers are Windows virtual-key
codes on every platform: `'A'`-`'Z'` and `'0'`-`'9'` are themselves, and Escape
is `0x1B`.

### Type into whatever has focus

Synthesis needs Input Control. `ksi_connect` asks for the scope, and
`ksi_authorize` with `KSI_AUTH_REQUEST` is what opens the polkit dialog, unless
this application already holds Input Control from an earlier run or from
`keysharp-desktop`; after the user approves it, the grant is remembered and
later runs go straight through.

```c
#include <keysharp_input/client.h>
#include <stdio.h>

static int press(ksi_connection *connection, uint16_t vk, ksi_error *error)
{
    ksi_input down;
    ksi_input up;

    ksi_input_init(&down);
    down.type = KSI_INPUT_KEYBOARD;
    down.data.keyboard.vk = vk;
    up = down;
    up.data.keyboard.flags = KSI_KEY_UP;

    if (ksi_synthesize(connection, &down, 1u, 0u, error) != KSI_STATUS_OK)
        return 0;
    return ksi_synthesize(connection, &up, 1u, 0u, error) == KSI_STATUS_OK;
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_permission_scopes granted = 0u;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.requested_scopes = KSI_SCOPE_INPUT_CONTROL;

    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "connect: %s\n", error.message);
        return 1;
    }
    if (ksi_authorize(connection, KSI_AUTH_REQUEST, KSI_SCOPE_INPUT_CONTROL,
                      &granted, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "authorize: %s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    if (!press(connection, 'H', &error) || !press(connection, 'I', &error))
        fprintf(stderr, "synthesize: %s\n", error.message);
    ksi_disconnect(connection);
    return 0;
}
```

### Watch keys, and swallow one

A hook is a `KSI_ROLE_CALLBACK_STREAM` connection. Every event the service
delivers must be answered with `ksi_hook_reply_event`, because the keystroke is
held until the decision arrives: `KSI_HOOK_PASS` lets it through,
`KSI_HOOK_BLOCK` drops it, `KSI_HOOK_MODIFY` replaces it. Observing needs Input
Monitoring; blocking or replacing also needs Input Control.

```c
#include <keysharp_input/client.h>
#include <stdio.h>

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_permission_scopes granted = 0u;
    ksi_operations active = 0u;
    const ksi_permission_scopes wanted =
        KSI_SCOPE_INPUT_MONITORING | KSI_SCOPE_INPUT_CONTROL;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.role = KSI_ROLE_CALLBACK_STREAM;
    options.requested_scopes = wanted;

    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "connect: %s\n", error.message);
        return 1;
    }
    if (ksi_authorize(connection, KSI_AUTH_REQUEST, wanted, &granted, &error)
            != KSI_STATUS_OK
        || ksi_hook_subscribe(connection, KSI_HOOK_KEYBOARD, &active, &error)
            != KSI_STATUS_OK) {
        fprintf(stderr, "subscribe: %s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }

    for (;;) {
        ksi_hook_message message;
        ksi_hook_reply reply;

        ksi_hook_message_init(&message);
        if (ksi_hook_next(connection, UINT32_MAX, &message, &error)
                != KSI_STATUS_OK)
            break;
        if (message.kind != KSI_HOOK_MESSAGE_EVENT)
            continue;

        ksi_hook_reply_init(&reply);
        reply.decision = KSI_HOOK_PASS;
        if (!(message.data.event.event.keyboard.flags & KSI_KEYBOARD_HOOK_UP)) {
            printf("vk %u\n", message.data.event.event.keyboard.vk_code);
            fflush(stdout);
            if (message.data.event.event.keyboard.vk_code == 0x1Bu)
                reply.decision = KSI_HOOK_BLOCK;
        }
        if (ksi_hook_reply_event(connection, &message.data.event, &reply,
                                 &error) != KSI_STATUS_OK)
            break;
    }
    ksi_disconnect(connection);
    return 0;
}
```

Run it, press a few keys, and press Escape: the `vk` line appears but the
keystroke never reaches the focused window. Holding
**Backspace+Escape+Enter** releases every hook and grab if a client stops
answering, so a hook that blocks too much cannot lock you out.

### Beyond the examples

`ksi_get_key_state`, `ksi_get_pointer_position`, `ksi_get_modifier_state` and
`ksi_get_idle_time` answer state queries; cursor position, modifier state,
lock-toggle state and idle time need no durable permission. `ksi_set_block_input`
suppresses physical input wholesale. `ksi_permissions_list` and
`ksi_permissions_revoke` back a settings UI.

Connect without requesting any scope to read `info.available_operations`
without opening a permission dialog. It is the static set of operations this
build of the service implements, not a readiness check: a device the operation
needs can still be absent, and the call then returns `UNAVAILABLE`. Use a
separate connection per unrelated concurrent task; one connection is used by one
thread at a time. [docs/integrating.md](docs/integrating.md) covers the whole API,
including nested dispatch for synthesizing from inside a hook callback.

The default socket is `/run/keysharp-input/keysharp-input.sock`; clients can
override it with `KEYSHARP_INPUT_SOCKET` or the C connect options.

Applications and language bindings should not hand-pack socket frames. The wire
protocol is private, and [docs/protocol.md](docs/protocol.md) documents it for
service maintainers and diagnostics only.

When packaging an application, depend on `keysharp-input-client-abi-0` if the
service is required, or recommend it if privileged input is optional. An
application uninstaller must not remove that package, because other clients may
still be using it.

## Command line

```text
keysharp-input version
keysharp-input info
keysharp-input probe [--socket PATH]
keysharp-input daemon [--socket PATH | --system-service] [--verbose]
keysharp-input permissions list [--socket PATH]
keysharp-input permissions revoke (--hash HASH | --pid PID | --all) \
  [input-monitoring|input-control|all] [--socket PATH]
```

With no arguments, the command prints help. `info` emits stable `key=value`
lines, including `client_abi_major` and `client_abi_minor`.

Permission hashes are lowercase SHA-256 values. `revoke` defaults to both input
scopes and performs one atomic daemon request. That default includes Input
Control, which is shared with `keysharp-desktop`; see Permissions above.

## Running the service

**Holding Backspace+Escape+Enter releases grabs, hooks, and input blocking**,
even when a client stops responding.

To watch what the service is doing:

```bash
journalctl -u keysharp-input.service -f
```

## More documentation

- [docs/integrating.md](docs/integrating.md) - the client API in depth
- [docs/security-model.md](docs/security-model.md) - trust boundaries and threat model
- [docs/packaging.md](docs/packaging.md) - install layout and release artifacts

## License

MIT.

[releases]: https://github.com/keysharp-org/keysharp-input/releases
