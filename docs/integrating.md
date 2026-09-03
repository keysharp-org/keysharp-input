# Client integration

Include `keysharp_input/client.h` and link `libkeysharp-input`. The supported
discovery mechanisms are:

```bash
pkg-config --cflags --libs keysharp-input
```

```cmake
find_package(KeysharpInput 0.2 CONFIG REQUIRED)
target_link_libraries(my-client PRIVATE KeysharpInput::client)
```

The public ABI is 0.1 and the library SONAME is `libkeysharp-input.so.0`.
`ksi_client_abi_major()` and `ksi_client_abi_minor()` provide runtime
introspection. Socket protocol 2.0 is an implementation detail of this ABI.

## Connections

Initialize every size-tagged structure with its matching `_init` function.
`ksi_connect_options_init` defaults to an RPC connection, check-only
authorization, a 130-second request timeout, and
`/run/keysharp-input/keysharp-input.sock`. The timeout accommodates an
interactive authorization request; clients that only make noninteractive or
latency-sensitive calls can set a shorter value. The environment
variable `KEYSHARP_INPUT_SOCKET` is consulted before that default.

HELLO can request no scopes. This is useful for learning the service's
available operations without opening a permission dialog. Call `ksi_authorize`
later with `KSI_AUTH_REQUEST` when the user invokes a feature that needs a
durable scope.

Use separate connections for unrelated concurrent work. One connection is
used by one thread at a time. The callback API is deliberately reentrant:
a registered nested-hook handler may call `ksi_synthesize` on the same callback
connection. The library pumps child hook requests until the nested call
completes, then sends the child's decision and resumes the parent request.

The hook read/reply path uses fixed buffers and performs no per-event heap
allocation. `ksi_hook_next` returns a tagged `ksi_hook_message`:

- `KSI_HOOK_MESSAGE_EVENT` must receive one `ksi_hook_reply_event`;
- `KSI_HOOK_MESSAGE_QUARANTINED` reports timeout/transport safety state; and
- `KSI_HOOK_MESSAGE_SESSION_REVOKED` reports scopes removed while connected.

If an application can synthesize from inside its hook callback, install a
`ksi_nested_hook_handler` before subscribing. With no handler, nested hook
requests fail open as Pass.

## Authorization and revocation

The public permission bits are:

| Constant | Value |
|---|---:|
| `KSI_SCOPE_INPUT_MONITORING` | `0x01` |
| `KSI_SCOPE_INPUT_CONTROL` | `0x02` |

The service's available-operation mask is independent of authorization. It is
static for a given build: a backend advertises an operation it implements, can
still return `UNAVAILABLE` when the device that operation needs is absent, and a
client can lack the permission required to invoke an available operation. An
absolute `MouseMove` is the case to expect. The service creates a second uinput
device for it, that creation is deliberately non-fatal, and `ksi_synthesize`
returns `UNAVAILABLE` for an absolute move when the device is missing.

For settings UI, use an authorization-lease connection. `ksi_lease_next`
blocks until a revocation or timeout, and `ksi_lease_granted_scopes` reads the
updated grant cache. All request loops consume `SESSION_REVOKED` events and
clear their cached scopes.

Permission administration is typed. `ksi_permissions_list` calls a visitor for
each record; returning false drains the response and returns `CANCELLED`.
`ksi_permissions_revoke` accepts one initialized `ksi_permission_revoke`.
Target kinds are HASH=1, PID=2, and ALL=3. Hashes are exactly 64 lowercase hex
characters. A zero scope mask is invalid.

`KSI_SCOPE_INPUT_CONTROL` is one grant shared with `keysharp-desktop`, which
manages the same bit for its pointer calls. A listed record carrying that scope
may have come from a prompt that named the other service, and revoking it here
also stops that application's `keysharp-desktop` pointer calls. A settings UI
should say so before it revokes. `KSI_SCOPE_INPUT_MONITORING` is not shared.

## Error handling

Every fallible function returns `ksi_status`: `OK`, `DENIED`, `UNSUPPORTED`,
`INVALID_REQUEST`, `UNAVAILABLE`, `BUSY`, `NOT_FOUND`,
`RESOURCE_EXHAUSTED`, `TIMEOUT`, `CANCELLED`, `REVOKED`, or `INTERNAL`.
Initialize an optional `ksi_error` for a stable detail code, system error, and
short diagnostic. Do not parse the message for program logic.

Treat a missing service, authorization denial, revocation, and a closed callback
stream as normal runtime conditions. Applications should keep non-privileged
features usable when the broker is unavailable.

## Packaging

Debian clients should depend on `keysharp-input-client-abi-0`, not the private
socket protocol token. Use `Depends` when privileged input is essential or
`Recommends` when it is optional. Do not invoke this component's uninstaller
from another application's uninstaller.
