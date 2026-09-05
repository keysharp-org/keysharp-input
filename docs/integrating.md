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

The public ABI is 0.2 and the library SONAME is `libkeysharp-input.so.0`.
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
Do not disconnect or free the callback context inside a nested callback. Defer
destruction until the outer client API call returns, and keep replacement input
arrays alive until that return.

The hook read/reply path uses fixed buffers and performs no per-event heap
allocation. `ksi_hook_next` returns a tagged `ksi_hook_message`:

- `KSI_HOOK_MESSAGE_EVENT` must receive one `ksi_hook_reply_event`;
- `KSI_HOOK_MESSAGE_QUARANTINED` reports timeout/transport safety state; and
- `KSI_HOOK_MESSAGE_SESSION_REVOKED` reports scopes removed while connected.

While waiting, `ksi_hook_next` sends the callback-stream heartbeats needed to
keep active hook and input-blocking leases alive, including for an infinite wait.

If an application can synthesize from inside its hook callback, install a
`ksi_nested_hook_handler` before subscribing. With no handler, nested hook
requests fail open as Pass.

## Passive observation and device discovery

Use `KSI_ROLE_OBSERVER_STREAM` for monitoring that cannot suppress input.
Request Input Monitoring and call `ksi_hook_subscribe` for keyboard or mouse;
the returned operation bits are `KSI_OPERATION_OBSERVE_KEYBOARD` and
`KSI_OPERATION_OBSERVE_MOUSE`. An observer neither grabs physical devices nor
creates uinput devices when requesting only monitoring. A callback stream is
still required for suppression or replacement.

Read initialized `ksi_observer_message` values with `ksi_observer_next`:

| Kind | Data |
|---|---|
| `KSI_OBSERVER_INPUT` | `data.input`, in the same raw coordinate/key-code units as hooks |
| `KSI_OBSERVER_RAW_INPUT` | `data.raw_input`, evdev touchpad/pen/touchscreen reports |
| `KSI_OBSERVER_DEVICE_ADDED`, `REMOVED`, `CHANGED` | `data.device` and `device_generation` |
| `KSI_OBSERVER_OVERFLOW` | `dropped_events`; refresh key state and enumerate devices again |
| `KSI_OBSERVER_SESSION_REVOKED` | `data.revoked_scopes` |

Observer events need no reply. Their bounded queues and nonblocking transport
cannot hold physical input waiting for a reader. A full queue discards events
and reports overflow; a partial socket write closes the stream, requiring a
reconnect. Observation represents upstream device input, including input that
an interceptor subsequently suppresses. It does not report the broker's own
synthesis as physical input. Hotplug events are delivered while at least one
keyboard or mouse observation subscription is active.

`ksi_devices_list(Connection, Visitor, Context, Generation, Error)` enumerates
readable seat0 devices under Input Monitoring. `Generation` is an optional
`uint64_t *` output. Subscribe before enumeration, then ignore queued device
notifications with a generation at or before that snapshot. The visitor receives
an initialized `ksi_device_info` containing a daemon-lifetime device ID, device
name/node, physical/unique identifiers, USB-style vendor/product/version fields,
and capability bits. IDs can change after unplug/restart; use the identifiers
with normal duplicate/missing-identifier handling for saved device preferences.
`axes[0..axis_count)` lists available evdev absolute axis codes with their minimum,
maximum, fuzz, flat, and resolution values. Resolution has the kernel's per-axis
units; these are device coordinates, not desktop pixels.

Enumeration uses bounded pages. A concurrent hotplug returns `BUSY`; discard
any partial snapshot and retry. Returning false from the visitor stops enumeration
and returns `CANCELLED`. Device capability bits describe supported paths, not
whether another process currently owns an exclusive grab. The broker's own
virtual output devices are excluded.

See [the complete observer example](../examples/observe.c).

## Linux input semantics

- Keyboard events provide Windows-style virtual keys plus raw evdev scan codes.
  `KSI_KEYBOARD_HOOK_REPEAT` identifies evdev repeat events;
  `KSI_KEYBOARD_HOOK_SYNCHRONIZED` identifies reconstructed state differences.
  Layout/group changes, compose state, and committed text are session/compositor
  concepts; obtain them from a session integration such as keysharp-desktop and
  interpret keymaps with xkbcommon. The input broker does not invent typed characters.
- Relative mouse coordinates are raw deltas, not accelerated desktop positions.
  Absolute reports use device ranges; button/wheel coordinates can be unspecified.
  Use the desktop integration when actual cursor coordinates are required.
- Hardware touchpad buttons can be observed. A mouse observation subscription
  also receives `KSI_OBSERVER_RAW_INPUT` for devices with
  `KSI_DEVICE_RAW_OBSERVATION`: evdev `EV_ABS`, `EV_KEY`, and `EV_SYN` records,
  including pen pressure, touch contacts, multitouch slots, and frame boundaries.
  `type`, `code`, and `value` retain kernel definitions. The synchronized flag marks
  reconstructed differences; the monotonic-time flag identifies `time_ms` as
  CLOCK_MONOTONIC, otherwise it uses the device timestamp clock. These reports
  never pass through interception/replay. Tap-to-click, gestures, acceleration,
  and compositor-generated scrolling require a session/libinput interpretation;
  raw contact coordinates must not be presented as mouse cursor positions.
  BlockInput can still block eligible devices wholesale.
- High-resolution wheel events retain signed units of 1/120 detent. On capable
  hardware their compatibility low-resolution duplicate is ignored. Synthesis emits
  high-resolution movement and accumulates matching low-resolution detents, so
  two `-60` movements produce one negative detent rather than reversing direction.
- Unicode synthesis uses the Ctrl+Shift+U input-method convention. Applications
  without that convention need an appropriate session/text-input mechanism.
- The system service uses logind's active user on seat0. Additional seats and
  environments without a compatible logind service are not currently supported.
- After `SYN_DROPPED`, the broker processes libevdev synchronization differences,
  including lost key releases, before normal event delivery resumes. Relative
  movement from an incomplete report cannot be reconstructed and is discarded.

## Adapting a general hook library

This is a Linux backend building block, not a complete SharpHook ABI replacement.

| Consumer feature | Integration |
|---|---|
| Key press/release, auto-repeat | Hook or passive keyboard events; preserve repeat and synchronized flags |
| Suppression/replacement | Callback stream with a timely Pass/Block/Modify reply |
| Observe without suppression | Observer stream; no decisions, grabs, or uinput creation |
| Mouse move and wheel | Preserve relative/absolute distinction and signed 1/120-detent wheel units |
| Device discovery and hotplug | Device enumeration, generation, add/remove/change notifications and axis ranges |
| Event timestamps | Hook `time_ms` is the underlying device event timestamp; raw events explicitly flag CLOCK_MONOTONIC |
| Injected events | Callback event flags/extra-info identify synthesis; passive observers exclude this broker's synthesis |
| Typed text/layout | Obtain session keymap/group separately; translate locally, and distinguish key translation from IME-committed text |
| Click counts and dragging | Aggregate button/motion events in the consumer, using its timing/threshold policy |
| Touchpad/pen/touchscreen | Raw observation with device metadata; compositor gesture and cursor semantics need another integration |
| Start/stop, overflow, revocation | Map connect/subscribe/unsubscribe outcomes and typed observer notices to consumer lifecycle events |

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
