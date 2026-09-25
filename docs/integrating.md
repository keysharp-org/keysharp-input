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

The public ABI is 0.4 and the library SONAME is `libkeysharp-input.so.0`.
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

## Gamepads

Gamepads report no text and cannot be typed on, so discovering them and reading
their sticks and buttons needs no scope, as with pointer position and idle time.

`ksi_gamepads_list(Connection, Visitor, Context, Generation, Error)` pages the
same way as `ksi_devices_list`, ordered by event node so that addressing "the
second gamepad" keeps meaning the same device, and reports only devices with
`KSI_DEVICE_GAMEPAD`: an absolute stick plus at least one code from the joystick
and gamepad button range, which is how the kernel's joydev driver binds one.
Because the listing is ungated it omits the device node path and the physical
and unique identifiers; `ksi_devices_list` reports those under Input Monitoring.
`button_codes[0..button_count)` lists the device's buttons in the order joydev
numbers them, so a consumer's button index matches the kernel's own joystick
interface, and `axes` carries the ranges as for any other device.

`ksi_get_gamepad_state(Connection, DeviceId, Generation, State, Error)` reads
one device. Pass the generation from the listing to read the device the listing
described: a hotplug in between returns `BUSY`, and an id that is not a
currently tracked gamepad returns `NOT_FOUND`. Pass 0 to accept whatever the
current device set is. `state.buttons` is a bitmap over that device's
`button_codes`, bit i for `button_codes[i]`, and `state.axes` reports each axis
value in the order the listing gave, in device units to scale against the
listed minimum and maximum. Values come from the kernel's current position
rather than a replayed event stream, so a consumer that starts mid-press still
sees the button held.

See [the complete gamepad example](../examples/read-gamepad.c).

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

## Device key state

`ksi_get_key_state` reports the seat. `ksi_get_device_key_state` (client ABI
0.4) selects one source by the positive ID from `ksi_devices_list` or a hook or
observer event; zero selects the seat, and events from synthesis carry zero, so
check the ID before a device query. Unknown or removed IDs return
`KSI_STATUS_NOT_FOUND`, and a service older than ABI 0.4 answers a device query
with `KSI_STATUS_INVALID_REQUEST`. Both queries require Input Monitoring.

Physical state is read from the kernel for every source, so it also covers
sources another remapper has grabbed. The bitmaps hold every `EV_KEY` code a
source reports, including touch and tool codes, and the seat is their union:
releasing a key on one keyboard leaves another keyboard's hold intact.
Broker-owned outputs never count as sources.

Logical state is what the desktop receives: an ungrabbed source's keys, what
a grabbed source holds downstream, and synthesis. A key the source held when its
grab ended counts only if it still holds it downstream, until the source releases
it, since the desktop never saw it pressed on the source itself. A source another interceptor
owns contributes physical state only, but the broker learns of that owner only
by trying to grab the source, so this holds while a hook or BlockInput wants
the source. A device query's bitmaps describe that source alone, without
synthesis, while its modifier mask and lock bytes describe the seat, which is
what hooks use to name keypad keys. Logical state follows admitted output, so a
query after a Send returns sees its result before paced output drains. A batch
that goes through another client's hooks is admitted only once they pass it.

See [the complete device-state example](../examples/read-key-state.c).

## Forwarding and synthesis devices

The keyboard keys of every intercepted keyboard, with their scan codes and
repeats, are written to the generic `Keysharp Virtual Input` device, which also
carries all client synthesis and hook Modify replacements except absolute
pointer moves, and the buttons pressed after one in the same batch, which use
`Keysharp Virtual Pointer` and are released there. Compositors read each
device's queued events as a group, so only events on one device keep the order
they were written in: sharing the keyboard device keeps a remap such as `+c::d`,
which sends Shift up, `d` and Shift down around a Shift the user holds, in
order, and a modifier held on one keyboard applies to keys from another. The
device holds a key while synthesis or any keyboard holds it, so the desktop sees
one press when the first holder presses and one release when the last lets go.
While a keyboard is intercepted, the desktop sees its keys as coming from that
device, so settings matched to one keyboard, such as a per-device layout, do not
apply to them.

Everything else an intercepted source reports, such as a mouse's motion and
buttons, a combined device's pointer, or a keyboard's switches, is replayed
through the source's own uinput clone, which keeps the source's name,
bus/vendor/product IDs, input properties, axis ranges and motion units, and
carries the physical path prefix `keysharp-input/forward/`. A clone has no
keyboard keys or LEDs, and a keyboard's clone has no joystick buttons either, so
udev never takes it for a controller; a keyboard with nothing else to report
gets none. A
game controller is never a keyboard, even when it reports a key such as
`KEY_RECORD`, so keyboard hooks do not take it and it gets no clone.

The installed udev rule keeps USB and PS/2 mouse hwdb DPI lookup working on
clones, and systemd's own rules cover Bluetooth. Settings matched by an
event-node path, physical connection path or device instance, and live
compositor configuration, are not carried over. The lock LEDs the desktop sets
on the generic keyboard device are relayed to every intercepted keyboard, since
a compositor that keeps lock state per keyboard lights only the device that
received the keys. A clone's switches follow
its source whether or not it is grabbed, since logind reads them from clones
too; force feedback is not relayed. No Keysharp device gets a session ACL: the
desktop opens them through logind like physical devices.

Clones are created when a client first asks for privileged input. A source is
grabbed only once udev has initialized its outputs, the generic keyboard device
for a keyboard and its clone if it has one, and once its keys and buttons are
released. A touch or pen contact does not delay the grab, so the desktop may
keep a contact that was in progress until the grab ends. Ending a grab releases
what the source holds downstream that it no longer holds; a key still held stays
down until the source releases it. When a source disappears, what it held
downstream is released at once, and its clone is removed after a 100 ms drain;
a running downstream remapper sees those releases, while a stopped one must
recover its own state.

Holds on the generic devices belong to their sender: a Send hold to its
connection, and a Modify hold also to its hook and to the physical source key
it replaced. A Modify hold also ends when that source's grab ends or the source
disappears. Unsubscribing, a hook quarantine or a disconnect ends only the
matching holds, after which Modify output from that hook is refused. Batches a
connection sent before it closed still play whole, and what they hold is
released after them. When the last client disconnects, every generic hold ends,
while keys still physically held stay down until they are released.

A sender's release of a key it holds ends only its own hold. A release from a
sender that does not hold the key ends every generic hold of it and releases it
for the sources still holding it, as a Win32 key-up does; a later synthetic
press from anyone puts it back for them, and the physical release ends it. A physical key-up from an intercepted source that reaches the
desktop ends every hold of that key the same way. A key-up a hook suppresses
ends only the Modify holds derived from it.

The system unit starts after `keyd.service`, so keyd grabs its hardware first and
the broker intercepts keyd's virtual devices. The generic devices carry keyd's
vendor ID, as does a clone of keyd's virtual pointer, so keyd leaves them alone.
While another process grabs output carrying the broker's traffic, or a source's
own clone, new grabs are deferred so one stream is not intercepted twice. A source
another program has grabbed is retried every 3 seconds.

## Adapting a general hook library

This is a Linux backend building block, not a complete SharpHook ABI replacement.

| Consumer feature | Integration |
|---|---|
| Key press/release, auto-repeat | Hook or passive keyboard events; preserve repeat and synchronized flags |
| Suppression/replacement | Callback stream with a timely Pass/Block/Modify reply |
| Observe without suppression | Observer stream; no decisions, grabs, or uinput creation |
| Mouse move and wheel | Preserve relative/absolute distinction and signed 1/120-detent wheel units |
| Device discovery and hotplug | Device enumeration, generation, add/remove/change notifications and axis ranges |
| Gamepads and joysticks | Ungated gamepad listing and polled stick/button state, in joydev button order |
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
