# keysharp-inputd IPC protocol

`keysharp-inputd` exposes a Windows-shaped logical input protocol over a Unix
socket. The daemon uses evdev, udev, and uinput internally while clients use
portable hook, state-query, suppression, and synthesis messages.

C constants and structs: `include/keysharp_inputd/protocol.h`

## Framing

Every message has a `ksi_message_header` carrying:

- protocol major/minor version
- message type
- client id
- correlation id (for request/response pairs)
- payload byte size

The current wire version is exactly `1.2`. Both numbers must match. A daemon and
client from mismatched installations fail the connection explicitly rather than
guessing at struct layouts or permission semantics. Changing versions
mid-connection is also an error.

Frames arrive over a stream socket and may be split or coalesced. The daemon
buffers per-client input and disconnects clients that send invalid versions,
invalid sizes, or oversized frames.

Supported message types:

```
CLIENT_HELLO          HEARTBEAT
SUBSCRIBE_HOOK        UNSUBSCRIBE_HOOK
HOOK_EVENT            HOOK_DECISION
HOOK_QUARANTINED
SYNTHESIZE_INPUT      SYNTHESIS_RESULT
EMERGENCY_PASSTHROUGH SET_BLOCK_INPUT
GET_INDICATOR_STATE   INDICATOR_STATE_RESULT
GET_POINTER_POSITION  POINTER_POSITION_RESULT
GET_KEY_STATE         KEY_STATE_RESULT
GET_POINTER_BUTTONS   POINTER_BUTTONS_RESULT
IDLE_TIME              MODIFIER_STATE
LIST_PERMISSIONS       REVOKE_PERMISSIONS
```

`GET_KEY_STATE` / `KEY_STATE_RESULT` report current logical modifiers, lock-key
state, a logical evdev key bitmap, and an appended physical evdev key bitmap. It
requires `KSI_CAP_HOOK_KEYBOARD`.

`GET_POINTER_BUTTONS` / `POINTER_BUTTONS_RESULT` report a validity byte followed
by logical and physical mouse-button masks. Logical buttons combine the evdev
physical snapshot with the daemon's queued synthetic button state. It requires
`KSI_CAP_HOOK_MOUSE`.

`MODIFIER_STATE` is an empty request and a same-type 12-byte response carrying
logical and physical left/right modifier masks plus Caps Lock, Num Lock, and
Scroll Lock toggle bytes. It requires an authenticated `CLIENT_HELLO` but no
privileged input operation.

`IDLE_TIME` is an empty request and a same-type response carrying a validity flag
and milliseconds since the daemon last observed upstream user activity. It
requires an authenticated `CLIENT_HELLO` but no privileged input capability, so
reading `A_TimeIdle` never causes a permission prompt. Until the daemon observes
its first activity event, the validity flag is false. The response uses the same
message type and carries a 16-byte idle payload.

`LIST_PERMISSIONS` and `REVOKE_PERMISSIONS` back the `keysharp-inputd permissions`
subcommand (see below).

The protocol permits a `HEARTBEAT` with correlation id `0` as a one-way grab
lease renewal. The daemon sends no response for that form, so hook-reader
connections can renew without introducing an unexpected receive frame. Other
heartbeat correlation ids retain request/response behavior.

## Authorization

Clients connect through the systemd socket at
`/run/keysharp-inputd/keysharp-inputd.sock`. The daemon authenticates via
`SO_PEERCRED`, `/proc/<pid>/stat` start time, and an app-wide identity derived
from the peer executable. Arguments are display metadata and are not part of
the authorization identity.

`CLIENT_HELLO` carries requested operation bits, optional flags, and one
authenticated connection role:

- `HOOK_STREAM` receives hook events, returns decisions, and carries synchronous
  requests made while one of those callbacks is active.
- `GENERAL_RPC` carries ordinary requests from unrelated client threads.

Callback synthesis stays on the same `HOOK_STREAM` and uses its current parent
event id as the request correlation id. The daemon accepts that ancestry only while
the same authenticated stream is the active responder for that event. A general
connection cannot claim a parent, and stale callback output is emitted only through
the bypassed fail-open path.

The system socket is machine-wide, but input ownership is not: only the uid of
logind's active session on `seat0` may acquire privileged operations, subscribe,
block, synthesize, query arbitrary key/button state, or enter a hook snapshot.
A seat-owner transition fences old work by generation and releases its grabs
before the new uid is published. Evdev discovery likewise admits only `seat0`
devices.

Capabilities and flags are:

```
KSI_CAP_HOOK_KEYBOARD   KSI_CAP_HOOK_MOUSE
KSI_CAP_SYNTH_KEYBOARD  KSI_CAP_SYNTH_MOUSE
KSI_CAP_BLOCK_INPUT

KSI_CLIENT_HELLO_FLAG_CHECK_ONLY
```

Unknown flag bits are rejected. Permanent grants are authoritative; clients
revoke a scope before requesting authorization again. `CHECK_ONLY`
(`0x00000002`) performs the same executable
identity and persistent-store lookup without invoking polkit or changing the
store. A fully granted request returns status `0`; an incomplete request returns
status `403` and its `granted_capabilities` field contains the already-granted
subset.

The daemon replies with granted capabilities. For an unknown identity it runs
`/usr/bin/pkcheck --action-id org.keysharp.input.grant --process PID,START,UID
--allow-user-interaction`. The PID, start time, and UID originate from
`SO_PEERCRED` and `/proc`, and the start time is checked before and after polkit
authorization. The polkit message names the missing `Input Monitoring`, `Input
Control`, or both scopes and includes a sanitized executable path. A successful
result is persisted per `{uid, app identity, scope}` under the root-owned
`/var/lib/keysharp-permissions/v1` namespace until manual revocation. The marker
format and shared scope namespace are in
[`permission-store.md`](permission-store.md).
Cancellation, denial, and errors create no records.

Wire operation bits and durable permission scopes are distinct namespaces:

| Request or operation | Required durable scope |
|---|---|
| passive keyboard/mouse hook, full arbitrary key/button state | Input Monitoring |
| synthesis, full-device `BlockInput` | Input Control |
| suppressing hook (`BLOCK` or `MODIFY`) | Input Monitoring and Input Control |
| pointer position, modifier snapshot, lock-toggle state, idle time | none |

The daemon maps requested operation bits to these two scopes before prompting or
consulting the permission store. `KSI_CAP_BLOCK_INPUT` remains an internal wire
operation, not a third permission category.

Run `keysharp-inputd permissions list` to inspect grants and
`keysharp-inputd permissions revoke <hash>` (or `--pid <pid>`) to remove one.
`keysharp-inputd permissions revoke --all` removes all input scopes for the
caller.
The subcommand speaks `KSI_MESSAGE_LIST_PERMISSIONS` and
`KSI_MESSAGE_REVOKE_PERMISSIONS` to the daemon. List entries carry only
`persistent_scopes`; denials are never stored.
Successful revocation also invalidates matching connected clients immediately:
cached operation bits are cleared, matching hook/BlockInput state is released,
and an authorization dialog which began before the revoke cannot restore the
grant. Revoking Input Monitoring invalidates each matching `HOOK_STREAM`, which
wakes its reader with EOF and requires a fresh connection and hello. Ordinary
RPC connections remain open so independently retained Input Control operations
continue working. This work runs on the daemon control plane; input-event
dispatch never reads permission files. The CLI always mutates scopes through the
running daemon, so editing marker files directly while it runs is unsupported.
A shared revoke-generation edge triggers control-plane refreshes made by any
compatible permission authority, with no periodic permission-file reads in the
input loop.

The list/revoke messages are scoped to the caller's uid. Only root (when the
daemon is running as root) can target another user's records.

## Hook model

The daemon owns hook transport and native fail-open safety; clients own callback
policy. Root keyboard and mouse events use independent lane threads. Each client
has one `HOOK_STREAM` call stack shared by both hook types, so its own
keyboard/mouse callbacks serialize while different clients can execute in
parallel. All uinput-bound writes use one output sequencer thread.

```
evdev / main thread       lane threads             sequencer thread
─────────────────────     ────────────────         ────────────────
classify hook event  ──►  (kbd lane)
                            │  send HOOK_EVENT
                            │  await decision/timeout
                            └─►  action          ──►  uinput
classify hook event  ──►  (mouse lane)
                            │  …
                            └─►  action          ──►
SYNTHESIZE_INPUT     ──────────────────────────────►
```

An ordinary `SYNTHESIZE_INPUT` result acknowledges atomic queue admission; its
low-level callbacks run later and never hold the sender RPC open. A request on an
active `HOOK_STREAM` instead forms one synchronous child transaction on the exact
parent lane, irrespective of child input type. The stream marks its parent frame as
pumping; recursive callbacks then enter the same per-stream call stack ahead of
queued root callbacks. Every child runs the complete newest-to-oldest hook chain,
and the synthesis result is sent only after all child frames unwind. The client
reader pumps those nested `HOOK_EVENT` frames synchronously, so Send returns
child-before-parent just as it does inside a Windows low-level hook. Before the
daemon publishes a synthesis result, it closes that parent pump and lets any
recursive frames which already entered from the other lane unwind. Consequently,
two separate back-to-back Sends cannot overlap stale native pump state.

Recursion is limited to 32 callback transactions and synthesis requests are
limited to 1024 `ksi_input` entries and 4096 expanded low-level hook events. Either
limit rejects the child before hook delivery or uinput output. Recursion-limit and
expanded-size failures use synthesis result details 32 and 33 respectively.

Hook subscriptions require the matching hook operation and Input Monitoring.
Suppressing `BLOCK`/`MODIFY` decisions additionally require the internal block
operation and therefore Input Control. An unauthorized matching response is
acknowledged as denied and resolves immediately as `PASS`, avoiding one timeout
of extra latency per event. Direct `SYNTHESIZE_INPUT` requires Input Control and
the matching synthesis operation. Once
`EVIOCGRAB` is active, passed events must be replayable through `uinput`; if
`uinput` is unavailable, subscriptions are denied.

Every entered subscriber callback has its own one-second deadline. Time spent in
recursive child callbacks is charged to those children, not again to the suspended
parent. A busy stream which cannot start another root turn simply passes that event;
the active callback owns timeout accounting. An entered timeout passes the event and
quarantines only that hook type. `HOOK_QUARANTINED` reports the event, strike and
cooldown; the daemon retries automatically after 1, 2, 4, 8 or 16 seconds. Sixty
seconds without another quarantine resets the strike history. The fifth consecutive
timeout invalidates only that HookStream so client recovery can reconnect it.
Keyboard and mouse quarantine state is independent.

`EMERGENCY_PASSTHROUGH` from a client already granted hook access clears all hook
subscriptions, discards pending hook events, and releases all grabs.

Hook subscriptions and non-zero `BlockInput` masks hold a 15-second lease.
Clients renew active leases using one-way heartbeats.
Expiry clears the client's input state, releases grabs, and disconnects the
client so it can reconnect or fall back.

Physically holding `Backspace+Escape+Enter`, in any press order, performs the same
fail-open action directly in the daemon. It clears hook subscriptions and
`BlockInput` masks and releases grabs without involving client hook logic. The
final chord event is consumed while a keyboard grab is active.

Setting a nonzero `SET_BLOCK_INPUT` mask requires `KSI_CAP_BLOCK_INPUT` and Input
Control. It sets the calling client's physical input block mask: keyboard,
mouse, both, or neither. Clearing the mask is always accepted, even after
authorization loss, so cleanup cannot strand blocked input. The daemon drops
blocked physical events while allowing virtual input to continue. Block masks
are client-scoped and are removed when that client disconnects.

The daemon bounds its queues and admits client input atomically. Each hook lane
has a single pending decision slot, so a decision from any client other than the
lane's current responder — or a late decision after the one-second timeout — is
rejected. A `SYNTHESIZE_INPUT` request or `MODIFY` decision that would exceed the
output bounds is rejected with a failure result rather than partially queued, and
capacity is reserved for key/button releases so saturation cannot split cleanup
after its press.

## Ordering and timestamps

Synthetic batches receive a trusted daemon monotonic admission timestamp in
nanoseconds. Before starting a batch, the daemon peeks every grabbed physical
device; an earlier kernel `CLOCK_MONOTONIC` event runs first (ties favor the
already-observed physical event). Synthesis also waits for every earlier physical
hook callback to reach output admission. After a synthetic batch starts, its
remaining members retain priority over later physical and unrelated synthetic input.
Nested callback synthesis is the normal exception and preempts its parent.
Emergency passthrough and fail-open recovery may preempt everything.

The caller's `INPUT.time` is never used for scheduling. A nonzero value is copied
to the generated hook payload, while zero is replaced with the current monotonic
millisecond value. Past and future values are therefore visible as metadata but
are delivered immediately. Synthetic events retain `device_id = 0`; physical
events retain their daemon-assigned device id.

### Keyboard hook event fields

Modelled after `KBDLLHOOKSTRUCT` + low-level hook `wParam`:

| Field | Description |
|---|---|
| `message` | `WM_KEYDOWN`, `WM_KEYUP`, `WM_SYSKEYDOWN`, `WM_SYSKEYUP` |
| `vk_code` | Windows virtual-key code |
| `scan_code` | Backend low-level key code (e.g. Linux evdev `KEY_*`) |
| `flags` | `LLKHF_EXTENDED`, `LLKHF_INJECTED`, `LLKHF_ALTDOWN`, `LLKHF_UP` |
| `time_ms` | Event timestamp |
| `extra_info` | Equivalent of `dwExtraInfo` |
| `device_id` | Daemon-assigned physical device id |

### Mouse hook event fields

Modelled after `MSLLHOOKSTRUCT` + low-level hook `wParam`:

| Field | Description |
|---|---|
| `message` | `WM_MOUSEMOVE`, `WM_LBUTTONDOWN`, `WM_MOUSEWHEEL`, etc. |
| `x`, `y` | Original replay values: relative counts or a normalized absolute target |
| `mouse_data` | Wheel delta or X-button value |
| `flags` | `LLMHF_INJECTED`-style flags |
| `time_ms` | Event timestamp |
| `extra_info` | Equivalent of `dwExtraInfo` |
| `device_id` | Zero for synthetic input; daemon-assigned positive id for physical input |
| `delta_x`, `delta_y` | Relative counts, or a physical absolute report's change in normalized `[0,65535]` axes; synthetic absolute reports use zero |

### evdev translation

```
KEY_A        → VK_A + scan code KEY_A
BTN_LEFT     → WM_LBUTTONDOWN/UP
REL_WHEEL    → WM_MOUSEWHEEL + WHEEL_DELTA-compatible mouse_data
BTN_SIDE     → WM_XBUTTONDOWN/UP + XBUTTON1-compatible mouse_data
BTN_EXTRA    → WM_XBUTTONDOWN/UP + XBUTTON2-compatible mouse_data
```

Axis records are grouped only to the evdev `SYN_REPORT` boundary; each resulting
relative or absolute movement report is forwarded once.

## Synthesis model

Input synthesis is modelled after Windows `SendInput` (`ksi_input`).

Keyboard synthesis fields: `vk`, `scan`, `flags` (`KEYEVENTF_*`), `time`, `extra_info`.

Mouse synthesis fields: `dx`, `dy`, `mouse_data`, `flags` (`MOUSEEVENTF_*`), `time`, `extra_info`.

The daemon translates requests into `uinput` events. `extra_info` is present in
the protocol for cross-platform shape compatibility but is not preserved by Linux
`uinput`.

`MODIFY` hook decisions append replacement `ksi_input` entries after the decision
header and require the same synthesis capabilities as direct `SYNTHESIZE_INPUT`.

## Device state queries

`GET_POINTER_POSITION` returns the last absolute pointer sample (raw `ABS_X`,
`ABS_Y`, and each axis's min/max). It requires only an authenticated zero-operation
hello and does not grant or consume Input Monitoring.

`GET_INDICATOR_STATE` / `INDICATOR_STATE_RESULT` report the current Caps Lock,
Num Lock, and Scroll Lock LED state without a privileged scope.

`MODIFIER_STATE` reports both logical and physical L/R modifier masks along with
the three lock-toggle bytes without exposing the full key bitmap. Full
`GET_KEY_STATE` and `GET_POINTER_BUTTONS` snapshots can reveal arbitrary key or
button state and therefore require Input Monitoring.

`IDLE_TIME` is fed by keyboard, button, touch, pen, gamepad/media-key,
relative-motion, wheel, and pointer-axis events from tracked evdev devices.
Devices tracked only for idle time are opened read-only and are never grabbed or
hook-dispatched. The daemon's own uinput devices are excluded before the idle
timestamp is updated or hooks are dispatched, so replayed and synthetic input
cannot masquerade as new physical activity. Event timestamps use
`CLOCK_MONOTONIC`; if an IPC query races queued device data, the daemon ingests
that data first and computes the elapsed duration from the newest processed
kernel event timestamp. A zero-operation idle query does not create the daemon's uinput
devices or elevate the observer thread to real-time scheduling; those resources
are activated only for explicitly requested privileged input functionality.

## Injected-event tagging

The daemon's `uinput` device is identified by:

```
name     Keysharp Virtual Input
bustype  BUS_VIRTUAL
vendor   0x0FAC   (masquerades as keyd's vendor so keyd won't re-grab our output; see protocol.h)
product  0x0001
```

The device is identified as *ours* by name **and** vendor (`0x0FAC` is shared with
keyd, so name is the discriminator); keyd's own `keyd virtual keyboard` therefore
does not match and remains a valid interception target for us to grab.

Events from this device set `LLKHF_INJECTED` / `LLMHF_INJECTED` in hook callback
flags. Pass-through replay events are suppressed from re-entering the callback
path; direct `SYNTHESIZE_INPUT` events are not, so clients can apply their own
policy to synthetic input.

## Multiple clients

Multiple processes are modelled as ordered hook clients. Each
subscription carries a client id, hook type, and subscription order. The daemon
owns delivery order, timeout enforcement, device ownership, replay, suppression,
and synthesis. Individual client processes do not open or grab physical devices
themselves.
