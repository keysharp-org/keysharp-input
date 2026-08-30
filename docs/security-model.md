# Security model

How `keysharp-inputd` authenticates clients, authorizes capabilities, and
enforces them. The durable storage contract it shares with other compatible
authorities is in [permission-store.md](permission-store.md); the identity
algorithm is in [app-identity.md](app-identity.md).


`keysharp-inputd` is a root-owned system service. Client users do not need and
should not be added to the `input` group.

- The daemon uses `SO_PEERCRED` to record each connecting process's pid/uid/gid.
- The system service resolves logind's active `seat0` uid and accepts input
  clients only from that uid. A switched-away user's existing connections stay
  open so its subscriptions can resume after switching back, but they are inert:
  they cannot receive hooks, hold BlockInput/grabs, query input state, or
  synthesize. A seat-owner generation fence also discards delayed callback,
  replay, and synthesis output from the former session before the new user is
  activated. If logind cannot identify an active owner, input IPC fails closed.
- A manually launched daemon keeps the separate per-user model: its private
  `$XDG_RUNTIME_DIR` socket accepts only the daemon uid.
- It resolves `/proc/<pid>/exe`. Root-owned executables whose entire path is
  protected from group/other writes use a stable path identity; development or
  mutable-path binaries use their content digest. Arguments are never read into
  the authorization flow.
- Clients send `CLIENT_HELLO` with requested capabilities; the daemon grants only
  what its own device access allows.
- Protocol 1.2 clients can set `KSI_CLIENT_HELLO_FLAG_CHECK_ONLY` (`0x2`) to
  inspect permanent grants without opening polkit. Missing capabilities return
  hello status `403` together with any already-granted subset.
- For an unknown `{uid, app identity}`, the daemon executes `/usr/bin/pkcheck`
  for `org.keysharp.input.grant` with the authenticated PID, process start time,
  and UID. The polkit dialog names the missing `Input Monitoring`, `Input
  Control`, or both scopes and the sanitized executable path. A shared per-app
  lock serializes prompts from compatible permission authorities; after
  taking it the daemon rechecks existing grants, and it retains the lock through
  the generation-fenced save. It verifies the start time again after
  authorization before saving.
- Successful authorization creates root-owned per-scope markers under
  `/var/lib/keysharp-permissions/v1`. Grants do not expire; denial and cancel
  are not stored. See
  [`permission-store.md`](permission-store.md).
- The installed socket is world-connectable so a newly active user can reach it,
  but inactive-uid peers are rejected before `CLIENT_HELLO`. Connections that do
  not complete the handshake are dropped after a short deadline, while per-uid
  and global slot limits remain bounded. Unknown hello flags are rejected.

`CLIENT_HELLO` operation bits remain fine-grained for enforcement:
`KSI_CAP_HOOK_KEYBOARD`, `KSI_CAP_HOOK_MOUSE`, `KSI_CAP_SYNTH_KEYBOARD`,
`KSI_CAP_SYNTH_MOUSE`, and `KSI_CAP_BLOCK_INPUT`. Hook operations map to the
durable Input Monitoring scope. Synthesis and `BlockInput` map to Input Control.
A suppressing hook therefore needs both scopes; a passive hook needs only Input
Monitoring. Cursor position, modifier, and lock-state queries need neither
scope. Full arbitrary key and mouse-button state queries need Input Monitoring.
Users can inspect and remove grants without root through the authenticated
daemon connection:

```bash
keysharp-inputd permissions list
keysharp-inputd permissions revoke <hash>
keysharp-inputd permissions revoke --pid <pid>
keysharp-inputd permissions revoke --all
```

Removing a grant immediately clears matching capability caches on every
connected client, releases its affected hooks and BlockInput state, and prevents
an in-flight authorization result from restoring it. Revoking Input Monitoring
also closes matching hook-stream transports so readers reconnect and perform a
fresh hello. A later interactive permission request authenticates again. An
inotify watch triggers external
revocation refreshes; watch failure releases active input state and disables
persistent privileges. There is no periodic grant-store I/O in input-event
dispatch.

Hook subscriptions require the matching hook operation and Input Monitoring.
`BLOCK` and `MODIFY` decisions require the internal block operation as well, so
suppressing hooks require both Input Monitoring and Input Control. Unauthorized
decisions resolve the waiting lane as `PASS` immediately. Direct synthesis needs
Input Control. Clearing `BlockInput` is always accepted so teardown fails open.

`MODIFY` is the protocol's suppress-and-replace primitive: the original hook
event is blocked and its nonempty replacement input list is emitted in order.
The entire decision is rejected if the list is empty or the client lacks any
required keyboard/mouse synthesis operation. Clients may instead return
`PASS`/`BLOCK` and perform inline sends as separate recursive
`SYNTHESIZE_INPUT` calls; `MODIFY` remains available to protocol clients such as
`hooktest`.

`SYNTHESIS_RESULT` uses stable detail values from `ksi_status_detail` in
`protocol.h`: malformed payload (1), input-count limit (2), payload-size
mismatch (3), resource exhaustion/backpressure (12), recursion limit (32),
expanded-input limit (33), cancellation (125), permission denied (403), and
callback timeout (408). Success has detail 0.

