# Security model

The root-owned service is the only process that opens physical evdev devices or
the uinput output device. Client users do not need membership in the `input`
group.

The system socket is world-connectable so the active desktop user can reach it.
The service authenticates each peer with `SO_PEERCRED`, admits only the active
seat0 uid, records the process start time, and derives the application identity
from `/proc/<pid>/exe`. A seat change fences queued work and releases grabs
before the new owner becomes active.

HELLO is mandatory. Its requested permission bits are Input Monitoring and
Input Control; its returned operation mask reports what the current backend can
perform. These masks are intentionally separate.

- Input Monitoring permits global hooks and arbitrary key/button state.
- Input Control permits synthesis, input blocking, and hook suppression.
- A hook that can observe and suppress needs both.
- Modifier, lock, pointer-position, and idle-time queries need neither.

CHECK authorization only reads existing grants. REQUEST takes the shared
per-application prompt lock and runs `pkcheck` for
`org.keysharp.input.grant`. PID, uid, process start time, executable identity,
and requested scopes come from authenticated service state. The identity is
revalidated after polkit succeeds and before a generation-fenced grant is
written.

Grants are root-owned records in `/var/lib/keysharp-permissions/v1`. The
canonical shared implementation is vendored from `keysharp-permissions`; this
service configures it to read and write only the two input scopes. Foreign
scope bits are rejected.

Revocation emits `SESSION_REVOKED`, clears cached grants, and releases matching
hooks or blocking state. The runtime generation file lets another compatible
authority trigger the same refresh. An inotify failure disables persistent
privileges and releases active input state. Permission files are never read on
the physical input hot path.

Hook lanes use preallocated event pools, fixed queues, and one-second callback
deadlines. Heap fallback is reserved for queue saturation. Missing, malformed,
unauthorized, stale, and timed-out decisions become Pass. Repeated timeouts
quarantine only the affected hook type and emit a typed notification. The fifth
consecutive timeout disconnects that callback stream. Replacement and
synthesis batches are bounded and admitted atomically.

The Backspace+Escape+Enter physical chord clears subscriptions, input blocking,
and grabs without consulting a client. Closing a client also releases all of
its state.

Users administer their own grants through the authenticated connection:

```bash
keysharp-input permissions list
keysharp-input permissions revoke --hash HASH
keysharp-input permissions revoke --pid PID input-monitoring
keysharp-input permissions revoke --all
```
