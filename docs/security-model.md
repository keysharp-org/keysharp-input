# Security model

The root-owned service is the only process that opens physical evdev devices or
the uinput output device. Client users do not need membership in the `input`
group.

The system socket is world-connectable so the active desktop user can reach it.
The service authenticates each peer with `SO_PEERCRED`, admits only the active
seat0 uid, records the process start time, and derives the application identity
from `/proc/<pid>/exe`. A seat change fences queued work and releases grabs
before the new owner becomes active.

Granted connections retain an executable fingerprint and revalidate it on the
identity worker pool at 250 ms maintenance intervals. An executable change or
process exit invalidates the transport and its hooks. A queued revalidation that
has not renewed the identity within one second closes the connection at the next
maintenance pass. This is a bounded lifecycle lease, not instantaneous kernel
notification of exec. No executable hashing or
permission-file reads run for each physical event. Pending prompts cancel when
their connection closes or the active-seat generation changes.
Store checks, grant commits, permission listing/revocation, and revoke-notification
refreshes run on bounded worker pools. Interactive prompts, identity checks, and
store administration have separate pools so a delayed store or dialog cannot hold
the physical input reader. Each connection has at most one pending store request,
with a 15-second deadline; prompt authorization has a 130-second overall deadline.
The main loop closes timed-out requests; a worker blocked inside an operating-system
filesystem call may outlive that request. The service's shutdown deadline handles
workers that cannot return, after physical grabs have been released.
Cancellation is checked after acquiring the grant lock and before publishing each
marker. Scopes committed before cancellation remain durable.

An external revoke notification pauses privileged dispatch and releases grabs
while a worker refreshes cached grants. The main loop continues receiving physical
input; it restores subscriptions whose grants remain valid and invalidates revoked
ones. Refresh failure or timeout disables privileged input. Connection IDs, seat
generation, and permission generation fence late completions.

HELLO is mandatory. Its requested permission bits are Input Monitoring and
Input Control; its returned operation mask reports what the backend implements,
not what is ready right now. These masks are intentionally separate.

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
service configures it to read and write only the two input scopes. Scope bits
outside that pair are rejected. Input Control is not exclusive to this service:
`keysharp-desktop` manages the same bit, the marker carries no service name,
and a grant or a revocation of it on either side is the same record.

Revocation emits `SESSION_REVOKED`, clears cached grants, and releases matching
hooks or blocking state. Revoking Input Control removes the one marker
`keysharp-desktop` also reads, so it ends that service's use of the scope too.
The runtime generation file lets another compatible authority trigger the same
refresh. An inotify failure disables persistent privileges and releases active
input state. Permission files are never read on the physical input hot path.

Hook lanes use preallocated event pools, fixed queues, and one-second callback
deadlines. Heap fallback is reserved for queue saturation. Missing, malformed,
unauthorized, stale, and timed-out decisions become Pass. Repeated timeouts
quarantine only the affected hook type and emit a typed notification. The fifth
consecutive timeout disconnects that callback stream. Replacement and
synthesis batches are bounded and admitted atomically.

Passive observer streams require Input Monitoring but acquire no grabs and accept
no hook decisions. Each stream has a fixed queue; event delivery never waits for
socket capacity. Overflow is reported explicitly and slow readers cannot hold the
physical replay path. Device enumeration also requires Input Monitoring.

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

The first, second, and fourth of those omit a scope and so default to both
input scopes. Because Input Control is one shared grant, each of them also
stops the application's `keysharp-desktop` pointer calls. The third names
`input-monitoring`, the only scope no other authority shares.
