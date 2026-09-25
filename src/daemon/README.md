# Daemon ownership units

These private implementation units are included by `daemon.c` in dependency
order and compile as one translation unit. This keeps daemon-only types and
helpers private while making ownership boundaries explicit without introducing
an internal ABI.

- `privilege_workers.inc`: process identification and permission prompt jobs.
- `permission_workers.inc`: bounded store checks, listings, revocations, and snapshots.
- `permission_completions.inc`: main-thread grant application and revocation fences.
- `client_lifecycle.inc`: client removal and connection cleanup.
- `hook_lanes.inc`: bounded output sequencing, keyboard/mouse lanes, decisions,
  and lane shutdown.
- `grab_leases.inc`: operations, grabs, leases, fail-open state, and hook
  failure accounting.
- `hook_dispatch.inc`: physical event snapshotting, emergency replay, and
  backend hook callback dispatch.
- `observers.inc`: bounded passive input/device notification queues and nonblocking writes.
- `hook_ingress.inc`: physical/synthetic hook ingress fairness and Send input
  conversion into hook events.
- `protocol_server.inc`: protocol handlers, frame parsing, accept, and command
  result processing.

Standalone infrastructure with independently testable ownership lives beside
`daemon.c`:

- `connection_ref.c`: connection lifetime, serialized writes, and the per-stream
  keyboard/mouse callback call stack.
- `pipe_ring.c`: bounded pipe-woken inline ring.
- `synthetic_hooks.c`: pure expansion of SendInput records into the individual
  low-level hook events observed by Windows callbacks.
- `wake_pipe.c`: nonblocking self-pipe lifecycle and draining shared by queues.
- `worker_pool.c`: fixed worker threads, bounded jobs, and timed shutdown.

Do not add cross-unit globals. Shared daemon state and forward declarations
belong in `daemon.c`; reusable synchronization or lifecycle mechanisms belong
in standalone modules.

## Concurrency invariants

- The main thread exclusively owns `clients[]`, subscription snapshots, device
  discovery, and protocol parsing.
- Permission workers carry immutable requests and retained connection references.
  The main thread compares their completion tokens without dereferencing worker-owned
  jobs; deadlines live in client state. Store locks and marker commits never run
  on the physical input reader.
- Each hook lane owns its current event context. Other threads communicate with
  it only through bounded action, decision, and nested-transaction queues.
- One `ksi_hook_send_ref` owns each callback stream's keyboard/mouse callback stack.
  Root turns enter only an empty stack; recursive turns enter only while the top
  callback is synchronously pumping Send.
- The output sequencer writes all client and passed output and owns generic
  synthesis-device recovery. Admission order is fixed before work reaches it.
  The reader registers each source and retires it when the source disappears.
  A source's keyboard keys go to the sink, the generic keyboard device that
  synthesis also writes, and the rest of it to its own clone, created only when
  there is some. Ending a grab is queued like output: it moves the source to a
  new target when admitted and again when written, so a decision from the ended
  grab cannot reach its outputs, and releases the holds the source no longer
  has. The
  registry lock fences these changes against writes, and linux_output's lock
  serializes every uinput write with the grab probe. The sequencer destroys a
  retired clone after a 100 ms drain.
- Passed physical input carries its source's target and raw evdev values
  through the hook lane and output queue; the keyboard lane goes to the sink
  and the mouse lane to the clone, so each lane ends its report on the device
  it wrote. A key or button transition never bypasses a full lane, which would
  reorder it; it fails open instead. Client synthesis and Modify replacements
  use the generic devices, where every hold has an owner. A compositor reads
  each device's queue as a group, so keyboard state has one device: the sink
  holds a key while synthesis or any source does and writes only the first
  press and the last release. The output queue refuses Modify output from
  revoked hooks. A closed
  connection's accepted batches still play whole: a release marker queued
  behind them in the synthetic hook queue ends what they hold. Key state
  is kept at two queue positions, written (APPLIED) and admitted (ENQUEUED),
  so queries see accepted output early. Each action updates ENQUEUED when it
  is admitted and APPLIED when it drains:

  | Action | Key state it changes |
  |---|---|
  | REPLAY | source output; a key-up ends the Modify holds derived from it and, unless a hook suppressed it, every generic hold of its key |
  | SOURCE_STATE | source state, which ending a grab keeps |
  | SYNTH | generic holds, and displaced or restored source holds |
  | END_GRAB | source target, source holds the source no longer has, and Modify holds owned by the ended grab |
  | RELEASE_SYNTH_OWNER | generic holds of the matching owners |
  | RELEASE_GENERIC | all generic holds |
  | RELEASE_ALL, RECREATE_SYNTH | all generic holds; RELEASE_ALL also every source's holds |
- A `ksi_synth_completion` counts every admitted fragment; exactly the transition
  from one to zero releases the atomic-transaction count and destroys it. Recursive
  completions also own the callback-stream reply reference; ordinary batches are detached
  because their RPC already acknowledged admission.
- `flush_generation` invalidates queued snapshots during fail-open or teardown;
  stale events may release resources but must not invoke callbacks or output
  synthetic replacements.
- `active_input_generation` independently fences every queued output across a
  seat-owner transition.
- Each entered callback has its own monotonic deadline. A parent's deadline is
  suspended while recursive child transactions consume their own turns.

The white-box CTest target includes `daemon.c` in a test translation unit so it
can exercise private queue and ownership invariants without exporting a
daemon-internal API. Reusable modules such as `pipe_ring` and `synthetic_hooks`
have separate black-box test executables. Keep production symbols private; add
focused module tests when changing expansion or synchronization behavior and
white-box tests for daemon-only admission, completion, or ownership rules.
