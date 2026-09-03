# Shared permission store

`keysharp-input` vendors the canonical MIT-licensed `keysharp-permissions`
source as a submodule. Other compatible authorities use the same library so
scope values, application identity, locking, persistence, and revocation cannot
drift.

The version-1 namespace contains eight scopes:

| Scope | Value |
|---|---:|
| Input Monitoring | `0x01` |
| Input Control | `0x02` |
| Window Monitoring | `0x04` |
| Window Control | `0x08` |
| Screen Capture | `0x10` |
| Audio Capture | `0x20` |
| Camera Capture | `0x40` |
| Clipboard Monitoring | `0x80` |

This service configures `read_scopes` and `write_scopes` to `0x03`. It cannot
list, grant, or revoke a scope outside that mask.

Inside the mask it is not alone. `keysharp-desktop` manages `0x02` for its
pointer calls, and a marker file is named `grant-<uid>-<hash>-<scope>.grant`
with no service in it, so Input Control is one grant that either service reads,
writes, and unlinks. Only `0x01` belongs to this service alone.

Persistent records live below `/var/lib/keysharp-permissions/v1`; runtime
generation and prompt-lock files live below `/run/keysharp-permissions`. Both
directories are root-owned. A grant is keyed by uid, the application identity
from [app-identity.md](app-identity.md), and one scope bit. Record paths and
contents are validated before use; symlinks, permissive modes, malformed data,
unknown scope bits, and ownership mismatches are rejected.

Writes use a protected temporary file, fsync, atomic rename, and directory
fsync while holding the store lock. Revocation increments the uid's generation
while holding that same lock. An authorization request records the generation,
runs polkit without the store lock, revalidates identity, and writes only if the
generation is unchanged. Therefore a concurrent revoke wins.

A separate per-uid/application prompt lock serializes interactive requests
across authorities. After taking it, an authority rechecks the store and avoids
a duplicate prompt when another authority already granted the scope.

Package removal and purge preserve this shared state. Users revoke records
through an authority's authenticated permission CLI; no one package owns the
shared directory.

The portal PermissionStore is not used because it neither prompts for nor
enforces evdev/uinput access. Polkit authenticates an interactive transaction;
the protected store supplies durable per-application consent.
