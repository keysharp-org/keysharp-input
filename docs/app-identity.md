# Privileged application identity v1

Compatible permission authorities use this app-wide executable identity for
their per-scope marker namespaces while their binaries, authorization actions,
protocols, and implementations remain independent. The identity deliberately
excludes the argument vector: argv can contain secrets, can be rewritten by the
process, and is not a security boundary.

The final identifier is the lowercase hexadecimal SHA-256 of this byte sequence:

```text
ASCII("org.keysharp.app-identity-v1") || 00 || ASCII(kind) || 00 || identity
```

There is no terminator after `identity`.

- Use kind `path` when the running executable inode and every ancestor directory
  through `/` are owned by UID 0 and are not writable by group or others.
  Ancestors are checked with `lstat`; a symlink or mutable ancestor falls back to
  content identity. `identity` is the exact absolute byte string returned by
  `readlink("/proc/<pid>/exe")`. This keeps package-managed grants stable across
  upgrades without letting a user-writable directory transfer a path grant.
- Otherwise use kind `sha256`. Hash the bytes read from the already-open
  `/proc/<pid>/exe` file, encode that digest as 64 lowercase ASCII hex bytes,
  and use those 64 bytes as `identity`.

`/proc/<pid>/exe` names the native host. Framework-dependent programs launched
through a shared host such as `dotnet` therefore share that host identity and
cannot receive distinct per-application permissions. A client that needs a
distinct identity must use its own native/apphost executable.

Test vectors:

| Kind | Identity | Final app hash |
|---|---|---|
| `path` | `/usr/bin/example-client` | `4109d2117781adb1d57931e66ffad58fa3f88a0a6bb7584714f8699225933e1b` |
| `sha256` | 64 ASCII `0` bytes | `73cd7ab5e10d259a782b6e021af8326514447477af0358481ee31fc5fee7d434` |

The daemon captures the peer PID and UID with `SO_PEERCRED`, records field 22
from `/proc/<pid>/stat`, identifies the executable asynchronously, and rejects
the identity if the process start time differs from the accept-time snapshot.
After polkit returns success it verifies both the start time and app hash again
before writing a permission marker.
