# Shared permission-store contract

Independent privileged components can implement this small on-disk contract
without linking to a common library or depending on one another. A permission
granted through one compatible authority can therefore satisfy the same scope in
another.

## Identity and scopes

A permission is keyed by `(uid, application identity, scope)`. Application
identity uses `org.keysharp.app-identity-v1`, documented in
[`app-identity.md`](app-identity.md).

The v1 storage and administration-message namespace contains these stable
scopes: Input Monitoring, Input Control, Window Monitoring, Window Control,
Screen Capture, Audio Capture, Camera Capture, and Clipboard Monitoring. Their
numeric constants are part of the public contract in
`include/keysharp_inputd/protocol.h`. They are a separate namespace from
`CLIENT_HELLO` operation bits.

`keysharp-inputd` accepts only the Input Monitoring and Input Control storage
scopes. Hook observation and full key/button-state polling map to Input
Monitoring. Synthesis and input blocking map to Input Control. Suppressing hooks
require both. Cursor position, modifier snapshots, lock-toggle state, and idle
time use neither scope.

## Files and concurrency

The persistent root is `/var/lib/keysharp-permissions/v1`, owned by root and mode
`0700`. Each permission is one root-owned, mode-`0600` marker:

```text
grant-<uid>-<64-lowercase-hex-identity>-<8-hex-scope>.grant
```

Its contents are:

```text
keysharp-permission-v1
<uid>\t<identity>\t<scope>\t<unix-time>\t<display-path>
```

Authorization requires the filename and record to agree. Readers reject
symlinks, non-regular files, an unexpected owner, permissive modes, malformed
records, and unknown identity text.

The executable path is display-only metadata. Before it is stored or included
in a polkit detail, every byte below `0x20` and `0x7f` is replaced with `?`, so a
Linux filename cannot inject a new line or terminal control into a prompt.

One file represents one scope bit. Adding a permission uses a mode-`0600`
temporary file, `fsync`, atomic `rename`, and a directory `fsync`. Revocation
unlinks only explicitly owned scope files. Unknown files and scope values are
preserved. Implementations serialize marker operations through
`/var/lib/keysharp-permissions/v1/.lock` with `flock`.

Unix DAC cannot grant write access to a protected file based on executable
identity. Safety instead comes from narrowly sandboxed root authorities, the
protected directory, validated marker files, the common lock, and each authority
masking requests to the scopes it enforces.

## Live revocation and prompt races

Every revoke is bracketed, while holding the common store lock, by increments of
the root-owned generation file
`/run/keysharp-permissions/revoke-<uid>.generation`. `keysharp-inputd` watches the
runtime directory with inotify, re-reads affected identities only after a
generation edge, and clears affected hooks, grabs, blocking state, and cached
operations. Revoking Input Monitoring also invalidates matching hook-stream
transports so their readers reconnect and reauthorize. Queue overflow, watch
loss, unexpected generation-file deletion, or a failed generation read disables
persistent privileges and releases active input state. There is no periodic
permission-store I/O on the input/event loop.

Before opening polkit, an authority takes the root-owned mode-`0600`
`/run/keysharp-permissions/.prompt-<uid>-<app-hash>.lock`. Once serialized, it
rechecks the store and skips any scope another authority already granted. The
prompt lock remains held until the result has been processed and persisted. The
shared store lock is not held across user interaction, so revocation remains
available. A permission is written only if the generation observed after taking
the prompt lock is unchanged; an overlapping revoke therefore wins.

## Why this store exists

[`xdg-desktop-portal` PermissionStore](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.PermissionStore.html)
is a backend for permissions associated with portal-owned resources. Its
free-form strings are not interpreted, so it supplies neither an authorization
prompt nor an enforcement boundary for evdev, uinput, or compositor-extension
access. [`polkit`](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
authenticates a transaction; administrator policy is not application-managed
durable per-executable consent. Root-owned markers therefore carry the durable
scope state enforced by compatible authorities.

## Package ownership and removal

The persistent and runtime roots are shared state, not files owned by any one
package. Installing a compatible component may create them. Package removal,
package purge, and the portable uninstaller preserve them so removing one
component cannot revoke authorization needed by another. Permissions are removed
through an authenticated administration CLI. A system-wide action that removes
all shared permission state must be explicit and must first verify that no
installed package still uses this contract.
