# Integrating with keysharp-input

How another project depends on `keysharp-input` and talks to `keysharp-inputd`.
For the complete message set see [protocol.md](protocol.md); for the
authorization rules see [security-model.md](security-model.md).

## The dependency model

There is no library to link. A client needs two things:

- **At build time:** the wire contract in `keysharp-inputd/protocol.h`. It is
  installed under the standard include directory, and it is MIT-licensed, so
  vendoring a copy into your own tree is equally valid.
- **At run time:** an installed, running `keysharp-inputd`.

This keeps the coupling loose. Your build does not need the daemon present, and
your application should treat its absence as a normal condition rather than an
error — see [Degrading when it is absent](#degrading-when-it-is-absent).

## Declaring the dependency

Distribution packages should express the relationship through the package
manager: `Depends` when your application is useless without global input, or
`Recommends` when input features are optional. The dependency graph then
decides when the broker is still needed, and ordinary removal and purge both
preserve the shared permission store.

Applications distributed outside a package manager can bundle the portable
archive and install it only when a compatible broker is missing:

```sh
sudo ./install.sh --skip-if-compatible
```

That probes `keysharp-inputd --info`, verifies the service wiring, socket
settings, polkit policy, tmpfiles declaration, and uaccess rule, and leaves a
compatible installation untouched. It refuses to layer `/usr/local` files over
a distribution- or Nix-managed installation.

Never run the component's uninstaller from your own uninstaller. The broker can
have other clients.

## Finding the socket

| Context | Path |
|---|---|
| Installed system service | `/run/keysharp-inputd/keysharp-inputd.sock` (mode `0666`) |
| Manually launched daemon | `$XDG_RUNTIME_DIR/keysharp/keysharp-inputd.sock` |
| Explicit override | whatever `keysharp-inputd --socket PATH` was given |

The installed socket is world-connectable so a newly active user can reach it.
Authorization does not depend on socket permissions: the daemon rejects peers
that are not the active seat owner before the handshake.

## Wire basics

The transport is an `AF_UNIX` stream socket, so both peers are always the same
machine and the same architecture. Messages are fixed-layout C structures
written directly to the socket:

- **Native byte order and native struct layout.** No field is byte-swapped and
  no packing attribute is applied. Use the header's types as declared; do not
  hand-marshal fields in network order.
- Every message begins with `ksi_message_header`: `size`, `major`, `minor`,
  `type`, `client_id`, `correlation_id`.
- Replies carry the `correlation_id` of their request.

## Handshake and version negotiation

The first message on a connection is `KSI_MESSAGE_CLIENT_HELLO` carrying
`ksi_client_hello_payload`:

| Field | Meaning |
|---|---|
| `requested_capabilities` | bitwise OR of the `KSI_CAP_*` operations you need |
| `flags` | `KSI_CLIENT_HELLO_FLAG_CHECK_ONLY` (`0x2`) to inspect grants without prompting |
| `role` | `KSI_CONNECTION_GENERAL_RPC` (0) or `KSI_CONNECTION_HOOK_STREAM` (1) |

The reply is `ksi_client_hello_result_payload` with a `status` and the
`granted_capabilities` actually available. A client must use the granted set,
not the requested set: the daemon grants only what its own device access and
the caller's permanent grants allow.

Put `KSI_PROTOCOL_MAJOR` and `KSI_PROTOCOL_MINOR` in the header. Treat a
differing major version as incompatible and disable your input features; a
higher minor version on the daemon is backward compatible for the messages this
version defines. Compile the constants in from the header you built against
rather than hardcoding numbers.

Hook streams use a separate connection with `KSI_CONNECTION_HOOK_STREAM`, so an
application that both observes and synthesizes opens two.

## Capabilities and permissions

Two distinct namespaces meet here, and confusing them is the most common
integration mistake.

**Operation bits** are what you request in `CLIENT_HELLO`. They are wire-level
and fine-grained:

| Constant | Value |
|---|---:|
| `KSI_CAP_HOOK_KEYBOARD` | `0x01` |
| `KSI_CAP_HOOK_MOUSE` | `0x02` |
| `KSI_CAP_SYNTH_KEYBOARD` | `0x04` |
| `KSI_CAP_SYNTH_MOUSE` | `0x08` |
| `KSI_CAP_BLOCK_INPUT` | `0x10` |

**Durable scopes** are what the user actually consents to, and what is stored
and revoked. `keysharp-inputd` owns two of the eight shared scopes:

| Constant | Value | Covers |
|---|---:|---|
| `KSP_SCOPE_INPUT_MONITORING` | `0x01` | hook observation, arbitrary key/button state polling |
| `KSP_SCOPE_INPUT_CONTROL` | `0x02` | synthesis and `BlockInput` |

A suppressing hook needs both, because it observes and controls. A passive hook
needs only Input Monitoring. These values are the cross-component contract in
[permission-store.md](permission-store.md); the remaining six scopes belong to
other authorities and are never granted by this daemon.

Cursor position, modifier state, lock-toggle state, and idle time are
permission-free. They never create or consult a grant, so a client can use them
before or without any authorization.

To find out what you already have without opening a polkit dialog, send the
hello with `KSI_CLIENT_HELLO_FLAG_CHECK_ONLY`. Missing capabilities come back as
status `403` together with the already-granted subset. This is the right call
for a settings screen or a startup probe; a plain hello is the right call at the
moment the user asks for the feature.

## Handling revocation

Grants can be revoked at any time, including mid-session. On revocation the
daemon clears the matching capability caches, releases affected hooks and
`BlockInput` state, and closes matching hook-stream transports so readers
reconnect and perform a fresh hello.

A client must therefore treat loss of a hook stream as a normal event:
reconnect, re-hello, and honour the new granted set. Do not assume a capability
granted at startup is still held.

## Degrading when it is absent

Check for the socket, and fall back cleanly when it is missing, the handshake
fails, or the major version differs. A user without the broker installed should
get an application that runs with its global-input features disabled, not one
that fails to start. Tell them what to install and why, and request the
capability at the moment the feature is used rather than at launch.

## A minimal client

`tools/hooktest.c` is a complete, working client covering connection, hello,
hook subscription, pass/block/modify decisions, synthesis, and teardown. Read it
first; it is the reference implementation of everything above.

## Checklist

- [ ] Vendor or install `keysharp-inputd/protocol.h`
- [ ] Declare the runtime dependency in your package metadata
- [ ] Discover the socket, and degrade cleanly when it is absent
- [ ] Send `CLIENT_HELLO` with the operation bits you need, and honour the granted set
- [ ] Reject a differing protocol major version
- [ ] Use `CHECK_ONLY` for status probes so you never prompt unexpectedly
- [ ] Reconnect and re-hello when a hook stream closes
- [ ] Never invoke the component's uninstaller from your own
