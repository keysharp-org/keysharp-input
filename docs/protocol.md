# Private IPC protocol 2.0

Applications and language bindings should use `keysharp_input/client.h`. This
document defines the binary transport for service maintenance, diagnostics, and
conformance tests.

## Envelope

Every integer is unsigned little-endian unless stated otherwise. Native C
layout is never sent. The header is exactly 24 bytes:

| Offset | Type | Field |
|---:|---|---|
| 0 | byte[4] | magic `KSIP` |
| 4 | u16 | major, `2` |
| 6 | u16 | minor, `0` |
| 8 | u16 | opcode |
| 10 | u16 | flags |
| 12 | u32 | payload length |
| 16 | u64 | request id |

Flags are RESPONSE=`0x0001`, EVENT=`0x0002`, and MORE=`0x0004`. Unknown bits
are invalid. RESPONSE and EVENT are mutually exclusive. MORE requires
RESPONSE. Events use request id zero; responses use a nonzero id. Requests use
a nonzero id except a one-way, empty PING with id zero.

A response begins with `{u32 status,u32 detail}`. On success, the opcode's
result body follows. On failure it may append `{u32 utf8_length,byte text[]}`
and has no result body. Status values are OK=0, DENIED=1, UNSUPPORTED=2,
INVALID_REQUEST=3, UNAVAILABLE=4, BUSY=5, NOT_FOUND=6,
RESOURCE_EXHAUSTED=7, TIMEOUT=8, CANCELLED=9, REVOKED=10, INTERNAL=255.

HELLO must be the first request and may appear exactly once.

## Common operations

| Opcode | Name | Request | Successful result body |
|---:|---|---|---|
| `0x0001` | HELLO | `{u16 role,u16 auth_mode,u32 scopes,u64 reserved=0}` | `{u32 granted,u32 reserved=0,u64 available_operations}` |
| `0x0002` | AUTHORIZE | `{u16 auth_mode,u16 reserved=0,u32 scopes,u64 reserved=0}` | `{u32 granted,u32 reserved=0}` |
| `0x0003` | PING | empty | empty |
| `0x0004` | PERMISSIONS_LIST | empty | streamed, below |
| `0x0005` | PERMISSIONS_REVOKE | 48 bytes, below | empty |
| `0x0006` | SESSION_REVOKED | server EVENT | `{u32 revoked_scopes,u32 reserved=0}` |

Roles are RPC=0, EVENT_STREAM=1, CALLBACK_STREAM=2, and
AUTHORIZATION_LEASE=3. This service accepts RPC, CALLBACK_STREAM, and
AUTHORIZATION_LEASE. Authorization modes are CHECK=0 and REQUEST=1. Input
scopes are InputMonitoring=`0x01` and InputControl=`0x02`; foreign bits are
rejected.

LIST sends zero or more RESPONSE|MORE frames. Each successful frame body is
`{u32 scopes,u32 path_length,u64 granted_at_utc,u8 hash[32],byte path[]}`.
The terminal RESPONSE is status-only. REVOKE is
`{u32 target_kind,u32 scopes,u64 pid,u8 hash[32]}`; kinds HASH=1, PID=2,
ALL=3. Unused pid/hash fields are zero. Scope zero is invalid. The service
lists and revokes only its two managed scopes.

## Available operations

| Bit | Operation | Permission |
|---:|---|---|
| `0x0001` | keyboard hook | Input Monitoring |
| `0x0002` | mouse hook | Input Monitoring |
| `0x0004` | keyboard synthesis | Input Control |
| `0x0008` | mouse synthesis | Input Control |
| `0x0010` | input blocking | Input Control |
| `0x0020` | indicator query | none |
| `0x0040` | pointer-position query | none |
| `0x0080` | arbitrary key-state query | Input Monitoring |
| `0x0100` | pointer-button query | Input Monitoring |
| `0x0200` | idle-time query | none |
| `0x0400` | modifier-state query | none |

Operation availability and granted permission scopes are separate masks.

## Input operations

| Opcode | Name | Request body | Successful result body |
|---:|---|---|---|
| `0x1000` | SUBSCRIBE_HOOK | `{u32 hook_type,u32 reserved=0}` | `{u32 active_hook_operations,u32 reserved=0}` |
| `0x1001` | UNSUBSCRIBE_HOOK | same | same |
| `0x1002` | HOOK_EVENT | server request, below | client response, below |
| `0x1003` | HOOK_QUARANTINED | server EVENT, 32 bytes | none |
| `0x1010` | SYNTHESIZE_INPUT | `{u32 count,u32 flags,input[count]}` | empty |
| `0x1012` | SET_BLOCK_INPUT | `{u32 mask,u32 reserved=0}` | `{u32 effective,u32 reserved=0}` |
| `0x1020` | GET_INDICATOR_STATE | empty | 4 bytes |
| `0x1021` | GET_POINTER_POSITION | empty | 28 bytes |
| `0x1022` | GET_KEY_STATE | empty | 200 bytes |
| `0x1023` | GET_POINTER_BUTTONS | empty | 12 bytes |
| `0x1024` | GET_IDLE_TIME | empty | 16 bytes |
| `0x1025` | GET_MODIFIER_STATE | empty | 12 bytes |

Hook types are keyboard=13 and mouse=14. A hook event is an ordinary server
request with a nonzero id. Its body begins `{u32 hook_type,u32 reserved=0}`.
The keyboard event body after that prefix is 40 bytes:
`{u32 message,u32 vk,u32 scan,u32 flags,u64 time_ms,u64 extra_info,u32 device,u32 reserved}`.
The mouse body is 52 bytes:
`{u32 message,i32 x,i32 y,u32 mouse_data,u32 flags,u64 time_ms,u64 extra_info,u32 device,u32 reserved,i32 delta_x,i32 delta_y}`.

The decision is a RESPONSE with the same opcode and request id. Success is
`{status,detail,u32 decision,u32 input_count,input[input_count]}`. Decisions
are Pass=0, Block=1, Modify=2. Pass and Block have zero inputs; Modify has at
least one. A non-OK status has no decision body and fails open as Pass.

HOOK_QUARANTINED is
`{u32 hook_type,u32 reason,u64 event_id,u32 generation,u32 strike_count,u32 retry_after_ms,u32 reserved=0}`.
Reasons are timeout=1 and transport=2.

Each input record is 40 bytes. It starts `{u32 type,u32 reserved=0}`. Keyboard
type 1 stores `{u16 vk,u16 scan,u32 flags,u32 time,u32 reserved,u64 extra_info,u64 reserved}`
at offset 8. Mouse type 0 stores
`{i32 dx,i32 dy,u32 mouse_data,u32 flags,u32 time,u32 reserved,u64 extra_info}`
at offset 8. The only public synthesis flag is BYPASS_HOOK=`0x01`.

## Ordering and safety

Callback-stream requests may receive nested HOOK_EVENT requests while awaiting
their response. A client must synchronously dispatch and answer each child
before it can receive the parent response. Request ids pair frames; they do not
encode ancestry.

Hook callbacks are bounded and fail open. A malformed, unauthorized, stale, or
late decision becomes Pass. Suppression and replacement additionally require
Input Control. SESSION_REVOKED clears the affected grant and releases hooks or
blocking state that depended on it. A callback or authorization-lease stream
can remain open for unaffected scopes.

Subscriptions and nonzero input blocking use a 15-second lease. Empty PING
requests renew it; id zero avoids a response on a receive-sensitive callback
stream. The physical Backspace+Escape+Enter chord also releases grabs without
depending on any client.

## Client forward compatibility

The shipped client library tolerates enumerated values it does not know. Scope
bits, operation bits, quarantine hook types, key codes, and scan codes arrive
verbatim; an unrecognized one is never treated as supported and never fails the
call. Framing stays strict: magic, major and minor, unknown flag bits, reserved
fields, payload lengths, and malformed tails invalidate the connection. Values
travelling client to service are still validated against this build's
vocabulary before they are sent.
