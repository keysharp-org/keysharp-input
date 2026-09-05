# Permissions

The service manages two durable scopes:

| Scope | Required for |
|---|---|
| Input Monitoring | hooks and arbitrary key or button state |
| Input Control | synthesis, blocking, and suppressing or replacing hook events |

Modifier, lock-toggle, cursor-position, and idle-time queries need no durable
permission.

Polkit authenticates an interactive request that no existing grant already
satisfies, and the result remains until it is revoked. Grants live in the
shared permission store outside this project's install prefix, so they survive
an upgrade or a reinstall.

### Input Control is one grant shared with keysharp-desktop

A grant marker is keyed by uid, executable identity, and one scope bit. It
carries no service name, and every authority reads the same directory, so Input
Control is a single grant rather than one grant per service.

A system-installed `keysharp-desktop` manages the same bit for its pointer calls. An application
granted Input Control there already holds it here: `ksi_synthesize` and
`ksi_set_block_input` go through with no second prompt, because the request
path rechecks the store under the shared prompt lock and never reaches
`pkcheck`. The reverse holds too.

Revocation crosses the same way. `keysharp-input permissions revoke` defaults
to both input scopes, so a revoke with no scope argument also stops that
application's `keysharp-desktop` pointer calls, and `revoke --all` does it for
every application of the calling uid. Pass `input-monitoring` to revoke only
the scope nothing else shares.

Input Monitoring is this service's alone. `keysharp-desktop` accepts it for
neither a grant nor a revocation, so a hook grant survives anything done there.
