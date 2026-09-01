# Physical live checks

These checks require a real Linux desktop, root service access, and sacrificial
input devices. They are intentionally not part of CTest or CI.

1. Install the package and confirm `keysharp-input probe` succeeds.
2. Connect a small client through `keysharp_input/client.h`, request Input
   Monitoring, subscribe to keyboard and mouse hooks, and return Pass.
3. Confirm physical events appear once and remain usable after the client exits.
4. Request Input Control and synthesize one key and one pointer movement.
5. Return Block for a chosen test key, then disconnect and confirm the key is
   restored immediately.
6. Revoke the active hash with `keysharp-input permissions revoke --hash HASH`
   and confirm the callback stream reports `SESSION_REVOKED` and releases grabs.
7. Hold Backspace+Escape+Enter and confirm all input reaches the desktop again.

Run destructive or blocking tests only with a second recovery session or input
device available. The service's panic chord and disconnect cleanup are safety
nets, not a substitute for that recovery path.

To inspect service state:

```bash
systemctl status keysharp-input.socket keysharp-input.service
journalctl -u keysharp-input.service -f
```
