# Privileged physical-input live tests

These tests exercise the installed daemon's real evdev/uinput path. They are
manual, are never registered with CTest, and require access to `/dev/uinput` and
the daemon socket. The source device exposes only F13 through F18, avoiding text,
shortcuts, modifiers, pointer motion, and ordinary desktop keys.

## Build and safety

```bash
cmake -S . -B build-physical \
  -DBUILD_TESTING=OFF -DKEYSHARP_INPUTD_BUILD_PHYSICAL_TEST_TOOL=ON
cmake --build build-physical -j
```

Do not run the source against an unmodified production session if F13–F18 have
locally configured actions. For output assertions, first identify the daemon's
`Keysharp Virtual Input` keyboard under `/dev/input/by-id` or `/proc/bus/input/devices`
and capture it with a root-capable evdev reader using an exclusive grab. The grab
keeps captured output away from the desktop. `evtest --grab /dev/input/eventN` is
one suitable reader; keep it running in terminal 1.

The commands below deliberately require the acknowledgement environment variable.
Run them as a user with uinput permission, or through `sudo --preserve-env`:

```bash
export KEYSHARP_INPUTD_PHYSICAL_TEST=I_UNDERSTAND
SRC=build-physical/keysharp-inputd-physical-source
HOOK=build/keysharp-inputd-hooktest
```

## Test matrix

Start each hook command in terminal 2, then run its source command in terminal 3.
Stop and investigate if a source hook has `injected=yes` or `device=0`: source
events must be reported as physical and must retain one stable nonzero device ID.

### Physical device ID and PASS output

```bash
$HOOK --keyboard --decision pass --count 2
$SRC 13
```

Expected hook records: F13 down/up, `injected=no`, the same nonzero `device` on
both. Expected captured output: exactly F13 down, SYN, F13 up, SYN.

### BLOCK output

```bash
$HOOK --keyboard --decision block --target-vk 0x7c --count 2
$SRC 13
```

VK `0x7c` is F13. The physical hook records remain visible and receive BLOCK;
the captured output must contain no F13 event.

### MODIFY output

```bash
$HOOK --keyboard --decision modify --target-vk 0x7d --modify-vk 0x7e --count 4
$SRC 14
```

VKs `0x7d` and `0x7e` are F14 and F15. Expected source records are physical F14
down/up with a nonzero device ID. Expected replacement records are injected F15
down/up with `device=0`. Captured output must contain F15 down/up and no F14.

### SendInput does not intersperse physical input

This invariant needs a protocol client that submits one batch of alternating
F16/F17 strokes while repeatedly running `$SRC 18`.
Capture the daemon keyboard output as above. Each accepted synthetic batch must
be one contiguous run: physical F18 may appear before or after it, never between
two members. Repeat at least 1,000 batches because this is a scheduling test.

The source's two-second discovery delay prevents the virtual device's first event
from racing inputd hotplug discovery. The tool always destroys its device on a
normal exit; if it is killed, closing its file descriptor destroys it in-kernel.

### Replay visibility (uaccess ACL / total-lockout regression)

This verifies that the `70-keysharp-inputd-uaccess.rules` rule installed by
`--install-input-access` makes replayed events visible to the display server
while hooks are engaged. Without the ACL, a session user outside the `input`
group cannot read the daemon's virtual devices and pass-through input can be
lost. This test needs a real desktop session (X11 or
Wayland) whose user is **not** in the `input` group — `id -nG | grep -w input`
must print nothing — because membership masks the failure.

Keep an SSH session from another machine open for recovery before starting.
If input ever dies: hold Backspace+Escape+Enter in any order to activate the
daemon's panic combo (releases all grabs), or use the SSH session to run
`sudo systemctl stop keysharp-inputd`.

The daemon consumes the final chord key while the keyboard is grabbed and clears
all hooks and `BlockInput` requests. Restart affected protocol clients if the
hooks are needed again.

1. Confirm the rule is installed:
   `test -f /etc/udev/rules.d/70-keysharp-inputd-uaccess.rules && echo ok`
2. Run `$HOOK --keyboard --mouse --decision pass --count 1000000` so the daemon
   grabs devices and creates its virtual devices.
3. Find the `Keysharp Virtual Input` / `Keysharp Virtual Pointer` event nodes in
   `/proc/bus/input/devices` and verify the ACL:
   `getfacl /dev/input/eventN` must list `user:<session-user>:rw-`.
4. Type ordinary text into an editor and move the mouse: everything must pass
   through normally and appear in the hooktest output.
5. Negative control (optional — this deliberately reproduces the lockout; only
   with the SSH recovery shell ready): stop hooktest, run
   `sudo keysharp-inputd --remove-input-access`, start hooktest again so the
   virtual devices are recreated without the ACL, and confirm input dies while
   hook records still appear. Recover via Backspace+Escape+Enter or SSH, then re-run
   `sudo keysharp-inputd --install-input-access` and repeat steps 1–4.
