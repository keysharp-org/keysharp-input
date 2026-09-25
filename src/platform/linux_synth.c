#include "internal/linux_synth.h"

#include "internal/globals.h"
#include "internal/linux_devices.h"
#include "linux_device_filter.h"
#include "../protocol_internal.h"
#include "vk_evdev.h"
#include "linux_key_bits.h"
#include "linux_wheel.h"
#include "linux_output.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KSI_VK_PACKET 0xE7u

/* Relative mouse: keyboard keys + BTN_* + REL_X/Y/WHEEL. */
static atomic_int uinput_fd = -1;
/* Absolute pointer: ABS_X/Y with INPUT_PROP_POINTER for absolute MouseMove. */
static atomic_int uinput_abs_fd = -1;
/* The sequencer owns device mutation; the main thread reads readiness. */
static atomic_bool synth_write_failed;
static atomic_bool synth_lifecycle_busy;
static pthread_mutex_t synth_lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static int32_t wheel_remainder;
static int32_t horizontal_wheel_remainder;

/* The output sequencer owns generic device writes, recovery and held-key state.
 * Startup and shutdown access this state only while that thread is stopped.
 * Key state on the generic keyboard device is the sink's; see linux_forward. */

#define KSI_SYNTH_CLAIM_CAPACITY 1024u

typedef struct synth_claim {
    ksi_synth_owner owner;
    uint8_t keys[KSI_KEY_BITMAP_BYTES];
} synth_claim;

typedef struct synth_holds {
    ksi_forward_view view;
    uint32_t epoch; /* forwarding epoch of the last dead-target sweep */
    size_t used;
    uint16_t holders[KEY_MAX + 1];
    uint8_t held[KSI_KEY_BITMAP_BYTES]; /* keys with at least one holder */
    synth_claim claims[KSI_SYNTH_CLAIM_CAPACITY];
} synth_holds;

/* applied follows written output on the sequencer. enqueued follows admitted
 * output in queue order, so a query sees a Send's result once it is accepted,
 * as it would after a synchronous Win32 SendInput. */
static synth_holds applied = { .view = KSI_FORWARD_APPLIED };
static synth_holds enqueued = { .view = KSI_FORWARD_ENQUEUED };
static pthread_mutex_t enqueued_mutex = PTHREAD_MUTEX_INITIALIZER;

static int resolve_synth_key_code(const ksi_keybdinput *input, int *out_value);
static uint16_t mouse_data_to_xbutton(uint32_t mouse_data);
static int update_generic_key(uint16_t code);
static uint16_t pending_high_surrogate;
static bool synth_pacing_active;

static bool owner_matches(const ksi_synth_owner *owner, const ksi_synth_owner *filter)
{
    return (filter->target == 0u || owner->target == filter->target)
        && (filter->connection_id == 0u || owner->connection_id == filter->connection_id)
        && (filter->hook_type == 0u || owner->hook_type == filter->hook_type)
        && (filter->source_type == 0u || owner->source_type == filter->source_type)
        && (filter->source_code == 0u || owner->source_code == filter->source_code);
}

/* A Modify replacement must not outlive its source's grab. */
static bool owner_is_dead(const ksi_synth_owner *owner, ksi_forward_view view)
{
    return owner != NULL && owner->target != 0u && ksi_linux_forward_failed(owner->target, view);
}

/* A dead owner keeps only its releases, so both views agree whichever side of
 * the source's end admitted the batch. */
static bool keep_release(ksi_input *input)
{
    if (input->type == KSI_INPUT_KEYBOARD)
        return (input->data.keyboard.flags & (KSI_KEY_UP | KSI_KEY_UNICODE)) == KSI_KEY_UP;
    input->data.mouse.flags &= KSI_MOUSE_LEFT_UP | KSI_MOUSE_RIGHT_UP
        | KSI_MOUSE_MIDDLE_UP | KSI_MOUSE_X_UP;
    return input->data.mouse.flags != 0u;
}

static synth_claim *find_claim(synth_holds *holds, const ksi_synth_owner *owner)
{
    for (size_t i = 0u; i < holds->used; i++)
        if (memcmp(&holds->claims[i].owner, owner, sizeof(*owner)) == 0) return &holds->claims[i];
    return NULL;
}

/* Returns whether the key has no holder left. */
static bool remove_holder(synth_holds *holds, uint16_t code)
{
    if (--holds->holders[code] != 0u) return false;
    ksi_set_key_bit(holds->held, code, false);
    return true;
}

static int hold_key(synth_holds *holds, const ksi_synth_owner *owner, uint16_t code)
{
    synth_claim *claim = find_claim(holds, owner);

    if (claim == NULL) {
        if (holds->used == KSI_SYNTH_CLAIM_CAPACITY) {
            errno = ENOSPC;
            return -1;
        }
        claim = &holds->claims[holds->used++];
        memset(claim->keys, 0, sizeof(claim->keys));
        claim->owner = *owner;
    }
    if (!ksi_key_bit(claim->keys, code)) {
        ksi_set_key_bit(claim->keys, code, true);
        if (holds->holders[code]++ == 0u) ksi_set_key_bit(holds->held, code, true);
    }
    return 0;
}

static void drop_key(synth_holds *holds, synth_claim *claim, uint16_t code)
{
    ksi_set_key_bit(claim->keys, code, false);
    (void)remove_holder(holds, code);
    if (!ksi_any_key_bit(claim->keys)) *claim = holds->claims[--holds->used];
}

/* Ends every hold of code. Iterating backwards keeps swap-removal from
 * skipping a claim. */
static void release_code(synth_holds *holds, uint16_t code)
{
    for (size_t i = holds->used; ksi_key_bit(holds->held, code) && i-- > 0u; )
        if (ksi_key_bit(holds->claims[i].keys, code))
            drop_key(holds, &holds->claims[i], code);
}

/* Records in released each key that no owner holds after the removal. */
static void remove_claim(synth_holds *holds, synth_claim *claim, uint8_t *released)
{
    for (size_t byte = 0u; byte < sizeof(claim->keys); byte++) {
        for (unsigned int bits = claim->keys[byte]; bits != 0u; bits &= bits - 1u) {
            uint16_t code = (uint16_t)(byte * 8u + (unsigned int)__builtin_ctz(bits));
            if (remove_holder(holds, code) && released != NULL)
                ksi_set_key_bit(released, code, true);
        }
    }
    *claim = holds->claims[--holds->used];
}

/* A null filter selects claims whose source target has ended. */
static void drop_claims(synth_holds *holds, const ksi_synth_owner *filter, uint8_t *released)
{
    for (size_t i = holds->used; i-- > 0u; ) {
        const ksi_synth_owner *owner = &holds->claims[i].owner;
        if (filter != NULL ? owner_matches(owner, filter) : owner_is_dead(owner, holds->view))
            remove_claim(holds, &holds->claims[i], released);
    }
}

static void sweep_dead_targets(synth_holds *holds, uint8_t *released)
{
    uint32_t epoch = ksi_linux_forward_epoch();

    if (holds->epoch == epoch) return;
    holds->epoch = epoch;
    drop_claims(holds, NULL, released);
}

/* One key transition in queue order, for either view. A press restores a hold
 * synthesis displaced (if restore) or holds the key for its owner; a release ends
 * the owner's hold, or else, as a Win32 key-up does, the key everywhere. */
static int apply_key(synth_holds *holds, uint16_t code, bool down, bool restore,
    const ksi_synth_owner *owner)
{
    static const ksi_synth_owner anonymous;
    synth_claim *claim;

    if (owner == NULL) owner = &anonymous;
    if (down)
        return restore && ksi_linux_forward_restore_key(code, holds->view) ? 0 : hold_key(holds, owner, code);

    claim = find_claim(holds, owner);
    if (claim != NULL && ksi_key_bit(claim->keys, code)) {
        drop_key(holds, claim, code);
        return 0;
    }
    ksi_linux_forward_release_key(code, holds->view);
    release_code(holds, code);
    return 0;
}

typedef struct button_transition {
    uint16_t button;
    bool down;
} button_transition;

static bool moves_absolutely(const ksi_mouseinput *input)
{
    return (input->flags & (KSI_MOUSE_MOVE | KSI_MOUSE_ABSOLUTE)) == (KSI_MOUSE_MOVE | KSI_MOUSE_ABSOLUTE);
}

/* Zero names an unsupported X button. */
static size_t button_transitions(const ksi_mouseinput *input, button_transition out[8])
{
    static const struct { uint32_t flag; uint16_t button; bool down; } buttons[] = {
        { KSI_MOUSE_LEFT_DOWN, BTN_LEFT, true }, { KSI_MOUSE_LEFT_UP, BTN_LEFT, false },
        { KSI_MOUSE_RIGHT_DOWN, BTN_RIGHT, true }, { KSI_MOUSE_RIGHT_UP, BTN_RIGHT, false },
        { KSI_MOUSE_MIDDLE_DOWN, BTN_MIDDLE, true }, { KSI_MOUSE_MIDDLE_UP, BTN_MIDDLE, false },
        { KSI_MOUSE_X_DOWN, 0u, true }, { KSI_MOUSE_X_UP, 0u, false },
    };
    size_t count = 0u;

    for (size_t i = 0u; i < sizeof(buttons) / sizeof(buttons[0]); i++)
        if ((input->flags & buttons[i].flag) != 0u)
            out[count++] = (button_transition){ buttons[i].button != 0u
                ? buttons[i].button : mouse_data_to_xbutton(input->mouse_data), buttons[i].down };
    return count;
}

static uint64_t synth_hook_time_ms(uint32_t input_time)
{
    return input_time != 0u ? (uint64_t)input_time : ksi_linux_monotonic_ms();
}

static uint32_t keyboard_indicator_flags_for_hook(void)
{
    bool caps_lock = false;
    bool num_lock = false;
    bool scroll_lock = false;
    uint32_t flags = 0;

    ksi_linux_devices_get_indicator_state(&caps_lock, &num_lock, &scroll_lock);

    if (caps_lock) {
        flags |= KSI_KEYBOARD_HOOK_CAPS_LOCK_ON;
    }

    if (num_lock) {
        flags |= KSI_KEYBOARD_HOOK_NUM_LOCK_ON;
    }

    if (scroll_lock) {
        flags |= KSI_KEYBOARD_HOOK_SCROLL_LOCK_ON;
    }

    return flags;
}

/* After a failure only hold bookkeeping continues, so both key-state views
 * stay in step until recovery rebuilds the devices. */
static int emit_event_to(int fd, uint16_t type, uint16_t code, int32_t value)
{
    const struct input_event event = { .type = type, .code = code, .value = value };
    int result = synth_write_failed ? -1 : ksi_linux_output_write(fd, &event, 1u);
    if (result != 0) synth_write_failed = true;
    else if (synth_pacing_active) ksi_linux_output_pace(1u);
    return result;
}

static int emit_event(uint16_t type, uint16_t code, int32_t value)
{
    return emit_event_to(uinput_fd, type, code, value);
}

static int emit_abs_event(uint16_t code, int32_t value)
{
    return emit_event_to(uinput_abs_fd, EV_ABS, code, value);
}

static int emit_abs_sync(void)
{
    return emit_event_to(uinput_abs_fd, EV_SYN, SYN_REPORT, 0);
}

static int emit_sync(void)
{
    return emit_event(EV_SYN, SYN_REPORT, 0);
}

/* Returns the number of events written, or -1. */
static int paced(int written)
{
    if (written > 0 && synth_pacing_active) ksi_linux_output_pace((size_t)written);
    return written;
}

static int sink_key(uint16_t code, bool held)
{
    return paced(ksi_linux_forward_sink_key(code, held));
}

/* A keystroke that leaves every hold as it was. */
static int tap_sink_key(uint16_t code)
{
    return paced(ksi_linux_forward_sink_tap(code));
}

static int send_key_code(int key_code, int value, const ksi_synth_owner *owner)
{
    uint16_t code = ksi_canonical_button((uint16_t)key_code);

    return apply_key(&applied, code, value != 0, true, owner) == 0 && update_generic_key(code) >= 0 ? 0 : -1;
}

void ksi_linux_synth_add_logical_key_state(uint8_t *keys, size_t key_bytes)
{
    pthread_mutex_lock(&enqueued_mutex);
    sweep_dead_targets(&enqueued, NULL);
    for (size_t i = 0u; i < key_bytes && i < sizeof(enqueued.held); i++)
        keys[i] |= enqueued.held[i];
    pthread_mutex_unlock(&enqueued_mutex);
}

/* Mirrors a batch accepted into the output queue, under the queue lock so the
 * mirror follows queue order. Unicode sequences leave nothing held. */
void ksi_linux_synth_note_enqueued_synth(
    const ksi_input *inputs, size_t count, const ksi_synth_owner *owner)
{
    if (inputs == NULL) return;

    pthread_mutex_lock(&enqueued_mutex);
    sweep_dead_targets(&enqueued, NULL);
    bool dead = owner_is_dead(owner, KSI_FORWARD_ENQUEUED);
    bool moved_absolutely = false;
    for (size_t i = 0u; i < count; i++) {
        ksi_input input = inputs[i];
        int value;
        int key_code;

        if (dead && !keep_release(&input)) continue;
        if (input.type == KSI_INPUT_MOUSE) {
            button_transition buttons[8];
            size_t buttons_count = button_transitions(&input.data.mouse, buttons);
            moved_absolutely |= moves_absolutely(&input.data.mouse);
            for (size_t b = 0u; b < buttons_count; b++)
                if (buttons[b].button != 0u)
                    (void)apply_key(&enqueued, buttons[b].button, buttons[b].down, !moved_absolutely, owner);
            continue;
        }

        key_code = input.type == KSI_INPUT_KEYBOARD
            ? resolve_synth_key_code(&input.data.keyboard, &value) : -1;
        if (key_code >= 0 && key_code <= KEY_MAX)
            (void)apply_key(&enqueued, ksi_canonical_button((uint16_t)key_code), value != 0, true, owner);
    }
    pthread_mutex_unlock(&enqueued_mutex);
}

void ksi_linux_synth_reset_enqueued_synth(void)
{
    pthread_mutex_lock(&enqueued_mutex);
    enqueued.used = 0u;
    memset(enqueued.holders, 0, sizeof(enqueued.holders));
    memset(enqueued.held, 0, sizeof(enqueued.held));
    pthread_mutex_unlock(&enqueued_mutex);
}

static int hex_digit_to_key(char digit)
{
    if (digit >= '0' && digit <= '9') {
        return digit == '0' ? KEY_0 : KEY_1 + (digit - '1');
    }

    if (digit >= 'a' && digit <= 'f') {
        switch (digit) {
            case 'a':
                return KEY_A;
            case 'b':
                return KEY_B;
            case 'c':
                return KEY_C;
            case 'd':
                return KEY_D;
            case 'e':
                return KEY_E;
            case 'f':
                return KEY_F;
        }
    }

    if (digit >= 'A' && digit <= 'F') {
        switch (digit) {
            case 'A':
                return KEY_A;
            case 'B':
                return KEY_B;
            case 'C':
                return KEY_C;
            case 'D':
                return KEY_D;
            case 'E':
                return KEY_E;
            case 'F':
                return KEY_F;
        }
    }

    return -1;
}

/* The Ctrl+Shift+U entry sequence is transient: the sink writes a modifier
 * only if no one holds it, and each returns to what synthesis's owners hold. */
static int send_unicode_input(uint32_t codepoint)
{
    char hex[9];
    int length;

    if (codepoint == 0 || codepoint > 0x10FFFFu) {
        fprintf(stderr, "keysharp-input: unsupported unicode codepoint U+%x\n", codepoint);
        return -1;
    }

    length = snprintf(hex, sizeof(hex), codepoint <= 0xFFFFu ? "%04x" : "%x", codepoint);

    if (length <= 0 || length >= (int)sizeof(hex)) {
        fprintf(stderr, "keysharp-input: failed to format unicode codepoint U+%x\n", codepoint);
        return -1;
    }

    bool failed = sink_key(KEY_LEFTCTRL, true) < 0 || sink_key(KEY_LEFTSHIFT, true) < 0
        || tap_sink_key(KEY_U) < 0;

    failed |= update_generic_key(KEY_LEFTSHIFT) < 0;
    failed |= update_generic_key(KEY_LEFTCTRL) < 0;

    if (failed) {
        fprintf(stderr, "keysharp-input: failed to start unicode input sequence U+%x: %s\n", codepoint, strerror(errno));
        return -1;
    }

    for (int i = 0; i < length; i++) {
        int key_code = hex_digit_to_key(hex[i]);

        if (key_code < 0 || tap_sink_key((uint16_t)key_code) < 0) {
            fprintf(stderr, "keysharp-input: failed to emit unicode hex digit '%c' for U+%x: %s\n", hex[i], codepoint, strerror(errno));
            return -1;
        }
    }

    if (tap_sink_key(KEY_SPACE) < 0) {
        fprintf(stderr, "keysharp-input: failed to commit unicode input U+%x: %s\n", codepoint, strerror(errno));
        return -1;
    }

    if (g_verbose) printf("keysharp-input: synth unicode U+%x via ctrl+shift+u\n", codepoint);
    return 0;
}

static int send_unicode_utf16_unit(uint16_t unit)
{
    if (unit >= 0xD800u && unit <= 0xDBFFu) {
        pending_high_surrogate = unit;
        return 0;
    }

    if (unit >= 0xDC00u && unit <= 0xDFFFu) {
        uint16_t high = pending_high_surrogate;
        uint32_t codepoint;

        pending_high_surrogate = 0;

        if (high < 0xD800u || high > 0xDBFFu) {
            fprintf(stderr, "keysharp-input: low unicode surrogate 0x%x without preceding high surrogate\n", unit);
            return -1;
        }

        codepoint = 0x10000u + ((((uint32_t)high - 0xD800u) << 10) | ((uint32_t)unit - 0xDC00u));
        return send_unicode_input(codepoint);
    }

    pending_high_surrogate = 0;
    return send_unicode_input(unit);
}

static int enable_event(int event_type)
{
    if (ioctl(uinput_fd, UI_SET_EVBIT, event_type) < 0) {
        fprintf(stderr, "keysharp-input: uinput UI_SET_EVBIT(%d) failed: %s\n", event_type, strerror(errno));
        return -1;
    }

    return 0;
}

static int enable_key(int key_code)
{
    if (ioctl(uinput_fd, UI_SET_KEYBIT, key_code) < 0) {
        fprintf(stderr, "keysharp-input: uinput UI_SET_KEYBIT(%d) failed: %s\n", key_code, strerror(errno));
        return -1;
    }

    return 0;
}

static int enable_relative(int relative_code)
{
    if (ioctl(uinput_fd, UI_SET_RELBIT, relative_code) < 0) {
        fprintf(stderr, "keysharp-input: uinput UI_SET_RELBIT(%d) failed: %s\n", relative_code, strerror(errno));
        return -1;
    }

    return 0;
}

static int vk_to_evdev_key(uint16_t vk)
{
    return ksi_vk_to_evdev(vk);
}

static int scan_to_evdev_key(uint16_t scan, bool extended)
{
    if (scan == 0) {
        return -1;
    }

    if (extended) {
        /* Map Windows AT set-1 E0-prefixed scan codes to evdev keycodes.
         * These differ from the base (non-extended) numbering used by Linux. */
        switch (scan) {
            case 0x1Cu: return KEY_KPENTER;
            case 0x1Du: return KEY_RIGHTCTRL;
            case 0x35u: return KEY_KPSLASH;
            case 0x37u: return KEY_SYSRQ;
            case 0x38u: return KEY_RIGHTALT;
            case 0x47u: return KEY_HOME;
            case 0x48u: return KEY_UP;
            case 0x49u: return KEY_PAGEUP;
            case 0x4Bu: return KEY_LEFT;
            case 0x4Du: return KEY_RIGHT;
            case 0x4Fu: return KEY_END;
            case 0x50u: return KEY_DOWN;
            case 0x51u: return KEY_PAGEDOWN;
            case 0x52u: return KEY_INSERT;
            case 0x53u: return KEY_DELETE;
            case 0x5Bu: return KEY_LEFTMETA;
            case 0x5Cu: return KEY_RIGHTMETA;
            case 0x5Du: return KEY_COMPOSE;
            default: return -1;
        }
    }

    /* Non-extended PS/2 AT scan codes share Linux evdev numbering. */
    if (scan <= KEY_MAX) {
        return scan;
    }

    return -1;
}

static int enable_keyboard_keys(void)
{
    /* Scan-code synthesis supports keyboard keys without Windows VK mappings.
     * Exclude other device classes' buttons from this capability set. */
    for (int key = KEY_RESERVED + 1; key <= KEY_MAX; key++) {
        if (ksi_linux_key_code_is_keyboard((unsigned int)key)
            && enable_key(key) != 0) {
            return -1;
        }
    }

    return 0;
}

static int configure_uinput_device(void)
{
    struct uinput_setup setup;

    /* No EV_REP: synthesis emits only the transitions it is asked for. As the sink,
     * the device also carries grabbed keyboards' scan codes and the lock LEDs the
     * desktop drives, which the reader relays to those keyboards. */
    if (enable_event(EV_KEY) != 0
        || enable_event(EV_REL) != 0
        || enable_event(EV_MSC) != 0
        || enable_event(EV_LED) != 0
        || ioctl(uinput_fd, UI_SET_MSCBIT, MSC_SCAN) < 0) {
        return -1;
    }

    for (int led = LED_NUML; led <= LED_KANA; led++) {
        if (ioctl(uinput_fd, UI_SET_LEDBIT, led) < 0) {
            fprintf(stderr, "keysharp-input: uinput UI_SET_LEDBIT(%d) failed: %s\n", led, strerror(errno));
            return -1;
        }
    }

    if (enable_keyboard_keys() != 0) {
        return -1;
    }

    if (enable_key(BTN_LEFT) != 0
        || enable_key(BTN_RIGHT) != 0
        || enable_key(BTN_MIDDLE) != 0
        || enable_key(BTN_SIDE) != 0
        || enable_key(BTN_EXTRA) != 0) {
        return -1;
    }

    if (enable_relative(REL_X) != 0
        || enable_relative(REL_Y) != 0
        || enable_relative(REL_WHEEL) != 0
        || enable_relative(REL_HWHEEL) != 0
        || enable_relative(REL_WHEEL_HI_RES) != 0
        || enable_relative(REL_HWHEEL_HI_RES) != 0) {
        return -1;
    }

    memset(&setup, 0, sizeof(setup));
    (void)snprintf(setup.name, sizeof(setup.name), "%s", KSI_SYNTH_DEVICE_NAME);
    setup.id.bustype = KSI_SYNTH_DEVICE_BUSTYPE;
    setup.id.vendor = KSI_SYNTH_DEVICE_VENDOR;
    setup.id.product = KSI_SYNTH_DEVICE_PRODUCT;
    setup.id.version = KSI_SYNTH_DEVICE_VERSION;

    if (ioctl(uinput_fd, UI_DEV_SETUP, &setup) < 0) {
        fprintf(stderr, "keysharp-input: uinput UI_DEV_SETUP failed: %s\n", strerror(errno));
        return -1;
    }

    if (ioctl(uinput_fd, UI_DEV_CREATE) < 0) {
        fprintf(stderr, "keysharp-input: uinput UI_DEV_CREATE failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int configure_abs_uinput_device(void)
{
    struct uinput_setup setup;
    struct uinput_abs_setup abs_setup;

    /* INPUT_PROP_POINTER: tells libinput this is an absolute pointer device
     * (like a drawing tablet in mouse mode), not a touchscreen or trackpad.
     * The compositor maps the ABS range [0, 65535] directly to screen area. */
    if (ioctl(uinput_abs_fd, UI_SET_PROPBIT, INPUT_PROP_POINTER) < 0) {
        fprintf(stderr, "keysharp-input: UI_SET_PROPBIT(INPUT_PROP_POINTER) failed: %s\n", strerror(errno));
        /* Non-fatal: proceed without the property; the device may still work
         * under xf86-input-evdev even if libinput classifies it differently. */
    }

    if (ioctl(uinput_abs_fd, UI_SET_EVBIT, EV_ABS) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_SET_EVBIT(EV_ABS) failed: %s\n", strerror(errno));
        return -1;
    }

    if (ioctl(uinput_abs_fd, UI_SET_EVBIT, EV_KEY) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_SET_EVBIT(EV_KEY) failed: %s\n", strerror(errno));
        return -1;
    }

    /* Buttons live on the absolute device too so button+absolute-move events
     * arrive from a single device and can be correctly ordered. The full set
     * (including the side/extra X-buttons) is enabled so any button routed here
     * after an absolute move is actually emitted rather than silently dropped
     * for lack of a keybit. */
    if (ioctl(uinput_abs_fd, UI_SET_KEYBIT, BTN_LEFT) < 0
        || ioctl(uinput_abs_fd, UI_SET_KEYBIT, BTN_RIGHT) < 0
        || ioctl(uinput_abs_fd, UI_SET_KEYBIT, BTN_MIDDLE) < 0
        || ioctl(uinput_abs_fd, UI_SET_KEYBIT, BTN_SIDE) < 0
        || ioctl(uinput_abs_fd, UI_SET_KEYBIT, BTN_EXTRA) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_SET_KEYBIT failed: %s\n", strerror(errno));
        return -1;
    }

    if (ioctl(uinput_abs_fd, UI_SET_ABSBIT, ABS_X) < 0
        || ioctl(uinput_abs_fd, UI_SET_ABSBIT, ABS_Y) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_SET_ABSBIT failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&setup, 0, sizeof(setup));
    (void)snprintf(setup.name, sizeof(setup.name), "%s", KSI_SYNTH_ABS_DEVICE_NAME);
    setup.id.bustype = KSI_SYNTH_DEVICE_BUSTYPE;
    setup.id.vendor  = KSI_SYNTH_DEVICE_VENDOR;
    setup.id.product = KSI_SYNTH_ABS_DEVICE_PRODUCT;
    setup.id.version = KSI_SYNTH_DEVICE_VERSION;

    if (ioctl(uinput_abs_fd, UI_DEV_SETUP, &setup) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_DEV_SETUP failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&abs_setup, 0, sizeof(abs_setup));
    abs_setup.absinfo.minimum = 0;
    abs_setup.absinfo.maximum = 65535;
    abs_setup.absinfo.resolution = 1;

    abs_setup.code = ABS_X;
    if (ioctl(uinput_abs_fd, UI_ABS_SETUP, &abs_setup) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_ABS_SETUP(ABS_X) failed: %s\n", strerror(errno));
        return -1;
    }

    abs_setup.code = ABS_Y;
    if (ioctl(uinput_abs_fd, UI_ABS_SETUP, &abs_setup) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_ABS_SETUP(ABS_Y) failed: %s\n", strerror(errno));
        return -1;
    }

    if (ioctl(uinput_abs_fd, UI_DEV_CREATE) < 0) {
        fprintf(stderr, "keysharp-input: abs device UI_DEV_CREATE failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int start_synth_devices(void)
{
    uinput_fd = open(KSI_UINPUT_PATH, O_WRONLY | O_NONBLOCK | O_CLOEXEC);

    if (uinput_fd < 0) {
        fprintf(stderr, "keysharp-input: cannot open %s: %s\n", KSI_UINPUT_PATH, strerror(errno));
        return 0;
    }

    if (configure_uinput_device() != 0) {
        close(uinput_fd);
        uinput_fd = -1;
        return 0;
    }

    ksi_linux_forward_attach_sink(uinput_fd);
    puts("keysharp-input: uinput relative mouse device created");

    uinput_abs_fd = open(KSI_UINPUT_PATH, O_WRONLY | O_NONBLOCK | O_CLOEXEC);

    if (uinput_abs_fd < 0) {
        fprintf(stderr, "keysharp-input: cannot open %s for abs device: %s\n", KSI_UINPUT_PATH, strerror(errno));
        /* Non-fatal: absolute mouse moves won't work but everything else will. */
        return 0;
    }

    if (configure_abs_uinput_device() != 0) {
        close(uinput_abs_fd);
        uinput_abs_fd = -1;
        fprintf(stderr, "keysharp-input: failed to create absolute pointer device\n");
        return 0;
    }

    puts("keysharp-input: uinput absolute pointer device created");
    return 0;
}

int ksi_linux_synth_start(void)
{
    pthread_mutex_lock(&synth_lifecycle_mutex);
    synth_lifecycle_busy = true;
    int result = uinput_fd >= 0 ? 0 : start_synth_devices();
    synth_lifecycle_busy = false;
    pthread_mutex_unlock(&synth_lifecycle_mutex);
    return result;
}

static void stop_synth_devices(void)
{
    ksi_linux_synth_release_all();
    ksi_linux_forward_attach_sink(-1);
    wheel_remainder = horizontal_wheel_remainder = 0;

    if (uinput_fd >= 0) {
        (void)ioctl(uinput_fd, UI_DEV_DESTROY);
        close(uinput_fd);
        uinput_fd = -1;
        puts("keysharp-input: uinput relative mouse device destroyed");
    }

    if (uinput_abs_fd >= 0) {
        (void)ioctl(uinput_abs_fd, UI_DEV_DESTROY);
        close(uinput_abs_fd);
        uinput_abs_fd = -1;
        puts("keysharp-input: uinput absolute pointer device destroyed");
    }
}

void ksi_linux_synth_stop(void)
{
    pthread_mutex_lock(&synth_lifecycle_mutex);
    synth_lifecycle_busy = true;
    stop_synth_devices();
    synth_lifecycle_busy = false;
    pthread_mutex_unlock(&synth_lifecycle_mutex);
}

bool ksi_linux_synth_is_started(void)
{
    return uinput_fd >= 0;
}

/* The sink latches its own write failures, whoever wrote. */
static bool synth_failed(void)
{
    return synth_write_failed || (uinput_fd >= 0 && !ksi_linux_forward_sink_ready());
}

bool ksi_linux_synth_is_available(void)
{
    return !synth_lifecycle_busy && ksi_linux_synth_is_started() && !synth_failed();
}

bool ksi_linux_synth_absolute_is_available(void)
{
    return !synth_lifecycle_busy && uinput_abs_fd >= 0 && !synth_write_failed;
}

/* Recreating the devices is real ioctl work, so a persistent failure is
 * retried at this interval rather than on every main-loop pass. */
#define KSI_SYNTH_RETRY_INTERVAL_MS 3000u
static uint64_t last_synth_retry_ms;

/* Main thread. The daemon answers true by queueing RECREATE_SYNTH, because
 * only the sequencer may stop and restart the devices it writes. */
bool ksi_linux_synth_needs_recovery(void)
{
    uint64_t now;

    if (synth_lifecycle_busy || !synth_failed()) {
        return false;
    }

    now = ksi_linux_monotonic_ms();

    if (now != 0 && last_synth_retry_ms != 0
        && now - last_synth_retry_ms < KSI_SYNTH_RETRY_INTERVAL_MS) {
        return false;
    }

    last_synth_retry_ms = now;
    return true;
}

/* A failed reopen re-latches the failure so the next recovery poll retries. */
void ksi_linux_synth_recreate(void)
{
    pthread_mutex_lock(&synth_lifecycle_mutex);
    synth_lifecycle_busy = true;
    fprintf(stderr, "keysharp-input: synthetic output device write failed; recreating uinput devices\n");
    stop_synth_devices();
    synth_write_failed = false;
    (void)start_synth_devices();
    if (uinput_fd < 0) synth_write_failed = true;
    synth_lifecycle_busy = false;
    pthread_mutex_unlock(&synth_lifecycle_mutex);
}

/* Resolve a keyboard synth input to the evdev key code it toggles and its
 * up/down value (*out_value: 1 = down, 0 = up). Returns -1 for inputs that do
 * not map to a single persistent key transition — unicode units (emitted as a
 * self-contained sequence that leaves nothing held) and unsupported vk/scan.
 * Shared by the drain path (send_keyboard_input) and the enqueue-time logical
 * tracker (ksi_linux_synth_note_enqueued_synth) so both agree on exactly which
 * key each input toggles. */
static int resolve_synth_key_code(const ksi_keybdinput *input, int *out_value)
{
    int key_code = -1;

    if (out_value != NULL) {
        *out_value = (input->flags & KSI_KEY_UP) != 0 ? 0 : 1;
    }

    if ((input->flags & KSI_KEY_UNICODE) != 0) {
        return -1;
    }

    if ((input->flags & KSI_KEY_SCANCODE) != 0) {
        bool extended = (input->flags & KSI_KEY_EXTENDED) != 0;
        key_code = scan_to_evdev_key(input->scan, extended);
    }

    if (key_code < 0
        && input->vk == 0x0Du
        && (input->flags & KSI_KEY_EXTENDED) != 0) {
        key_code = KEY_KPENTER;
    }

    if (key_code < 0) {
        key_code = vk_to_evdev_key(input->vk);
    }

    return key_code;
}

static bool keyboard_input_to_hook_event(
    const ksi_keybdinput *input,
    ksi_keyboard_hook_event *event)
{
    bool key_up;
    uint32_t flags;

    if (input == NULL || event == NULL) {
        return false;
    }

    memset(event, 0, sizeof(*event));
    key_up = (input->flags & KSI_KEY_UP) != 0;
    flags = KSI_KEYBOARD_HOOK_INJECTED | keyboard_indicator_flags_for_hook();

    if (key_up) {
        flags |= KSI_KEYBOARD_HOOK_UP;
    }

    if ((input->flags & KSI_KEY_EXTENDED) != 0) {
        flags |= KSI_KEYBOARD_HOOK_EXTENDED;
    }

    event->message = key_up ? KSI_MESSAGE_KEY_UP : KSI_MESSAGE_KEY_DOWN;
    event->flags = flags;
    event->time_ms = synth_hook_time_ms(input->time);
    event->extra_info = input->extra_info;

    if ((input->flags & KSI_KEY_UNICODE) != 0) {
        event->vk_code = KSI_VK_PACKET;
        event->scan_code = input->scan;
        return true;
    }

    {
        int value;
        int key_code = resolve_synth_key_code(input, &value);

        (void)value;

        if (key_code >= 0) {
            event->scan_code = (uint32_t)key_code;
            event->vk_code = ksi_evdev_to_vk((unsigned int)key_code);
        }
    }

    if (event->vk_code == 0u) {
        event->vk_code = input->vk;
    }

    if (event->scan_code == 0u) {
        event->scan_code = input->scan;
    }

    return event->vk_code != 0u || event->scan_code != 0u;
}

static bool mouse_input_to_hook_event(
    const ksi_mouseinput *input,
    ksi_mouse_hook_event *event)
{
    if (input == NULL || event == NULL) {
        return false;
    }

    memset(event, 0, sizeof(*event));
    event->flags = KSI_MOUSE_HOOK_INJECTED;
    event->time_ms = synth_hook_time_ms(input->time);
    event->extra_info = input->extra_info;

    if ((input->flags & KSI_MOUSE_MOVE) != 0) {
        event->message = KSI_MESSAGE_MOUSE_MOVE;
        event->x = input->dx;
        event->y = input->dy;

        if ((input->flags & KSI_MOUSE_ABSOLUTE) != 0) {
            event->mouse_data = KSI_MOUSE_ABSOLUTE;
        } else {
            event->delta_x = input->dx;
            event->delta_y = input->dy;
        }

        return true;
    }

    if ((input->flags & KSI_MOUSE_WHEEL) != 0) {
        event->message = KSI_MESSAGE_MOUSE_WHEEL;
        event->mouse_data = input->mouse_data << 16;
        return true;
    }

    if ((input->flags & KSI_MOUSE_HORIZONTAL_WHEEL) != 0) {
        event->message = KSI_MESSAGE_MOUSE_HORIZONTAL_WHEEL;
        event->mouse_data = input->mouse_data << 16;
        return true;
    }

    if ((input->flags & KSI_MOUSE_LEFT_DOWN) != 0) {
        event->message = KSI_MESSAGE_LEFT_BUTTON_DOWN;
        return true;
    }

    if ((input->flags & KSI_MOUSE_LEFT_UP) != 0) {
        event->message = KSI_MESSAGE_LEFT_BUTTON_UP;
        return true;
    }

    if ((input->flags & KSI_MOUSE_RIGHT_DOWN) != 0) {
        event->message = KSI_MESSAGE_RIGHT_BUTTON_DOWN;
        return true;
    }

    if ((input->flags & KSI_MOUSE_RIGHT_UP) != 0) {
        event->message = KSI_MESSAGE_RIGHT_BUTTON_UP;
        return true;
    }

    if ((input->flags & KSI_MOUSE_MIDDLE_DOWN) != 0) {
        event->message = KSI_MESSAGE_MIDDLE_BUTTON_DOWN;
        return true;
    }

    if ((input->flags & KSI_MOUSE_MIDDLE_UP) != 0) {
        event->message = KSI_MESSAGE_MIDDLE_BUTTON_UP;
        return true;
    }

    if ((input->flags & KSI_MOUSE_X_DOWN) != 0) {
        event->message = KSI_MESSAGE_X_BUTTON_DOWN;
        event->mouse_data = input->mouse_data;
        return true;
    }

    if ((input->flags & KSI_MOUSE_X_UP) != 0) {
        event->message = KSI_MESSAGE_X_BUTTON_UP;
        event->mouse_data = input->mouse_data;
        return true;
    }

    return false;
}

bool ksi_linux_synth_input_to_hook_event(
    const ksi_input *input,
    uint32_t *hook_type,
    ksi_hook_event_payload *event,
    size_t *event_size)
{
    if (input == NULL || hook_type == NULL || event == NULL || event_size == NULL) {
        return false;
    }

    memset(event, 0, sizeof(*event));

    if (input->type == KSI_INPUT_KEYBOARD) {
        if (!keyboard_input_to_hook_event(&input->data.keyboard, &event->event.keyboard)) {
            return false;
        }

        *hook_type = KSI_HOOK_KEYBOARD;
        event->hook_type = *hook_type;
        *event_size = sizeof(event->event.keyboard);
        return true;
    }

    if (input->type == KSI_INPUT_MOUSE) {
        if (!mouse_input_to_hook_event(&input->data.mouse, &event->event.mouse)) {
            return false;
        }

        *hook_type = KSI_HOOK_MOUSE;
        event->hook_type = *hook_type;
        *event_size = sizeof(event->event.mouse);
        return true;
    }

    return false;
}

static int send_keyboard_input(
    const ksi_keybdinput *input, const ksi_synth_owner *owner)
{
    int key_code;
    int value;

    if ((input->flags & KSI_KEY_UNICODE) != 0) {
        if ((input->flags & KSI_KEY_UP) != 0) {
            return 0;
        }

        return send_unicode_utf16_unit(input->scan);
    }

    key_code = resolve_synth_key_code(input, &value);

    if (key_code < 0) {
        fprintf(stderr, "keysharp-input: unsupported keyboard input vk=0x%x scan=%u flags=0x%x\n",
            input->vk,
            input->scan,
            input->flags);
        return -1;
    }

    /* SendInput/keybd_event semantics are explicit transitions only. Do not
     * emit EV_KEY value 2: that marks autorepeat from a held physical key. */
    if (send_key_code(key_code, value, owner) != 0) {
        fprintf(stderr, "keysharp-input: failed to emit keyboard input: %s\n", strerror(errno));
        return -1;
    }

    if (g_verbose) {
        printf("keysharp-input: synth key vk=0x%x scan=%u evdev=%d %s\n",
            input->vk,
            input->scan,
            key_code,
            value == 0 ? "up" : "down");
    }

    return 0;
}

static uint16_t mouse_data_to_xbutton(uint32_t mouse_data)
{
    uint32_t xbutton = mouse_data >> 16;

    if (xbutton == KSI_XBUTTON1) {
        return BTN_SIDE;
    }

    if (xbutton == KSI_XBUTTON2) {
        return BTN_EXTRA;
    }

    return 0;
}

/* Which device holds each pressed button, indexed by (button - BTN_LEFT), so a
 * release goes where its press went even across batches: a `Click x,y Down` on
 * the absolute device then a move-less `Click Up` cannot strand the button. */
#define KSI_TRACKED_BTN_BASE BTN_LEFT
#define KSI_TRACKED_BTN_COUNT 8
static bool button_held_on_abs[KSI_TRACKED_BTN_COUNT];

static bool *tracked_button_slot(uint16_t btn)
{
    int idx = (int)btn - KSI_TRACKED_BTN_BASE;

    if (idx < 0 || idx >= KSI_TRACKED_BTN_COUNT) {
        return NULL;
    }

    return &button_held_on_abs[idx];
}

/* Brings the generic devices in line with synthesis's holds of code. A button
 * pressed on the absolute device is released there; every other hold is the
 * sink's. Returns the number of sink events written, or -1. */
static int update_generic_key(uint16_t code)
{
    bool *slot = tracked_button_slot(code);
    bool held = applied.holders[code] != 0u;

    if (slot == NULL || !*slot) return sink_key(code, held);
    if (held) return 0;
    *slot = false;
    /* A recreated device starts with nothing held. */
    if (uinput_abs_fd < 0) return 0;
    return emit_event_to(uinput_abs_fd, EV_KEY, code, 0) == 0 && emit_abs_sync() == 0 ? 0 : -1;
}

static void release_unheld(const uint8_t *released)
{
    for (size_t byte = 0u; byte < KSI_KEY_BITMAP_BYTES; byte++)
        for (unsigned int bits = released[byte] & (uint8_t)~applied.held[byte]; bits != 0u; bits &= bits - 1u)
            (void)update_generic_key((uint16_t)(byte * 8u + (unsigned int)__builtin_ctz(bits)));
}

void ksi_linux_synth_maintain_output(void)
{
    uint8_t released[KSI_KEY_BITMAP_BYTES] = {0};

    ksi_linux_forward_collect(false);
    if (applied.epoch == ksi_linux_forward_epoch()) return;
    sweep_dead_targets(&applied, released);
    release_unheld(released);
}

void ksi_linux_synth_release_owner(const ksi_synth_owner *filter, ksi_forward_view view)
{
    uint8_t released[KSI_KEY_BITMAP_BYTES] = {0};

    if (filter == NULL) return;
    if (view == KSI_FORWARD_ENQUEUED) pthread_mutex_lock(&enqueued_mutex);
    drop_claims(view == KSI_FORWARD_APPLIED ? &applied : &enqueued, filter, released);
    if (view == KSI_FORWARD_ENQUEUED) pthread_mutex_unlock(&enqueued_mutex);
    else release_unheld(released);
}

void ksi_linux_synth_physical_release(const ksi_forward_packet *packet, ksi_forward_view view)
{
    synth_holds *holds = view == KSI_FORWARD_APPLIED ? &applied : &enqueued;
    uint8_t released[KSI_KEY_BITMAP_BYTES] = {0};

    if ((ksi_forward_key_values(packet) & KSI_FORWARD_KEY_UP) == 0u) return;

    if (view == KSI_FORWARD_ENQUEUED) pthread_mutex_lock(&enqueued_mutex);
    for (uint32_t i = 0u; i < packet->count && i < KSI_FORWARD_PACKET_EVENTS; i++) {
        uint16_t code = packet->events[i].code;
        const ksi_synth_owner derived = { .target = packet->target,
            .source_type = EV_KEY, .source_code = code };

        if (packet->events[i].type != EV_KEY || packet->events[i].value != 0 || code > KEY_MAX)
            continue;
        if (packet->target != 0u) drop_claims(holds, &derived, released);
        if ((packet->flags & KSI_FORWARD_SUPPRESSED) != 0u) continue;
        code = ksi_canonical_button(code);
        if (ksi_key_bit(holds->held, code)) ksi_set_key_bit(released, code, true);
        release_code(holds, code);
    }
    if (view == KSI_FORWARD_ENQUEUED) pthread_mutex_unlock(&enqueued_mutex);
    else release_unheld(released);
}

void ksi_linux_synth_release_all(void)
{
    applied.used = 0u;
    memset(applied.holders, 0, sizeof(applied.holders));
    memset(applied.held, 0, sizeof(applied.held));
    for (uint16_t i = 0u; i < KSI_TRACKED_BTN_COUNT; i++)
        if (button_held_on_abs[i]) (void)update_generic_key((uint16_t)(KSI_TRACKED_BTN_BASE + i));
    ksi_linux_forward_sink_clear_synth();
}

/* A press after this batch's absolute move goes, with its release, to the
 * absolute device, so the click lands at the move and restores no clone hold.
 * Other buttons are the sink's, whose write also ends this input's motion report. */
static int route_mouse_button(uint16_t btn, bool down, bool moved_absolutely, bool abs_active,
    bool *abs_pending, bool *rel_pending, const ksi_synth_owner *owner)
{
    bool *slot = tracked_button_slot(btn);
    bool was_held = applied.holders[btn] != 0u;
    int written;

    if (apply_key(&applied, btn, down, !moved_absolutely, owner) != 0) return -1;
    if (!was_held && applied.holders[btn] != 0u && abs_active && slot != NULL) {
        *slot = *abs_pending = true;
        return emit_event_to(uinput_abs_fd, EV_KEY, btn, 1);
    }
    written = update_generic_key(btn);
    if (written > 0) *rel_pending = false;
    return written < 0 ? -1 : 0;
}

/* moved_absolutely persists across the batch's inputs, as admission sees it. */
static int send_mouse_input(
    const ksi_mouseinput *input, bool *moved_absolutely,
    const ksi_synth_owner *owner)
{
    bool abs_move_active;
    bool rel_pending = false; /* relative-device events awaiting a SYN */
    bool abs_pending = false; /* absolute-device button events awaiting a SYN */

    *moved_absolutely |= moves_absolutely(input);

    if ((input->flags & KSI_MOUSE_MOVE) != 0) {
        if ((input->flags & KSI_MOUSE_ABSOLUTE) != 0) {
            if (uinput_abs_fd < 0) {
                fprintf(stderr, "keysharp-input: absolute mouse move dropped: abs device unavailable\n");
            } else if (emit_abs_event(ABS_X, input->dx) != 0
                       || emit_abs_event(ABS_Y, input->dy) != 0
                       || emit_abs_sync() != 0) {
                return -1;
            }
        } else {
            if (input->dx != 0 && emit_event(EV_REL, REL_X, input->dx) != 0) {
                return -1;
            }

            if (input->dy != 0 && emit_event(EV_REL, REL_Y, input->dy) != 0) {
                return -1;
            }

            if (input->dx != 0 || input->dy != 0) {
                rel_pending = true;
            }
        }
    }

    if ((input->flags & KSI_MOUSE_WHEEL) != 0) {
        int32_t delta = (int32_t)input->mouse_data;
        int32_t steps = ksi_linux_wheel_steps(delta, &wheel_remainder);

        if (emit_event(EV_REL, REL_WHEEL_HI_RES, delta) != 0
            || (steps != 0 && emit_event(EV_REL, REL_WHEEL, steps) != 0)) {
            return -1;
        }

        rel_pending = true;
    }

    if ((input->flags & KSI_MOUSE_HORIZONTAL_WHEEL) != 0) {
        int32_t delta = (int32_t)input->mouse_data;
        int32_t steps = ksi_linux_wheel_steps(delta, &horizontal_wheel_remainder);

        if (emit_event(EV_REL, REL_HWHEEL_HI_RES, delta) != 0
            || (steps != 0 && emit_event(EV_REL, REL_HWHEEL, steps) != 0)) {
            return -1;
        }

        rel_pending = true;
    }

    abs_move_active = *moved_absolutely && uinput_abs_fd >= 0;

    button_transition buttons[8];
    size_t buttons_count = button_transitions(input, buttons);

    for (size_t i = 0u; i < buttons_count; i++) {
        if (buttons[i].button == 0u
            || route_mouse_button(buttons[i].button, buttons[i].down, *moved_absolutely,
                abs_move_active, &abs_pending, &rel_pending, owner) != 0) {
            return -1;
        }
    }

    /* Commit each device that actually received events with its own SYN. The
     * absolute move above already emitted its own abs SYN. */
    if (rel_pending && emit_sync() != 0) {
        fprintf(stderr, "keysharp-input: failed to emit mouse input: %s\n", strerror(errno));
        return -1;
    }

    if (abs_pending && emit_abs_sync() != 0) {
        fprintf(stderr, "keysharp-input: failed to emit absolute mouse button: %s\n", strerror(errno));
        return -1;
    }

    if (g_verbose) {
        printf("keysharp-input: synth mouse dx=%d dy=%d data=%u flags=0x%x\n",
            input->dx,
            input->dy,
            input->mouse_data,
            input->flags);
    }

    return 0;
}

int ksi_linux_synth_send_input(
    const ksi_input *inputs, size_t count, uint32_t flags,
    const ksi_synth_owner *owner)
{
    int result = 0;

    if (uinput_fd < 0) {
        fprintf(stderr, "keysharp-input: synthesis unavailable; %s could not be opened\n", KSI_UINPUT_PATH);
        return -1;
    }

    /* A top-level batch starts with no pending high surrogate, so an unpaired one
     * cannot join the next batch's low surrogate; a pair may span two fragments,
     * which keep it. */
    if ((flags & KSI_INTERNAL_SYNTH_BATCH_FRAGMENT) == 0u
            || (flags & KSI_INTERNAL_SYNTH_BATCH_START) != 0u) {
        pending_high_surrogate = 0;
    }

    /* Share output pacing with physical forwarding on the sequencer. */
    synth_pacing_active = true;

    /* Buttons after an absolute move go with it; see route_mouse_button. */
    bool moved_absolutely = false;
    int had_error = 0;
    bool dead = owner_is_dead(owner, KSI_FORWARD_APPLIED);

    for (size_t i = 0; i < count; i++) {
        ksi_input input = inputs[i];

        if (dead && !keep_release(&input)) continue;
        if (input.type == KSI_INPUT_KEYBOARD) {
            result = send_keyboard_input(&input.data.keyboard, owner);
        } else if (input.type == KSI_INPUT_MOUSE) {
            result = send_mouse_input(&input.data.mouse, &moved_absolutely, owner);
        } else {
            fprintf(stderr, "keysharp-input: unsupported input type %u\n", input.type);
            result = -1;
        }

        /* An invalid input (unmappable codepoint or vk, lone surrogate) skips
         * only itself, as Win32 SendInput never rejects a single unicode event. */
        had_error |= result != 0;
    }

    synth_pacing_active = false;
    return had_error ? -1 : 0;
}
