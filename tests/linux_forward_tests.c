#include <errno.h>
#include <fcntl.h>
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <linux/uinput.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Pipe-backed outputs exercise routing without creating or grabbing devices. */
struct libevdev_uinput { int fds[2]; };
static struct libevdev_uinput outputs[32];
static char output_paths[32][64];
static size_t output_count;
static size_t destroyed;
static char issued_phys[128];
static bool metadata_ok = true;
static uint8_t source_switches;
static int last_source;
bool g_verbose = false;

/* KEYBOARD is a combined keyboard and pointer; PLAIN has only keyboard keys;
 * HOTKEYS adds a switch and joystick buttons to them. */
enum { MOUSE = 1, KEYBOARD = 2, KEYD = 3, SWITCHES = 4, PLAIN = 5, HOTKEYS = 6 };

static int fake_source(int fd, struct libevdev **out)
{
    struct libevdev *device = libevdev_new();
    if (device == NULL) return -ENOMEM;
    last_source = fd;
    libevdev_set_name(device, fd == MOUSE ? "Physical Mouse" : "Physical Keyboard");
    libevdev_set_phys(device, "usb-port/input0");
    libevdev_set_uniq(device, "source-serial");
    libevdev_set_id_bustype(device, BUS_USB);
    libevdev_set_id_vendor(device, fd == KEYD ? 0x0fac : 0x1234);
    libevdev_set_id_product(device, fd == MOUSE ? 1 : 2);
    libevdev_set_id_version(device, 7);
    (void)libevdev_enable_event_type(device, EV_REP);
    (void)libevdev_enable_event_code(device, EV_KEY, KEY_A, NULL);
    (void)libevdev_enable_event_code(device, EV_KEY, KEY_LEFTSHIFT, NULL);
    (void)libevdev_enable_event_code(device, EV_LED, LED_CAPSL, NULL);
    if (fd == HOTKEYS) {
        (void)libevdev_enable_event_code(device, EV_SW, SW_TABLET_MODE, NULL);
        (void)libevdev_enable_event_code(device, EV_KEY, BTN_SOUTH, NULL);
        (void)libevdev_enable_event_code(device, EV_KEY, BTN_TRIGGER_HAPPY1, NULL);
    }
    if (fd != PLAIN && fd != HOTKEYS) {
        (void)libevdev_enable_property(device, INPUT_PROP_POINTER);
        (void)libevdev_enable_event_code(device, EV_FF, FF_RUMBLE, NULL);
        (void)libevdev_enable_event_code(device, EV_KEY, BTN_BACK, NULL);
        (void)libevdev_enable_event_code(device, EV_REL, REL_X, NULL);
        (void)libevdev_enable_event_code(device, EV_REL, REL_Y, NULL);
        (void)libevdev_enable_event_code(device, EV_REL, REL_WHEEL, NULL);
        (void)libevdev_enable_event_code(device, EV_REL, REL_WHEEL_HI_RES, NULL);
        const struct input_absinfo axis = { .minimum = -100, .maximum = 2000, .resolution = 40 };
        (void)libevdev_enable_event_code(device, EV_ABS, ABS_X, &axis);
    }
    if (fd == SWITCHES) {
        (void)libevdev_enable_event_code(device, EV_SW, SW_TABLET_MODE, NULL);
        (void)libevdev_enable_event_code(device, EV_SW, SW_RFKILL_ALL, NULL);
        (void)libevdev_set_event_value(device, EV_SW, SW_TABLET_MODE, 1);
        (void)libevdev_set_event_value(device, EV_LED, LED_CAPSL, 1);
    }
    *out = device;
    return 0;
}

/* Each uinput handle is a pipe; its write end stands for the device fd. */
static int fake_open(const char *path, int flags, ...)
{
    (void)flags;
    if (strcmp(path, "/dev/uinput") != 0 || output_count == sizeof(outputs) / sizeof(outputs[0])) {
        errno = ENOENT;
        return -1;
    }
    return pipe2(outputs[output_count].fds, O_CLOEXEC | O_NONBLOCK) == 0
        ? outputs[output_count].fds[1] : -1;
}

static int fake_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    void *argument = va_arg(args, void *);
    va_end(args);
    (void)fd;
    if (request == UI_SET_PHYS) {
        snprintf(issued_phys, sizeof(issued_phys), "%s", (const char *)argument);
        return 0;
    }
    if (request == EVIOCGSW((SW_MAX + 8u) / 8u)) {
        memset(argument, 0, (SW_MAX + 8u) / 8u);
        *(uint8_t *)argument = source_switches;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* Every source here is opened as a keyboard except MOUSE, so only the mouse
 * clone keeps keyboard keys; no clone keeps LEDs, which the sink carries. */
static int fake_create(const struct libevdev *source, int fd, struct libevdev_uinput **out)
{
    const struct input_absinfo *axis = libevdev_get_abs_info(source, ABS_X);
    bool mouse = libevdev_get_id_product(source) == 1;
    if (last_source == HOTKEYS) {
        metadata_ok &= libevdev_has_event_code(source, EV_SW, SW_TABLET_MODE)
            && !libevdev_has_event_code(source, EV_KEY, KEY_A)
            && !libevdev_has_event_code(source, EV_KEY, BTN_SOUTH)
            && !libevdev_has_event_code(source, EV_KEY, BTN_TRIGGER_HAPPY1)
            && !libevdev_has_event_type(source, EV_LED);
        axis = &(const struct input_absinfo){ .minimum = -100, .maximum = 2000, .resolution = 40 };
    }
    metadata_ok &= fd == outputs[output_count].fds[1]
        && strcmp(issued_phys, "keysharp-input/forward/usb-port/input0") == 0
        && strcmp(libevdev_get_name(source), mouse ? "Physical Mouse" : "Physical Keyboard") == 0
        && strcmp(libevdev_get_uniq(source), "source-serial") == 0
        && libevdev_get_id_bustype(source) == BUS_USB
        && libevdev_get_id_vendor(source) == (last_source == KEYD ? 0x0fac : 0x1234)
        && libevdev_get_id_product(source) == (mouse ? 1 : 2)
        && libevdev_get_id_version(source) == 7
        && (last_source == HOTKEYS || libevdev_has_property(source, INPUT_PROP_POINTER))
        && !libevdev_has_event_type(source, EV_REP)
        && !libevdev_has_event_type(source, EV_FF)
        && !libevdev_has_event_type(source, EV_LED)
        && !libevdev_has_event_code(source, EV_SW, SW_RFKILL_ALL)
        && (last_source == HOTKEYS || libevdev_has_event_code(source, EV_KEY, BTN_BACK))
        && libevdev_has_event_code(source, EV_KEY, KEY_A) == mouse
        && axis != NULL && axis->minimum == -100 && axis->maximum == 2000 && axis->resolution == 40;
    *out = &outputs[output_count];
    (void)snprintf(output_paths[output_count], sizeof(output_paths[output_count]),
        "/dev/input/event-test-%zu", output_count);
    output_count++;
    return 0;
}

static int fake_fd(const struct libevdev_uinput *device) { return device->fds[1]; }

static const char *fake_devnode(const struct libevdev_uinput *device)
{
    return device >= outputs && device < outputs + output_count
        ? output_paths[(size_t)(device - outputs)] : NULL;
}

/* destroy_output closes the caller-owned write end itself. */
static void fake_destroy(struct libevdev_uinput *device)
{
    close(device->fds[0]);
    destroyed++;
}

static void fake_sleep_ns(long nanoseconds)
{
    (void)nanoseconds;
}

/* Retirement waits on this clock. */
static uint64_t fake_now_ms = 1000u;
static uint64_t fake_monotonic_ms(void) { return fake_now_ms; }

#define libevdev_new_from_fd fake_source
#define libevdev_uinput_create_from_device fake_create
#define libevdev_uinput_get_fd fake_fd
#define libevdev_uinput_get_devnode fake_devnode
#define libevdev_uinput_destroy fake_destroy
#define open fake_open
#define ioctl fake_ioctl
#include "../src/platform/linux_output.h"
#define ksi_linux_sleep_ns fake_sleep_ns
#define ksi_linux_monotonic_ms fake_monotonic_ms
#include "../src/platform/linux_forward.c"
#undef libevdev_new_from_fd
#undef libevdev_uinput_create_from_device
#undef libevdev_uinput_get_fd
#undef libevdev_uinput_get_devnode
#undef libevdev_uinput_destroy
#undef open
#undef ioctl
#undef ksi_linux_sleep_ns
#undef ksi_linux_monotonic_ms

#include "../src/platform/linux_synth.c"

void ksi_linux_devices_get_indicator_state(bool *caps, bool *num, bool *scroll)
{
    *caps = *num = *scroll = false;
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); return false; \
} } while (0)

/* The sink: the generic keyboard device synthesis owns; and the absolute pointer. */
static int generic[2];
static int absolute[2];
static struct input_event events[16];

/* Number of events waiting on fd, or zero. A keystroke's scan code rides in
 * its packet, as from a real keyboard, and is left out here. */
static size_t read_events(int fd)
{
    ssize_t bytes = read(fd, events, sizeof(events));
    size_t count = 0u;

    for (size_t i = 0u; bytes > 0 && i < (size_t)bytes / sizeof(events[0]); i++)
        if (events[i].type != EV_MSC) events[count++] = events[i];
    return count;
}

/* Admits and writes a passed physical packet as the daemon does: its source
 * state, then the replay, each at admission and when written. */
static int forward(const ksi_forward_packet *packet)
{
    int result;

    ksi_linux_forward_note_source(packet, KSI_FORWARD_ENQUEUED);
    ksi_linux_forward_note_output(packet);
    ksi_linux_synth_physical_release(packet, KSI_FORWARD_ENQUEUED);
    ksi_linux_forward_note_source(packet, KSI_FORWARD_APPLIED);
    result = ksi_linux_forward_write(packet);
    ksi_linux_synth_physical_release(packet, KSI_FORWARD_APPLIED);
    return result;
}

/* Closes a source with nothing queued between admission and output. */
static void close_source(uint64_t target)
{
    ksi_linux_forward_close(target);
    ksi_linux_forward_apply_close(target);
}

/* A keystroke as a real keyboard reports it: its scan code, then the key. A
 * keyboard key rides the keyboard lane to the sink, anything else the mouse
 * lane to the source's clone. */
static ksi_forward_packet key_packet(uint64_t target, uint16_t code, int32_t value)
{
    return (ksi_forward_packet){ .target = target, .count = 2u,
        .flags = KSI_FORWARD_REPORT_END | (ksi_linux_key_code_is_keyboard(code) ? 0u : KSI_FORWARD_CLONE),
        .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 0x70004 },
                   { .type = EV_KEY, .code = code, .value = value }} };
}

static int forward_key(uint64_t target, uint16_t code, int32_t value)
{
    const ksi_forward_packet packet = key_packet(target, code, value);
    return forward(&packet);
}

/* Admits and drains a synthesized batch. */
static int send(const ksi_input *inputs, size_t count, const ksi_synth_owner *owner)
{
    ksi_linux_synth_note_enqueued_synth(inputs, count, owner);
    return ksi_linux_synth_send_input(inputs, count, 0u, owner);
}

static void release(const ksi_synth_owner *filter)
{
    ksi_linux_synth_release_owner(filter, KSI_FORWARD_ENQUEUED);
    ksi_linux_synth_release_owner(filter, KSI_FORWARD_APPLIED);
}

static ksi_input key_input(uint16_t code, bool down)
{
    return (ksi_input){ .type = KSI_INPUT_KEYBOARD, .data.keyboard = { .scan = code,
        .flags = KSI_KEY_SCANCODE | (down ? 0u : KSI_KEY_UP) } };
}

static ksi_input button_input(uint32_t flags)
{
    return (ksi_input){ .type = KSI_INPUT_MOUSE, .data.mouse = { .flags = flags } };
}

static bool logical(uint16_t code)
{
    uint8_t keys[KSI_KEY_BITMAP_BYTES] = {0};
    ksi_linux_synth_add_logical_key_state(keys, sizeof(keys));
    return ksi_key_bit(keys, code);
}

static bool forwarded(uint64_t target, uint16_t code)
{
    uint8_t keys[KSI_KEY_BITMAP_BYTES] = {0};
    ksi_linux_forward_add_key_state(target, keys, sizeof(keys));
    return ksi_key_bit(keys, code);
}

static bool sink_down(uint16_t code)
{
    return ksi_key_bit(sink.down, code);
}

/* Drains the sink; true if nothing written touched code. */
static bool sink_avoided(uint16_t code)
{
    bool avoided = true;

    for (size_t count; (count = read_events(generic[0])) != 0u; )
        for (size_t i = 0u; i < count; i++)
            avoided &= events[i].type != EV_KEY || events[i].code != code;
    return avoided;
}

/* The next n key events on the sink, in order, as code and value pairs. */
static bool sink_keys(size_t n, const uint16_t *codes, const int32_t *values)
{
    size_t count = read_events(generic[0]);
    size_t keys = 0u;

    for (size_t i = 0u; i < count; i++) {
        if (events[i].type == EV_SYN) continue;
        if (keys == n || events[i].code != codes[keys] || events[i].value != values[keys]) return false;
        keys++;
    }
    return keys == n;
}

static void release_everything(void)
{
    ksi_linux_synth_release_all();
    ksi_linux_synth_reset_enqueued_synth();
    (void)read_events(generic[0]);
}

static bool test_forwarding_and_synthesis(void)
{
    uint64_t mouse = ksi_linux_forward_open(MOUSE, false);
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    CHECK(mouse != 0u && keyboard != 0u && mouse != keyboard && metadata_ok);
    CHECK(ksi_linux_forward_has_clone(mouse) && ksi_linux_forward_has_clone(keyboard));
    CHECK(ksi_linux_forward_target_for_path("/dev/input/event-test-1") == keyboard);
    CHECK(ksi_linux_forward_target_for_path("/dev/input/event0") == 0u);

    ksi_forward_packet motion = { .target = mouse, .count = 2u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE,
        .events = {{ .type = EV_REL, .code = REL_X, .value = 320 },
                   { .type = EV_REL, .code = REL_Y, .value = -7 }} };
    CHECK(forward(&motion) == 0);
    CHECK(read_events(outputs[0].fds[0]) == 3u && events[0].code == REL_X
        && events[1].value == -7 && events[2].type == EV_SYN);

    /* A fragment waits for the source's own SYN, on the sink with the lane. */
    ksi_forward_packet key = key_packet(keyboard, KEY_A, 1);
    key.flags = 0u;
    CHECK(forward(&key) == 0);
    key.events[1].value = 2;
    CHECK(forward(&key) == 0);
    const ksi_forward_packet sync = { .target = keyboard, .count = 1u,
        .events = {{ .type = EV_SYN, .code = SYN_REPORT }} };
    CHECK(forward(&sync) == 0);
    CHECK(read_events(generic[0]) == 3u && events[0].value == 1 && events[1].value == 2);
    CHECK(read_events(outputs[1].fds[0]) == 0u);

    /* Synthesis shares the sink; a key a source already holds adds nothing. */
    const ksi_input generated[] = {
        { .type = KSI_INPUT_MOUSE, .data.mouse = { .dx = 20, .flags = KSI_MOUSE_MOVE } },
        key_input(KEY_A, true), key_input(KEY_B, true),
    };
    CHECK(send(generated, 3u, NULL) == 0);
    CHECK(read_events(generic[0]) == 4u && events[0].type == EV_REL && events[0].value == 20
        && events[2].code == KEY_B);

    /* A lane goes only to an output its source has. */
    motion.target = keyboard;
    CHECK(forward(&motion) == 0 && read_events(outputs[1].fds[0]) == 3u);
    motion.flags = KSI_FORWARD_REPORT_END;
    motion.target = mouse;
    CHECK(forward(&motion) == 0 && read_events(generic[0]) == 0u);
    motion.flags |= KSI_FORWARD_CLONE;

    /* Physical button aliases stay as the device reported them. */
    CHECK(forward_key(mouse, BTN_BACK, 1) == 0);
    CHECK(read_events(outputs[0].fds[0]) == 2u && events[0].code == BTN_BACK);

    /* Retirement releases holds at once; removal waits for readers to drain. */
    close_source(mouse);
    CHECK(read_events(outputs[0].fds[0]) == 2u && events[0].code == BTN_BACK && events[0].value == 0);
    ksi_linux_synth_maintain_output();
    CHECK(destroyed == 0u);

    /* A decision delayed past retirement cannot reach the replacement. */
    uint64_t replacement = ksi_linux_forward_open(MOUSE, false);
    CHECK(replacement != mouse && replacement != 0u);
    CHECK(forward(&motion) == 0 && read_events(outputs[2].fds[0]) == 0u);
    motion.target = replacement;
    CHECK(forward(&motion) == 0 && read_events(outputs[2].fds[0]) == 3u);

    close(outputs[2].fds[1]);
    outputs[2].fds[1] = -1;
    CHECK(forward(&motion) != 0);
    CHECK(ksi_linux_forward_failed(replacement, KSI_FORWARD_APPLIED)
        && ksi_linux_forward_failed(replacement, KSI_FORWARD_ENQUEUED)
        && !ksi_linux_forward_failed(keyboard, KSI_FORWARD_APPLIED));
    CHECK(ksi_linux_forward_take_failure() && !ksi_linux_forward_take_failure());
    CHECK(!synth_write_failed && ksi_linux_forward_sink_ready());

    /* Synthesis still holds A, so the keyboard's going leaves it down. */
    close_source(replacement);
    close_source(keyboard);
    CHECK(read_events(generic[0]) == 0u);
    CHECK(sink_down(KEY_A) && sink_down(KEY_B));
    ksi_linux_forward_collect(true);
    CHECK(destroyed == 3u);
    release_everything();
    return true;
}

/* A keyboard with nothing but keyboard keys needs no clone: its keys go to the
 * sink, and closing it releases them there without a drain. */
static bool test_plain_keyboard_has_no_clone(void)
{
    size_t before = output_count, retired = destroyed;
    uint64_t keyboard = ksi_linux_forward_open(PLAIN, true);

    CHECK(keyboard != 0u && output_count == before && !ksi_linux_forward_has_clone(keyboard));
    CHECK(!ksi_linux_forward_failed(keyboard, KSI_FORWARD_ENQUEUED));
    CHECK(forward_key(keyboard, KEY_A, 1) == 0 && sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 1 }));

    /* A lane for an output the source lacks writes nothing. */
    const ksi_forward_packet button = key_packet(keyboard, BTN_BACK, 1);
    CHECK(ksi_linux_forward_write(&button) == 0 && read_events(generic[0]) == 0u);

    close_source(keyboard);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));
    CHECK(ksi_linux_forward_failed(keyboard, KSI_FORWARD_ENQUEUED) && destroyed == retired);
    return true;
}

static bool test_wheel_state_is_per_device(void)
{
    size_t first_output = output_count;
    uint64_t first = ksi_linux_forward_open(MOUSE, false);
    uint64_t second = ksi_linux_forward_open(MOUSE, false);
    CHECK(first != 0u && second != 0u);
    ksi_forward_packet wheel = { .target = first, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE,
        .events = {{ .type = EV_REL, .code = REL_WHEEL_HI_RES, .value = -60 }} };
    CHECK(forward(&wheel) == 0);
    wheel.target = second;
    CHECK(forward(&wheel) == 0);
    wheel.target = first;
    CHECK(forward(&wheel) == 0);
    CHECK(read_events(outputs[first_output].fds[0]) == 5u);
    CHECK(events[0].code == REL_WHEEL_HI_RES && events[0].value == -60);
    CHECK(events[3].code == REL_WHEEL && events[3].value == -1);
    CHECK(read_events(outputs[first_output + 1u].fds[0]) == 2u
        && events[0].code == REL_WHEEL_HI_RES && events[1].type == EV_SYN);
    close_source(first);
    close_source(second);
    ksi_linux_forward_collect(true);
    return true;
}

/* Ending a grab releases the holds the source no longer has and keeps the rest
 * until it reports their release. Admission moves first, written output at the
 * same queue position, and a stale end cannot move written output back. */
static bool test_grab_end_releases_source_holds(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_synth_owner remap = { .target = keyboard, .connection_id = 3u,
        .hook_type = KSI_HOOK_KEYBOARD, .source_type = EV_KEY, .source_code = KEY_A };
    const ksi_input b = key_input(KEY_B, true);
    const ksi_forward_packet shift_up = key_packet(keyboard, KEY_LEFTSHIFT, 0);
    uint8_t kept[KSI_KEY_BITMAP_BYTES];

    CHECK(forward_key(keyboard, KEY_LEFTCTRL, 1) == 0 && forward_key(keyboard, KEY_LEFTSHIFT, 1) == 0);
    CHECK(read_events(generic[0]) == 4u);
    CHECK(send(&b, 1u, &remap) == 0 && read_events(generic[0]) == 2u);

    /* Shift's release is still waiting for its hook when the grab ends. */
    ksi_linux_forward_note_source(&shift_up, KSI_FORWARD_ENQUEUED);
    ksi_linux_forward_note_source(&shift_up, KSI_FORWARD_APPLIED);
    uint64_t next = ksi_linux_forward_end_grab(keyboard, kept);
    CHECK(next != keyboard && next != 0u);
    CHECK(ksi_key_bit(kept, KEY_LEFTCTRL) && !ksi_key_bit(kept, KEY_LEFTSHIFT));
    CHECK(forwarded(next, KEY_LEFTCTRL) && !forwarded(next, KEY_LEFTSHIFT));
    CHECK(read_events(generic[0]) == 0u);
    ksi_linux_forward_apply_end_grab(next, NULL);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));

    CHECK(forward_key(next, KEY_LEFTCTRL, 0) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTCTRL }, (const int32_t[]){ 0 }));
    CHECK(!forwarded(next, KEY_LEFTCTRL));

    /* Late decisions of the ended grab are dropped, and its remaps end. */
    CHECK(forward_key(keyboard, KEY_LEFTCTRL, 1) == 0 && read_events(generic[0]) == 0u);
    ksi_linux_synth_maintain_output();
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 0 }));
    CHECK(!logical(KEY_B));
    /* A dead owner's press is dropped in both views; its release still plays. */
    CHECK(send(&b, 1u, &remap) == 0 && read_events(generic[0]) == 0u && !logical(KEY_B));
    const ksi_synth_owner script = { .connection_id = 4u };
    const ksi_input b_up = key_input(KEY_B, false);
    CHECK(send(&b, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&b_up, 1u, &remap) == 0 && read_events(generic[0]) == 2u && events[0].value == 0);
    CHECK(!logical(KEY_B));

    /* An end applied out of order leaves written output on the newest target. */
    uint64_t later = ksi_linux_forward_end_grab(next, kept);
    ksi_linux_forward_apply_end_grab(later, NULL);
    ksi_linux_forward_apply_end_grab(next, NULL);
    CHECK(forward_key(later, KEY_A, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(forward_key(later, KEY_A, 0) == 0 && read_events(generic[0]) == 2u);

    close_source(later);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* A physical key-up ends generic holds of its key, as a Win32 key-up does,
 * and the remap holds derived from that key on that keyboard; other holds
 * survive. A key-up a hook suppressed ends only the derived holds. */
static bool test_physical_release(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    uint64_t other = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_synth_owner script = { .connection_id = 7u };
    const ksi_synth_owner remap = { .target = keyboard, .connection_id = 8u,
        .hook_type = KSI_HOOK_KEYBOARD, .source_type = EV_KEY, .source_code = KEY_A };
    const ksi_input shift = key_input(KEY_LEFTSHIFT, true);
    const ksi_input b = key_input(KEY_B, true);
    const ksi_forward_packet other_a_up = key_packet(other, KEY_A, 0);
    const ksi_forward_packet a_up = key_packet(keyboard, KEY_A, 0);
    ksi_forward_packet shift_up = key_packet(keyboard, KEY_LEFTSHIFT, 0);

    CHECK(send(&shift, 1u, &script) == 0 && send(&b, 1u, &remap) == 0);
    CHECK(read_events(generic[0]) == 4u);
    ksi_linux_synth_physical_release(&other_a_up, KSI_FORWARD_ENQUEUED);
    ksi_linux_synth_physical_release(&other_a_up, KSI_FORWARD_APPLIED);
    CHECK(logical(KEY_B) && read_events(generic[0]) == 0u);
    ksi_linux_synth_physical_release(&a_up, KSI_FORWARD_ENQUEUED);
    CHECK(!logical(KEY_B) && logical(KEY_LEFTSHIFT));
    ksi_linux_synth_physical_release(&a_up, KSI_FORWARD_APPLIED);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 0 }));

    shift_up.flags |= KSI_FORWARD_SUPPRESSED;
    ksi_linux_synth_physical_release(&shift_up, KSI_FORWARD_ENQUEUED);
    ksi_linux_synth_physical_release(&shift_up, KSI_FORWARD_APPLIED);
    CHECK(logical(KEY_LEFTSHIFT) && read_events(generic[0]) == 0u);
    shift_up.flags &= ~KSI_FORWARD_SUPPRESSED;
    ksi_linux_synth_physical_release(&shift_up, KSI_FORWARD_ENQUEUED);
    ksi_linux_synth_physical_release(&shift_up, KSI_FORWARD_APPLIED);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));
    CHECK(!logical(KEY_LEFTSHIFT) && !sink_down(KEY_LEFTSHIFT));

    close_source(keyboard);
    close_source(other);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* A mouse may report either member of an X-button pair, and synthesis names
 * the other, so a synthetic release displaces the forwarded alias. */
static bool test_button_alias_displacement(void)
{
    size_t output = output_count;
    uint64_t mouse = ksi_linux_forward_open(MOUSE, false);
    const ksi_synth_owner script = { .connection_id = 9u };
    const ksi_input x1_up = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .mouse_data = KSI_XBUTTON1 << 16, .flags = KSI_MOUSE_X_UP } };
    const ksi_input x1_down = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .mouse_data = KSI_XBUTTON1 << 16, .flags = KSI_MOUSE_X_DOWN } };

    CHECK(forward_key(mouse, BTN_BACK, 1) == 0 && read_events(outputs[output].fds[0]) == 2u);
    CHECK(send(&x1_up, 1u, &script) == 0);
    CHECK(read_events(outputs[output].fds[0]) == 2u && events[0].code == BTN_BACK && events[0].value == 0);
    CHECK(send(&x1_down, 1u, &script) == 0);
    CHECK(read_events(outputs[output].fds[0]) == 2u && events[0].code == BTN_BACK && events[0].value == 1);
    CHECK(read_events(generic[0]) == 0u);

    close_source(mouse);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* Ending a grab forgets displaced holds, so a later synthetic press is an owned
 * hold that its owner's release ends, not a source hold nothing releases. */
static bool test_displaced_hold_ends_with_grab(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_synth_owner script = { .connection_id = 12u };
    const ksi_input up = key_input(KEY_LEFTSHIFT, false);
    const ksi_input down = key_input(KEY_LEFTSHIFT, true);
    uint8_t held[KSI_KEY_BITMAP_BYTES];

    CHECK(forward_key(keyboard, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&up, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    uint64_t next = ksi_linux_forward_end_grab(keyboard, held);
    ksi_linux_forward_apply_end_grab(next, NULL);
    CHECK(ksi_key_bit(held, KEY_LEFTSHIFT) && !forwarded(next, KEY_LEFTSHIFT));
    CHECK(read_events(generic[0]) == 0u);

    CHECK(send(&down, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(!forwarded(next, KEY_LEFTSHIFT) && applied.holders[KEY_LEFTSHIFT] == 1u);
    release(&script);
    CHECK(read_events(generic[0]) == 2u && events[0].value == 0 && !logical(KEY_LEFTSHIFT));

    close_source(next);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* Autorepeat marks nothing held, and the sink writes neither a repeat nor a
 * release of a key it does not hold, so no scan code makes a report. */
static bool test_repeats_and_unheld_releases(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    ksi_forward_packet repeat = key_packet(keyboard, KEY_A, 2);
    ksi_forward_packet release_packet = key_packet(keyboard, KEY_A, 0);

    CHECK(forward(&repeat) == 0 && !forwarded(keyboard, KEY_A));
    CHECK(read(generic[0], events, sizeof(events)) < 0);
    release_packet.flags |= KSI_FORWARD_SUPPRESSED;
    CHECK(forward(&release_packet) == 0);
    CHECK(read(generic[0], events, sizeof(events)) < 0);

    CHECK(forward_key(keyboard, KEY_A, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(forward(&repeat) == 0 && forwarded(keyboard, KEY_A));
    CHECK(read_events(generic[0]) == 2u && events[0].value == 2);
    CHECK(forward(&release_packet) == 0 && read_events(generic[0]) == 2u && events[0].value == 0);

    close_source(keyboard);
    ksi_linux_forward_collect(true);
    return true;
}

/* An end applied ahead of queue order uses the source state that admission
 * saw, so a release still queued behind it cannot strand the key. */
static bool test_early_end_keeps_admitted_state(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_forward_packet up = key_packet(keyboard, KEY_A, 0);
    uint8_t held[KSI_KEY_BITMAP_BYTES];

    CHECK(forward_key(keyboard, KEY_A, 1) == 0 && read_events(generic[0]) == 2u);
    ksi_linux_forward_note_source(&up, KSI_FORWARD_ENQUEUED);
    uint64_t next = ksi_linux_forward_end_grab(keyboard, held);
    CHECK(!ksi_key_bit(held, KEY_A));
    ksi_linux_forward_apply_end_grab(next, held);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));

    close_source(next);
    ksi_linux_forward_collect(true);
    return true;
}

/* A retired clone is removed once readers have had the drain time. */
static bool test_retired_clone_removed_after_drain(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    size_t before = destroyed;

    close_source(keyboard);
    ksi_linux_synth_maintain_output();
    CHECK(destroyed == before);
    fake_now_ms += KSI_FORWARD_DRAIN_MS;
    ksi_linux_synth_maintain_output();
    CHECK(destroyed == before + 1u);
    return true;
}

/* A synthetic release displaces a physical hold; a later synthetic press puts
 * it back, and the source's own release ends it. */
static bool test_displaced_hold_restores(void)
{
    uint64_t first = ksi_linux_forward_open(KEYBOARD, true);
    uint64_t second = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_synth_owner script = { .connection_id = 1u };
    const ksi_input up = key_input(KEY_LEFTSHIFT, false);
    const ksi_input down = key_input(KEY_LEFTSHIFT, true);

    CHECK(forward_key(first, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 2u);

    /* An admitted release is visible before the paced queue drains. */
    ksi_linux_synth_note_enqueued_synth(&up, 1u, &script);
    CHECK(!forwarded(first, KEY_LEFTSHIFT));
    CHECK(ksi_linux_synth_send_input(&up, 1u, 0u, &script) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));

    CHECK(send(&down, 1u, &script) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 1 }));
    CHECK(applied.holders[KEY_LEFTSHIFT] == 0u && forwarded(first, KEY_LEFTSHIFT));
    CHECK(!forwarded(second, KEY_LEFTSHIFT) && !logical(KEY_LEFTSHIFT));
    CHECK(forward_key(first, KEY_LEFTSHIFT, 0) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));

    /* With nothing displaced, a press is an ordinary owned hold. */
    CHECK(send(&down, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(applied.holders[KEY_LEFTSHIFT] == 1u);
    CHECK(send(&up, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(!sink_down(KEY_LEFTSHIFT));

    /* A source released between displacement and the press leaves nothing to
     * restore, so the press is an owned hold. */
    CHECK(forward_key(second, KEY_LEFTSHIFT, 1) == 0);
    CHECK(send(&up, 1u, &script) == 0);
    const ksi_forward_packet source_up = key_packet(second, KEY_LEFTSHIFT, 0);
    ksi_linux_forward_note_source(&source_up, KSI_FORWARD_ENQUEUED);
    ksi_linux_forward_note_source(&source_up, KSI_FORWARD_APPLIED);
    CHECK(send(&down, 1u, &script) == 0 && applied.holders[KEY_LEFTSHIFT] == 1u);
    CHECK(logical(KEY_LEFTSHIFT) && sink_down(KEY_LEFTSHIFT));

    close_source(first);
    close_source(second);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* A compositor applies each device's queue whole, so only one device keeps key
 * order. A remap's [Shift up, d, Shift down] is written in order on the sink, once
 * each, and a key-up of a key held elsewhere waits for the last holder. */
static bool test_sink_keeps_order(void)
{
    uint64_t first = ksi_linux_forward_open(PLAIN, true);
    uint64_t second = ksi_linux_forward_open(PLAIN, true);
    const ksi_synth_owner script = { .connection_id = 3u };
    const ksi_input remap[] = { key_input(KEY_LEFTSHIFT, false), key_input(KEY_D, true),
        key_input(KEY_LEFTSHIFT, true) };
    const ksi_input d_up = key_input(KEY_D, false);

    CHECK(forward_key(first, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(remap, 3u, &script) == 0);
    CHECK(sink_keys(3u, (const uint16_t[]){ KEY_LEFTSHIFT, KEY_D, KEY_LEFTSHIFT },
        (const int32_t[]){ 0, 1, 1 }));
    CHECK(send(&d_up, 1u, &script) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_D }, (const int32_t[]){ 0 }));

    /* The same batch arriving one input at a time, as SendEvent and hooks send it. */
    for (size_t i = 0u; i < 3u; i++) {
        ksi_linux_synth_note_enqueued_synth(&remap[i], 1u, &script);
        CHECK(ksi_linux_synth_send_input(&remap[i], 1u, KSI_INTERNAL_SYNTH_BATCH_FRAGMENT, &script) == 0);
    }
    CHECK(sink_keys(3u, (const uint16_t[]){ KEY_LEFTSHIFT, KEY_D, KEY_LEFTSHIFT },
        (const int32_t[]){ 0, 1, 1 }));
    CHECK(send(&d_up, 1u, &script) == 0 && read_events(generic[0]) == 2u);

    /* Shift held on both keyboards is one hold on the sink. */
    CHECK(forward_key(second, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 0u);
    CHECK(send(remap, 3u, &script) == 0);
    CHECK(sink_keys(3u, (const uint16_t[]){ KEY_LEFTSHIFT, KEY_D, KEY_LEFTSHIFT },
        (const int32_t[]){ 0, 1, 1 }));
    CHECK(forwarded(first, KEY_LEFTSHIFT) && forwarded(second, KEY_LEFTSHIFT));
    CHECK(forward_key(first, KEY_LEFTSHIFT, 0) == 0 && read_events(generic[0]) == 0u);
    CHECK(forward_key(second, KEY_LEFTSHIFT, 0) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));

    /* A script's release of its own press leaves the user's hold down, and the
     * user's release ends the script's hold, as a Win32 key-up does. */
    CHECK(forward_key(first, KEY_A, 1) == 0 && read_events(generic[0]) == 2u);
    const ksi_input a_down = key_input(KEY_A, true), a_up = key_input(KEY_A, false);
    CHECK(send(&a_down, 1u, &script) == 0 && send(&a_up, 1u, &script) == 0);
    CHECK(read_events(generic[0]) == 0u && sink_down(KEY_A));
    CHECK(send(&a_down, 1u, &script) == 0 && read_events(generic[0]) == 0u);
    const ksi_forward_packet user_up = key_packet(first, KEY_A, 0);
    CHECK(forward(&user_up) == 0 && sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));

    /* The last remap's D is still the script's, since its up hotkey has not
     * run, and outlives the keyboards. */
    CHECK(sink_down(KEY_D) && applied.holders[KEY_D] == 1u);
    close_source(first);
    close_source(second);
    CHECK(read_events(generic[0]) == 0u && sink_down(KEY_D));
    release_everything();
    return true;
}

/* Ctrl and a click sent together keep their order on the sink, which has the
 * buttons too; a script's hold survives its keyboard being unplugged. */
static bool test_mixed_batch_and_unplug(void)
{
    uint64_t keyboard = ksi_linux_forward_open(PLAIN, true);
    const ksi_synth_owner script = { .connection_id = 5u };
    const ksi_input ctrl_click[] = { key_input(KEY_LEFTCTRL, true),
        button_input(KSI_MOUSE_LEFT_DOWN), button_input(KSI_MOUSE_LEFT_UP),
        key_input(KEY_LEFTCTRL, false) };
    const ksi_input w_down = key_input(KEY_W, true);

    CHECK(send(ctrl_click, 4u, &script) == 0);
    CHECK(sink_keys(4u, (const uint16_t[]){ KEY_LEFTCTRL, BTN_LEFT, BTN_LEFT, KEY_LEFTCTRL },
        (const int32_t[]){ 1, 1, 0, 0 }));

    /* Motion and a button in one input are one report. */
    const ksi_input drag = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .dx = 5, .flags = KSI_MOUSE_MOVE | KSI_MOUSE_LEFT_DOWN } };
    CHECK(send(&drag, 1u, &script) == 0 && read_events(generic[0]) == 3u);
    CHECK(events[0].code == REL_X && events[1].code == BTN_LEFT && events[2].type == EV_SYN);
    const ksi_input drop = button_input(KSI_MOUSE_LEFT_UP);
    CHECK(send(&drop, 1u, &script) == 0 && read_events(generic[0]) == 2u);

    CHECK(send(&w_down, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(forward_key(keyboard, KEY_W, 1) == 0 && read_events(generic[0]) == 0u);
    close_source(keyboard);
    ksi_linux_synth_maintain_output();
    CHECK(read_events(generic[0]) == 0u && sink_down(KEY_W) && logical(KEY_W));
    release_everything();
    CHECK(!sink_down(KEY_W));
    return true;
}

static bool test_owner_lifetimes(void)
{
    uint64_t first = ksi_linux_forward_open(KEYBOARD, true);
    uint64_t second = ksi_linux_forward_open(KEYBOARD, true);
    const ksi_input down = key_input(KEY_B, true);
    const ksi_input up = key_input(KEY_B, false);
    const ksi_synth_owner first_owner = { .target = first, .connection_id = 11u,
        .hook_type = KSI_HOOK_KEYBOARD, .source_type = EV_KEY, .source_code = KEY_A };
    const ksi_synth_owner second_owner = { .target = second, .connection_id = 22u,
        .hook_type = KSI_HOOK_MOUSE, .source_type = EV_KEY, .source_code = BTN_LEFT };
    const ksi_synth_owner script = { .connection_id = 33u };

    CHECK(send(&down, 1u, &first_owner) == 0 && send(&down, 1u, &second_owner) == 0);
    CHECK(read_events(generic[0]) == 2u && applied.holders[KEY_B] == 2u);

    /* Zero filter fields are wildcards. */
    release(&(ksi_synth_owner){ .connection_id = 11u, .hook_type = KSI_HOOK_MOUSE });
    CHECK(applied.holders[KEY_B] == 2u);
    release(&(ksi_synth_owner){ .hook_type = KSI_HOOK_MOUSE });
    CHECK(applied.holders[KEY_B] == 1u && read_events(generic[0]) == 0u);

    /* An owner's own release ends only its hold. */
    CHECK(send(&down, 1u, &script) == 0 && send(&up, 1u, &first_owner) == 0);
    CHECK(read_events(generic[0]) == 0u && applied.holders[KEY_B] == 1u);

    /* A disconnect ends the client's own holds. */
    release(&(ksi_synth_owner){ .connection_id = 33u });
    CHECK(read_events(generic[0]) == 2u && events[0].value == 0 && !logical(KEY_B));

    /* A release its sender never pressed is explicit and ends every hold. */
    CHECK(send(&down, 1u, &first_owner) == 0 && send(&down, 1u, &script) == 0);
    CHECK(send(&up, 1u, &(ksi_synth_owner){ .connection_id = 44u }) == 0);
    CHECK(read_events(generic[0]) == 4u && applied.holders[KEY_B] == 0u
        && enqueued.holders[KEY_B] == 0u);

    /* A remap's [Shift up, a] releases a forwarded Shift it never pressed. */
    CHECK(forward_key(first, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 2u);
    const ksi_input remap[] = { key_input(KEY_LEFTSHIFT, false), key_input(KEY_A, true) };
    CHECK(send(remap, 2u, &first_owner) == 0);
    CHECK(sink_keys(2u, (const uint16_t[]){ KEY_LEFTSHIFT, KEY_A }, (const int32_t[]){ 0, 1 }));

    /* Holds tied to a source end with it; others survive. */
    CHECK(send(&down, 1u, &second_owner) == 0 && read_events(generic[0]) == 2u);
    close_source(first);
    ksi_linux_synth_maintain_output();
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));
    CHECK(sink_down(KEY_B));
    close_source(second);
    ksi_linux_synth_maintain_output();
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 0 }));
    CHECK(!logical(KEY_A) && !logical(KEY_B));

    /* A decision delayed past retirement is accepted as a no-op. */
    CHECK(send(&down, 1u, &second_owner) == 0 && read_events(generic[0]) == 0u);

    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* The Ctrl+Shift+U sequence presses only modifiers the sink does not hold,
 * whether synthesis or the user holds them, and leaves every hold as it was. */
static bool test_unicode_entry_is_transient(void)
{
    uint64_t keyboard = ksi_linux_forward_open(PLAIN, true);
    const ksi_synth_owner script = { .connection_id = 5u };
    const ksi_input shift = key_input(KEY_LEFTSHIFT, true);
    const ksi_input e_acute = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = 0xE9u, .flags = KSI_KEY_UNICODE } };

    CHECK(send(&shift, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&e_acute, 1u, &script) == 0 && sink_avoided(KEY_LEFTSHIFT));
    CHECK(sink_down(KEY_LEFTSHIFT) && applied.holders[KEY_LEFTSHIFT] == 1u);
    CHECK(!sink_down(KEY_LEFTCTRL) && !sink_down(KEY_U));
    release_everything();

    CHECK(forward_key(keyboard, KEY_LEFTCTRL, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&e_acute, 1u, &script) == 0 && sink_avoided(KEY_LEFTCTRL));
    CHECK(sink_down(KEY_LEFTCTRL) && !sink_down(KEY_LEFTSHIFT));
    close_source(keyboard);
    CHECK(read_events(generic[0]) == 2u && !sink_down(KEY_LEFTCTRL));

    /* A modifier synthesis holds stays held. */
    const ksi_input ctrl = key_input(KEY_LEFTCTRL, true);
    CHECK(send(&ctrl, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&e_acute, 1u, &script) == 0 && sink_avoided(KEY_LEFTCTRL));
    CHECK(sink_down(KEY_LEFTCTRL) && applied.holders[KEY_LEFTCTRL] == 1u);
    release_everything();
    return true;
}

static bool test_release_all_includes_sources(void)
{
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);

    CHECK(forward_key(keyboard, KEY_A, 1) == 0 && read_events(generic[0]) == 2u);
    ksi_linux_forward_release_all(KSI_FORWARD_ENQUEUED);
    CHECK(!forwarded(keyboard, KEY_A));
    ksi_linux_forward_release_all(KSI_FORWARD_APPLIED);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));
    close_source(keyboard);
    ksi_linux_forward_collect(true);
    return true;
}

/* uinput cannot preset switches, and rfkill-input must not see a clone's
 * SW_RFKILL_ALL start at zero. */
static bool test_switch_state(void)
{
    size_t output = output_count;

    source_switches = 1u << SW_TABLET_MODE;
    uint64_t hotkeys = ksi_linux_forward_open(SWITCHES, true);
    CHECK(hotkeys != 0u && metadata_ok);
    CHECK(read_events(outputs[output].fds[0]) == 2u && events[0].type == EV_SW
        && events[0].code == SW_TABLET_MODE && events[0].value == 1);
    source_switches = 0u;
    ksi_linux_forward_sync_switches(hotkeys);
    CHECK(read_events(outputs[output].fds[0]) == 2u && events[0].code == SW_TABLET_MODE
        && events[0].value == 0);
    close_source(hotkeys);

    /* A keyboard whose only other report is a switch gets a clone for it,
     * without the joystick buttons that would make udev take it for one. */
    hotkeys = ksi_linux_forward_open(HOTKEYS, true);
    CHECK(hotkeys != 0u && ksi_linux_forward_has_clone(hotkeys) && metadata_ok);
    const ksi_forward_packet lid = { .target = hotkeys, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE,
        .events = {{ .type = EV_SW, .code = SW_TABLET_MODE, .value = 1 }} };
    (void)read_events(outputs[output + 1u].fds[0]);
    CHECK(forward(&lid) == 0 && read_events(outputs[output + 1u].fds[0]) == 2u
        && events[0].code == SW_TABLET_MODE);
    close_source(hotkeys);
    ksi_linux_forward_collect(true);
    return true;
}

/* A failed sink write marks the sink failed until a new one is attached, and
 * makes synthesis unavailable so recovery recreates it. */
static bool test_sink_failure(void)
{
    int broken[2];
    const ksi_synth_owner script = { .connection_id = 6u };
    const ksi_input a = key_input(KEY_A, true);

    CHECK(pipe2(broken, O_CLOEXEC | O_NONBLOCK) == 0);
    close(broken[0]);
    ksi_linux_forward_attach_sink(broken[1]);
    CHECK(ksi_linux_forward_sink_ready());
    CHECK(send(&a, 1u, &script) != 0);
    CHECK(!ksi_linux_forward_sink_ready() && ksi_linux_forward_take_failure());
    CHECK(!ksi_linux_synth_is_available() && ksi_linux_synth_needs_recovery());
    close(broken[1]);
    ksi_linux_synth_release_all();
    ksi_linux_synth_reset_enqueued_synth();
    ksi_linux_forward_attach_sink(generic[1]);
    CHECK(ksi_linux_forward_sink_ready() && !sink_down(KEY_A));
    return true;
}

/* A grab can end between a report's fragments and its SYN, which is then
 * stale; the outputs get the SYN when the grab ends or the source closes. */
static bool test_grab_end_finishes_open_reports(void)
{
    size_t output = output_count;
    uint64_t keyboard = ksi_linux_forward_open(KEYBOARD, true);
    ksi_forward_packet key = key_packet(keyboard, KEY_A, 1);
    ksi_forward_packet button = key_packet(keyboard, BTN_BACK, 1);
    uint8_t kept[KSI_KEY_BITMAP_BYTES];

    key.flags = 0u;
    button.flags &= ~KSI_FORWARD_REPORT_END;
    CHECK(forward(&key) == 0 && forward(&button) == 0);
    CHECK(read_events(generic[0]) == 1u && read_events(outputs[output].fds[0]) == 1u);
    uint64_t next = ksi_linux_forward_end_grab(keyboard, kept);
    ksi_linux_forward_apply_end_grab(next, kept);
    CHECK(read_events(generic[0]) == 1u && events[0].type == EV_SYN);
    CHECK(read_events(outputs[output].fds[0]) == 1u && events[0].type == EV_SYN);

    key.target = next;
    key.events[1].value = 0;
    CHECK(forward(&key) == 0 && read_events(generic[0]) == 1u);
    close_source(next);
    CHECK(read_events(generic[0]) == 1u && events[0].type == EV_SYN);
    ksi_linux_forward_collect(true);
    return true;
}

/* Closing is queue-ordered, so a restore admitted before an unplug and
 * written after it stays a restore in both views, and the sink releases the
 * key with the source. */
static bool test_close_keeps_queue_order(void)
{
    uint64_t keyboard = ksi_linux_forward_open(PLAIN, true);
    const ksi_synth_owner script = { .connection_id = 13u };
    const ksi_input up = key_input(KEY_LEFTSHIFT, false);
    const ksi_input down = key_input(KEY_LEFTSHIFT, true);

    CHECK(forward_key(keyboard, KEY_LEFTSHIFT, 1) == 0 && read_events(generic[0]) == 2u);
    /* Only a close already admitted is applied. */
    ksi_linux_forward_apply_close(keyboard);
    CHECK(forwarded(keyboard, KEY_LEFTSHIFT) && read_events(generic[0]) == 0u);
    CHECK(send(&up, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    ksi_linux_synth_note_enqueued_synth(&down, 1u, &script);
    ksi_linux_forward_close(keyboard);
    CHECK(!logical(KEY_LEFTSHIFT) && !forwarded(keyboard, KEY_LEFTSHIFT));
    CHECK(ksi_linux_synth_send_input(&down, 1u, 0u, &script) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 1 }));
    ksi_linux_forward_apply_close(keyboard);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 0 }));
    CHECK(applied.holders[KEY_LEFTSHIFT] == 0u && enqueued.holders[KEY_LEFTSHIFT] == 0u);

    /* A press admitted after the close is the script's own hold. */
    keyboard = ksi_linux_forward_open(PLAIN, true);
    CHECK(forward_key(keyboard, KEY_LEFTSHIFT, 1) == 0 && send(&up, 1u, &script) == 0);
    (void)read_events(generic[0]);
    ksi_linux_forward_close(keyboard);
    ksi_linux_synth_note_enqueued_synth(&down, 1u, &script);
    ksi_linux_forward_apply_close(keyboard);
    CHECK(ksi_linux_synth_send_input(&down, 1u, 0u, &script) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_LEFTSHIFT }, (const int32_t[]){ 1 }));
    CHECK(logical(KEY_LEFTSHIFT) && applied.holders[KEY_LEFTSHIFT] == 1u);
    release_everything();
    return true;
}

/* A button pressed after an absolute move goes to the absolute device with
 * the move, and is released there whenever its last holder lets go. */
static bool test_absolute_button_routing(void)
{
    uint64_t mouse = ksi_linux_forward_open(MOUSE, false);
    size_t output = output_count - 1u;
    const ksi_synth_owner script = { .connection_id = 14u };
    const ksi_input moved_down[] = {
        { .type = KSI_INPUT_MOUSE, .data.mouse = { .dx = 100, .dy = 200,
            .flags = KSI_MOUSE_MOVE | KSI_MOUSE_ABSOLUTE } },
        button_input(KSI_MOUSE_LEFT_DOWN),
    };
    const ksi_input up = button_input(KSI_MOUSE_LEFT_UP);
    const ksi_input down = button_input(KSI_MOUSE_LEFT_DOWN);

    uinput_abs_fd = absolute[1];
    CHECK(send(moved_down, 2u, &script) == 0 && read_events(generic[0]) == 0u);
    CHECK(read_events(absolute[0]) == 5u && events[3].code == BTN_LEFT && events[3].value == 1);
    CHECK(send(&up, 1u, &script) == 0 && read_events(generic[0]) == 0u);
    CHECK(read_events(absolute[0]) == 2u && events[0].code == BTN_LEFT && events[0].value == 0);
    CHECK(send(moved_down, 2u, &script) == 0 && read_events(absolute[0]) == 5u);
    release_everything();
    CHECK(read_events(absolute[0]) == 2u && events[0].code == BTN_LEFT && events[0].value == 0);

    /* A button the sink already holds is not pressed again with the move. */
    CHECK(send(&down, 1u, &script) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(moved_down, 2u, &script) == 0 && read_events(absolute[0]) == 3u);
    release_everything();

    /* Nor does such a press restore a hold on the mouse's clone. */
    CHECK(forward_key(mouse, BTN_LEFT, 1) == 0 && read_events(outputs[output].fds[0]) == 2u);
    CHECK(send(&up, 1u, &script) == 0 && read_events(outputs[output].fds[0]) == 2u);
    CHECK(send(moved_down, 2u, &script) == 0 && read_events(outputs[output].fds[0]) == 0u);
    CHECK(read_events(absolute[0]) == 5u && events[3].value == 1);
    CHECK(applied.holders[BTN_LEFT] == 1u && enqueued.holders[BTN_LEFT] == 1u);
    release_everything();
    (void)read_events(absolute[0]);
    uinput_abs_fd = -1;
    close_source(mouse);
    ksi_linux_forward_collect(true);
    return true;
}

/* Only keyboard keys of keyboards are sink holders: a button held on a clone
 * does not stop a synthetic click from releasing on the sink. A physical
 * X-button release ends a synthetic hold of its alias. */
static bool test_buttons_across_devices(void)
{
    uint64_t mouse = ksi_linux_forward_open(MOUSE, false);
    const ksi_synth_owner script = { .connection_id = 15u };
    const ksi_input click[] = { button_input(KSI_MOUSE_LEFT_DOWN), button_input(KSI_MOUSE_LEFT_UP) };
    const ksi_input x1 = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .mouse_data = KSI_XBUTTON1 << 16, .flags = KSI_MOUSE_X_DOWN } };

    CHECK(forward_key(mouse, BTN_LEFT, 1) == 0);
    CHECK(send(click, 2u, &script) == 0);
    CHECK(sink_keys(2u, (const uint16_t[]){ BTN_LEFT, BTN_LEFT }, (const int32_t[]){ 1, 0 }));

    CHECK(send(&x1, 1u, &script) == 0 && sink_keys(1u, (const uint16_t[]){ BTN_SIDE }, (const int32_t[]){ 1 }));
    CHECK(forward_key(mouse, BTN_BACK, 1) == 0 && forward_key(mouse, BTN_BACK, 0) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ BTN_SIDE }, (const int32_t[]){ 0 }) && !logical(BTN_SIDE));

    close_source(mouse);
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* A dead owner keeps only its mouse releases, as for keys. */
static bool test_dead_owner_mouse(void)
{
    uint64_t mouse = ksi_linux_forward_open(MOUSE, false);
    const ksi_synth_owner remap = { .target = mouse, .connection_id = 16u,
        .hook_type = KSI_HOOK_MOUSE, .source_type = EV_KEY, .source_code = BTN_BACK };
    const ksi_synth_owner script = { .connection_id = 17u };
    const ksi_input press = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .dx = 3, .flags = KSI_MOUSE_MOVE | KSI_MOUSE_LEFT_DOWN } };
    const ksi_input up = button_input(KSI_MOUSE_LEFT_UP);

    close_source(mouse);
    CHECK(send(&press, 1u, &remap) == 0 && read_events(generic[0]) == 0u && !logical(BTN_LEFT));
    CHECK(send(&press, 1u, &script) == 0 && read_events(generic[0]) == 3u);
    CHECK(send(&up, 1u, &remap) == 0);
    CHECK(sink_keys(1u, (const uint16_t[]){ BTN_LEFT }, (const int32_t[]){ 0 }));
    ksi_linux_forward_collect(true);
    release_everything();
    return true;
}

/* A tap of a key the user holds releases and presses it again, leaving it held. */
static bool test_tap_of_held_key(void)
{
    uint64_t keyboard = ksi_linux_forward_open(PLAIN, true);
    const ksi_synth_owner script = { .connection_id = 18u };
    const ksi_input e_acute = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = 0xE9u, .flags = KSI_KEY_UNICODE } };
    int32_t values[2];
    size_t seen = 0u;

    CHECK(forward_key(keyboard, KEY_E, 1) == 0 && read_events(generic[0]) == 2u);
    CHECK(send(&e_acute, 1u, &script) == 0);
    for (size_t count; (count = read_events(generic[0])) != 0u; )
        for (size_t i = 0u; i < count; i++)
            if (events[i].type == EV_KEY && events[i].code == KEY_E && seen < 2u) values[seen++] = events[i].value;
    CHECK(seen == 2u && values[0] == 0 && values[1] == 1 && sink_down(KEY_E));
    close_source(keyboard);
    release_everything();
    return true;
}

int main(void)
{
    /* A broken sink is a pipe without a reader, as the daemon ignores. */
    signal(SIGPIPE, SIG_IGN);
    if (pipe2(generic, O_CLOEXEC | O_NONBLOCK) != 0 || pipe2(absolute, O_CLOEXEC | O_NONBLOCK) != 0) return 1;
    uinput_fd = generic[1];
    ksi_linux_forward_attach_sink(generic[1]);
    if (!test_forwarding_and_synthesis() || !test_plain_keyboard_has_no_clone()
        || !test_wheel_state_is_per_device()
        || !test_grab_end_releases_source_holds()
        || !test_physical_release()
        || !test_displaced_hold_ends_with_grab()
        || !test_repeats_and_unheld_releases()
        || !test_early_end_keeps_admitted_state()
        || !test_retired_clone_removed_after_drain()
        || !test_button_alias_displacement()
        || !test_displaced_hold_restores()
        || !test_sink_keeps_order()
        || !test_mixed_batch_and_unplug()
        || !test_owner_lifetimes()
        || !test_unicode_entry_is_transient()
        || !test_release_all_includes_sources()
        || !test_switch_state()
        || !test_grab_end_finishes_open_reports()
        || !test_close_keeps_queue_order()
        || !test_absolute_button_routing()
        || !test_buttons_across_devices()
        || !test_dead_owner_mouse()
        || !test_tap_of_held_key()
        || !test_sink_failure()) return 1;
    /* keyd skips devices with its vendor identifier, so a clone of its
     * output must keep it; fake_create checks the vendor. */
    uint64_t keyd = ksi_linux_forward_open(KEYD, true);
    if (keyd == 0u || !metadata_ok) return 1;
    close_source(keyd);
    ksi_linux_forward_collect(true);
    uinput_fd = -1;
    puts("PASS physical forwarding identity, routing, lifetime, recovery and the shared keyboard sink");
    return 0;
}
