#include <libevdev/libevdev.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "device_codec.h"
#include "internal/linux_forward.h"
#include "platform/linux_wheel.h"

bool g_verbose = false;
static int fake_next_event(struct libevdev *device, unsigned int flags, struct input_event *event);
static int fake_has_event_pending(struct libevdev *device);
static int fake_libevdev_new(int fd, struct libevdev **device);
static void fake_libevdev_free(struct libevdev *device);
static const struct input_absinfo *fake_get_abs_info(const struct libevdev *device, unsigned int code);
static int fake_open(const char *path, int flags, ...);
static int fake_ioctl(int fd, unsigned long request, ...);
static uint64_t fake_forward_open(int fd, bool keyboard);
static bool fake_has_clone(uint64_t target);
static bool fake_sink_ready(void);
static uint64_t fake_forward_end_grab(uint64_t target, uint8_t *kept);
static bool fake_forward_failed(uint64_t target, ksi_forward_view view);
static bool fake_take_failure(void);
static void fake_forward_close(uint64_t target);
static void fake_apply_close(uint64_t target);
static int fake_close(int fd);
static uint64_t fake_forward_target_for_path(const char *path);
static void fake_forward_sync_switches(uint64_t target);
static int fake_probe_grabbed(int fd);
static int fake_output_write(int fd, const struct input_event *written, size_t count);
static void fake_add_key_state(uint64_t target, uint8_t *keys, size_t size);
#define libevdev_next_event fake_next_event
#define libevdev_has_event_pending fake_has_event_pending
#define libevdev_new_from_fd fake_libevdev_new
#define libevdev_free fake_libevdev_free
#define libevdev_get_abs_info fake_get_abs_info
#define open fake_open
#define ioctl fake_ioctl
#define ksi_linux_forward_open fake_forward_open
#define ksi_linux_forward_has_clone fake_has_clone
#define ksi_linux_forward_sink_ready fake_sink_ready
#define ksi_linux_forward_end_grab fake_forward_end_grab
#define ksi_linux_forward_failed fake_forward_failed
#define ksi_linux_forward_take_failure fake_take_failure
#define ksi_linux_forward_close fake_forward_close
#define ksi_linux_forward_apply_close fake_apply_close
#define close fake_close
#define ksi_linux_forward_target_for_path fake_forward_target_for_path
#define ksi_linux_forward_sync_switches fake_forward_sync_switches
#define ksi_linux_output_probe_grabbed fake_probe_grabbed
#define ksi_linux_output_write fake_output_write
#define ksi_linux_forward_add_key_state fake_add_key_state
#include "../src/platform/linux_devices.c"
#undef libevdev_next_event
#undef libevdev_has_event_pending
#undef libevdev_new_from_fd
#undef libevdev_free
#undef libevdev_get_abs_info
#undef open
#undef ioctl
#undef ksi_linux_forward_open
#undef ksi_linux_forward_has_clone
#undef ksi_linux_forward_sink_ready
#undef ksi_linux_forward_end_grab
#undef ksi_linux_forward_failed
#undef ksi_linux_forward_take_failure
#undef ksi_linux_forward_close
#undef ksi_linux_forward_apply_close
#undef close
#undef ksi_linux_forward_target_for_path
#undef ksi_linux_forward_sync_switches
#undef ksi_linux_output_probe_grabbed
#undef ksi_linux_output_write
#undef ksi_linux_forward_add_key_state

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); return false; \
} } while (0)

static unsigned int expected_flags[8];
static int results[8];
static struct input_event events[8];
static size_t step;
static size_t step_count;
static bool wrong_flag;
static size_t observations;
static size_t hooks;
static ksi_keyboard_hook_event keyboard_event;
static ksi_mouse_hook_event mouse_event;
static ksi_raw_input_event raw_event;
static uint64_t next_forward_target = 1u;
static size_t forward_opens, forward_closes, switch_syncs, grab_calls, probes;
static bool forward_failed, grab_busy, failure_pending_fake;
static uint64_t failed_target;
static int probe_result = 1;
/* Probed nodes at /fake-slot/N answer as grabbed when bit N is set here. */
static unsigned int probe_grabbed_slots;
/* When not negative, the desktop sets fake device 2's LEDs to this while a
 * grab is being released. */
static int compositor_leds = -1;
/* A probe that queues a key press, as one made while it runs would be. */
static bool probe_presses_key;
/* When not negative, releasing any fake grab sets every fake device's LEDs to
 * this, as the console keyboard handler does. */
static int console_leds = -1;
/* Kernel key and LED state per fake fd, as EVIOCGKEY and EVIOCGLED report it. */
#define FAKE_FDS 4
static unsigned long held_keys[FAKE_FDS][KSI_BIT_ARRAY_LENGTH(KEY_MAX)];
static unsigned char fake_leds[FAKE_FDS];
static size_t forwarded_events;
/* Whether a source opened next gets a clone, and whether the sink works. */
static bool clone_fake = true, sink_ready_fake = true;
static bool last_open_keyboard;
static uint32_t forwarded_hook_type;
static ksi_forward_packet forwarded_replay;
static char delivery_order[8];
static size_t delivery_count;

static uint64_t fake_forward_open(int fd, bool keyboard)
{
    (void)fd;
    last_open_keyboard = keyboard;
    forward_opens++;
    return next_forward_target++;
}
/* An ended grab keeps the holds in fake_kept. */
static uint8_t fake_kept[KSI_KEY_BITMAP_BYTES];
static uint64_t fake_forward_end_grab(uint64_t target, uint8_t *kept)
{
    memcpy(kept, fake_kept, sizeof(fake_kept));
    return target != 0u ? target + 1000u : 0u;
}
static bool fake_forward_failed(uint64_t target, ksi_forward_view view)
{
    (void)view;
    return target == 0u || forward_failed || target == failed_target;
}
static bool fake_take_failure(void)
{
    bool pending = failure_pending_fake;
    failure_pending_fake = false;
    return pending;
}
static void fake_forward_close(uint64_t target) { if (target != 0u) forward_closes++; }
static void fake_apply_close(uint64_t target) { (void)target; }
static size_t queued_closes;
static void queue_close(void *context, uint64_t target) { (void)context; (void)target; queued_closes++; }
static uint64_t fake_forward_target_for_path(const char *path)
{
    return path != NULL && strcmp(path, "/dev/null") == 0 ? 88u : 0u;
}
static bool fake_has_clone(uint64_t target) { return target != 0u && clone_fake; }
static bool fake_sink_ready(void) { return sink_ready_fake; }
static void fake_forward_sync_switches(uint64_t target) { if (target != 0u) switch_syncs++; }
static void set_long_bit(unsigned long *bits, unsigned int bit);

static int fake_slot(int fd);

static int fake_probe_grabbed(int fd)
{
    int slot = fake_slot(fd);
    bool fake = slot >= 0 && slot < FAKE_FDS;

    probes++;
    if (fake && (probe_grabbed_slots & (1u << slot)) != 0u) return 1;
    if (fake && console_leds >= 0) fake_leds[slot] = (unsigned char)console_leds;
    if (probe_presses_key) {
        probe_presses_key = false;
        events[step_count++] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 1 };
        events[step_count++] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
        set_long_bit(held_keys[0], KEY_A);
    }
    return probe_result;
}

static int fake_slot(int fd) { return fd == 12345 ? 0 : fd - 10; }

static int fake_output_write(int fd, const struct input_event *written, size_t count)
{
    int slot = fake_slot(fd);

    if (slot < 0 || slot >= FAKE_FDS) return -1;
    for (size_t i = 0u; i < count; i++)
        if (written[i].type == EV_LED)
            fake_leds[slot] = (unsigned char)((fake_leds[slot] & ~(1u << written[i].code))
                | (written[i].value != 0 ? 1u << written[i].code : 0u));
    return 0;
}

/* What every clone's queued output holds. */
static uint8_t fake_clone_output[KSI_KEY_BITMAP_BYTES];
static void fake_add_key_state(uint64_t target, uint8_t *keys, size_t size)
{
    (void)target;
    for (size_t i = 0u; i < size; i++) keys[i] |= fake_clone_output[i];
}

static int fake_has_event_pending(struct libevdev *device)
{
    (void)device;
    return step < step_count ? 1 : 0;
}
static int fake_libevdev_new(int fd, struct libevdev **device)
{
    (void)fd;
    *device = (struct libevdev *)&step;
    return 0;
}
static void fake_libevdev_free(struct libevdev *device) { (void)device; }
static const struct input_absinfo *fake_get_abs_info(const struct libevdev *device, unsigned int code)
{
    (void)device; (void)code;
    return NULL;
}

/* Paths under /fake/ open as one event node that fake_node describes. */
#define FAKE_NODE_FD 900
static struct {
    const char *name, *phys;
    struct input_id id;
    unsigned long ev[KSI_BIT_ARRAY_LENGTH(EV_MAX)];
    unsigned long key[KSI_BIT_ARRAY_LENGTH(KEY_MAX)];
    unsigned long rel[KSI_BIT_ARRAY_LENGTH(REL_MAX)];
    unsigned long abs[KSI_BIT_ARRAY_LENGTH(ABS_MAX)];
} fake_node;

static int fake_open(const char *path, int flags, ...)
{
    if (strncmp(path, "/fake-slot/", 11u) == 0) return 10 + atoi(path + 11);
    return strncmp(path, "/fake/", 6u) == 0 ? FAKE_NODE_FD : open(path, flags);
}

/* Fake descriptors were never opened. */
static int fake_close(int fd)
{
    return fd == FAKE_NODE_FD || fd == 12345 || (fd >= 10 && fd < 10 + FAKE_FDS) ? 0 : close(fd);
}

static int fake_node_ioctl(unsigned long request, void *out)
{
    unsigned int nr = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);
    const unsigned long *bits = nr == 0x20u ? fake_node.ev : nr == 0x20u + EV_KEY ? fake_node.key
        : nr == 0x20u + EV_REL ? fake_node.rel : nr == 0x20u + EV_ABS ? fake_node.abs : NULL;

    if (request == EVIOCGID) {
        memcpy(out, &fake_node.id, sizeof(fake_node.id));
        return 0;
    }
    if (_IOC_TYPE(request) == 'E' && (nr == 0x06u || nr == 0x07u)) {
        snprintf(out, size, "%s", nr == 0x06u ? fake_node.name : fake_node.phys);
        return 0;
    }
    if (_IOC_TYPE(request) == 'E' && bits != NULL) {
        memcpy(out, bits, size);
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static void set_long_bit(unsigned long *bits, unsigned int bit)
{
    bits[KSI_BIT_WORD(bit)] |= KSI_BIT_MASK(bit);
}

static void clear_long_bit(unsigned long *bits, unsigned int bit)
{
    bits[KSI_BIT_WORD(bit)] &= ~KSI_BIT_MASK(bit);
}

static void count_panic(void *context)
{
    (*(size_t *)context)++;
}

/* fd 12345 stands for a device whose grab this harness controls; fds 10 and
 * up index the per-device kernel state above. */
static int fake_ioctl(int fd, unsigned long request, ...)
{
    int slot = fake_slot(fd);
    va_list args;
    void *out;

    va_start(args, request);
    out = va_arg(args, void *);
    va_end(args);
    if (fd == FAKE_NODE_FD) return fake_node_ioctl(request, out);
    if (slot < 0 || slot >= FAKE_FDS) { errno = EBADF; return -1; }
    if (request == EVIOCGRAB && fd == 12345) {
        grab_calls++;
        if (grab_busy) { errno = EBUSY; return -1; }
        if (out == NULL && console_leds >= 0) fake_leds[0] = (unsigned char)console_leds;
        if (out == NULL && compositor_leds >= 0) fake_leds[2] = (unsigned char)compositor_leds;
        return 0;
    }
    if (request == EVIOCGKEY(sizeof(held_keys[0]))) {
        memcpy(out, held_keys[slot], sizeof(held_keys[slot]));
        return 0;
    }
    if (request == EVIOCGLED(sizeof(fake_leds[0]))) {
        memcpy(out, &fake_leds[slot], sizeof(fake_leds[slot]));
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static void capture_raw(void *context, const ksi_raw_input_event *event)
{
    (*(size_t *)context)++;
    raw_event = *event;
}

static int fake_next_event(struct libevdev *device, unsigned int flags, struct input_event *event)
{
    (void)device;
    if (step >= step_count) return -EAGAIN;
    if (flags != expected_flags[step]) wrong_flag = true;
    *event = events[step];
    return results[step++];
}

static void capture(void *context, uint32_t type, const void *event, size_t size)
{
    (void)size;
    if (context == &observations) observations++; else hooks++;
    if (type == KSI_HOOK_KEYBOARD) keyboard_event = *(const ksi_keyboard_hook_event *)event;
    else mouse_event = *(const ksi_mouse_hook_event *)event;
}

static ksi_forward_packet last_replay;

static void capture_hook(void *context, uint32_t type, const void *event, size_t size,
    const ksi_forward_packet *replay)
{
    capture(context, type, event, size);
    last_replay = *replay;
    if (delivery_count < sizeof(delivery_order)) delivery_order[delivery_count++] = 'H';
}

/* Admits a forwarded packet unless refuse_forward is set. */
static bool refuse_forward;
static bool capture_forward(void *context, uint32_t hook_type, const ksi_forward_packet *replay)
{
    (void)context;
    if (refuse_forward) return false;
    forwarded_events++;
    forwarded_hook_type = hook_type;
    forwarded_replay = *replay;
    if (delivery_count < sizeof(delivery_order)) delivery_order[delivery_count++] = 'F';
    return true;
}

static bool test_sync_repairs_lost_release(void)
{
    ksi_linux_tracked_device device = {
        .fd = -1, .evdev = (struct libevdev *)&step, .device_id = 4u,
        .grabbed = true, .keyboard_candidate = true,
        .has_pending_rel = true, .pending_rel_x = 17,
        .forward_report_lanes = KSI_FORWARD_REPORT_KEYBOARD,
    };
    step = 0u; step_count = 4u; wrong_flag = false; hooks = 0u;
    expected_flags[0] = LIBEVDEV_READ_FLAG_NORMAL;
    expected_flags[1] = LIBEVDEV_READ_FLAG_SYNC;
    expected_flags[2] = LIBEVDEV_READ_FLAG_SYNC;
    expected_flags[3] = LIBEVDEV_READ_FLAG_NORMAL;
    results[0] = results[1] = LIBEVDEV_READ_STATUS_SYNC;
    results[2] = results[3] = -EAGAIN;
    events[0] = (struct input_event){ .type = EV_SYN, .code = SYN_DROPPED };
    events[1] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 0 };
    ksi_linux_devices_set_hook_event_callback(capture_hook, &hooks);
    process_device_events(&device);
    CHECK(step == 4u && !wrong_flag && !device.synchronizing);
    CHECK(hooks == 1u && keyboard_event.message == KSI_MESSAGE_KEY_UP);
    CHECK((keyboard_event.flags & KSI_KEYBOARD_HOOK_SYNCHRONIZED) != 0u);
    CHECK(!device.has_pending_rel && device.pending_rel_x == 0);
    /* Fragments forwarded before the drop still need the burst's SYN. */
    CHECK((device.forward_report_lanes & KSI_FORWARD_REPORT_KEYBOARD) != 0u);

    /* The admission peeker must preserve the same synchronization contract. */
    step = 0u; wrong_flag = false;
    CHECK(buffer_next_device_event(&device));
    CHECK(device.has_buffered_event && device.buffered_event.code == KEY_A);
    CHECK(!wrong_flag && step == 2u);
    return true;
}

/* A keystroke's scan code, key and report end travel as one packet. A report
 * with two keys keeps its own report end, so a blocked second key cannot leave
 * the first unsynced on the clone. */
static bool test_keystroke_is_one_packet(void)
{
    ksi_linux_tracked_device device = { .fd = -1, .evdev = (struct libevdev *)&step,
        .device_id = 5u, .grabbed = true, .keyboard_candidate = true, .forwarding_target = 9u };

    memset(expected_flags, 0, sizeof(expected_flags));
    memset(results, 0, sizeof(results));
    events[0] = (struct input_event){ .type = EV_MSC, .code = MSC_SCAN, .value = 30 };
    events[1] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 1 };
    events[2] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    step = 0u; step_count = 3u; hooks = forwarded_events = 0u;
    ksi_linux_devices_set_hook_event_callback(capture_hook, &hooks);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    process_device_events(&device);
    CHECK(hooks == 1u && forwarded_events == 0u && last_replay.flags == KSI_FORWARD_REPORT_END);
    CHECK(last_replay.count == 2u && last_replay.events[0].type == EV_MSC
        && last_replay.events[1].code == KEY_A);

    events[0] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 0 };
    events[1] = (struct input_event){ .type = EV_KEY, .code = KEY_B, .value = 1 };
    step = 0u; hooks = 0u;
    process_device_events(&device);
    CHECK(hooks == 2u && last_replay.flags == 0u && last_replay.events[0].code == KEY_B);
    CHECK(forwarded_events == 1u && forwarded_replay.events[0].type == EV_SYN);

    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    return true;
}

static bool test_observation_without_grab(void)
{
    ksi_linux_tracked_device device = { .keyboard_candidate = true, .device_id = 7u };
    struct input_event key = { .type = EV_KEY, .code = KEY_A, .value = 1 };
    observations = hooks = 0u;
    ksi_linux_devices_set_observer_callback(capture, NULL, &observations);
    dispatch_keyboard_event(&device, &key, 0u, false);
    CHECK(observations == 1u && hooks == 0u && !device.grabbed);
    CHECK(keyboard_event.device_id == 7u);
    key.value = 2;
    dispatch_keyboard_event(&device, &key, 0u, false);
    CHECK((keyboard_event.flags & KSI_KEYBOARD_HOOK_REPEAT) != 0u && hooks == 0u);
    return true;
}

static bool test_high_resolution_wheel(void)
{
    ksi_linux_tracked_device device = { .high_resolution_wheel = true, .mouse_hook_candidate = true };
    struct input_event wheel = { .type = EV_REL, .code = REL_WHEEL, .value = -1 };
    observations = 0u;
    dispatch_relative_event(&device, &wheel, 0u, false);
    CHECK(observations == 0u);
    wheel.code = REL_WHEEL_HI_RES; wheel.value = -60;
    dispatch_relative_event(&device, &wheel, 0u, false);
    CHECK(observations == 1u && (int16_t)(mouse_event.mouse_data >> 16) == -60);
    int32_t remainder = 0;
    CHECK(ksi_linux_wheel_steps(-60, &remainder) == 0 && remainder == -60);
    CHECK(ksi_linux_wheel_steps(-60, &remainder) == -1 && remainder == 0);
    CHECK(ksi_linux_wheel_steps(30, &remainder) == 0);
    CHECK(ksi_linux_wheel_steps(-60, &remainder) == 0 && remainder == -30);
    CHECK(ksi_linux_wheel_steps(-210, &remainder) == -2 && remainder == 0);
    return true;
}

static bool test_device_metadata_codec(void)
{
    ksi_device_info original = {
        .struct_size = sizeof(original), .device_id = 11u,
        .capabilities = KSI_DEVICE_KEYBOARD | KSI_DEVICE_CAN_INTERCEPT_KEYBOARD,
        .bus_type = 3u, .vendor = 0x1234u, .product = 0x5678u, .version = 2u,
        .name = "Keyboard", .path = "/dev/input/event4", .physical = "usb-port/input0", .unique = "serial",
        .axis_count = 1u,
        .axes = {{ .struct_size = sizeof(ksi_device_axis_info), .code = ABS_X,
            .minimum = -100, .maximum = 1500, .fuzz = 2, .flat = 5, .resolution = 40 }},
        .button_count = 3u,
        .button_codes = { BTN_SOUTH, BTN_TRIGGER_HAPPY1, BTN_LEFT },
    };
    ksi_device_info decoded;
    uint8_t wire[KSI_DEVICE_INFO_WIRE_SIZE];
    ksi_device_encode(wire, &original);
    CHECK(ksi_device_decode(wire, sizeof(wire), &decoded));
    CHECK(memcmp(&decoded, &original, sizeof(original)) == 0);
    /* The one descent in joydev order must land below the first code. */
    original.button_codes[2] = BTN_EAST;
    ksi_device_encode(wire, &original);
    CHECK(!ksi_device_decode(wire, sizeof(wire), &decoded));
    original.button_codes[2] = BTN_LEFT;
    ksi_device_encode(wire, &original);
    memset(wire + 24u, 'x', KSI_DEVICE_NAME_CAPACITY);
    CHECK(!ksi_device_decode(wire, sizeof(wire), &decoded));
    return true;
}

static bool test_gamepad_classification(void)
{
    unsigned long key_bits[KSI_BIT_ARRAY_LENGTH(KEY_MAX)] = { 0 };
    unsigned long abs_bits[KSI_BIT_ARRAY_LENGTH(ABS_MAX)] = { 0 };
    ksi_device_info public = { .struct_size = sizeof(public) };

    set_long_bit(abs_bits, ABS_X);
    CHECK(!looks_like_gamepad(key_bits, abs_bits));
    set_long_bit(key_bits, BTN_SOUTH);
    CHECK(looks_like_gamepad(key_bits, abs_bits));
    clear_long_bit(abs_bits, ABS_X);
    CHECK(!looks_like_gamepad(key_bits, abs_bits));
    set_long_bit(abs_bits, ABS_X);
    set_long_bit(key_bits, BTN_TOOL_PEN);
    clear_long_bit(key_bits, BTN_SOUTH);
    CHECK(!looks_like_gamepad(key_bits, abs_bits));
    set_long_bit(key_bits, BTN_SOUTH);

    set_long_bit(key_bits, BTN_LEFT);
    set_long_bit(key_bits, BTN_TRIGGER_HAPPY1);
    collect_gamepad_buttons(key_bits, &public);
    CHECK(public.button_count == 4u);
    CHECK(public.button_codes[0] == BTN_SOUTH && public.button_codes[1] == BTN_TOOL_PEN
        && public.button_codes[2] == BTN_TRIGGER_HAPPY1 && public.button_codes[3] == BTN_LEFT);
    return true;
}

static bool test_gamepad_state_codec(void)
{
    ksi_gamepad_state original = {
        .struct_size = sizeof(original), .device_id = 7u, .device_generation = 42u,
        .button_count = 9u, .axis_count = 2u,
        .buttons = { 0x81u, 0x01u },
        .axes = {{ .struct_size = sizeof(ksi_gamepad_axis_state), .code = ABS_X, .value = -32768 },
            { .struct_size = sizeof(ksi_gamepad_axis_state), .code = ABS_HAT0Y, .value = 1 }},
    };
    ksi_gamepad_state decoded;
    uint8_t wire[KSI_GAMEPAD_STATE_MAX_PAYLOAD_SIZE];
    size_t size = ksi_gamepad_state_encode(wire, &original);
    CHECK(size == KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE + 2u * KSI_GAMEPAD_AXIS_WIRE_SIZE);
    CHECK(ksi_gamepad_state_decode(wire, size, &decoded));
    CHECK(memcmp(&decoded, &original, sizeof(original)) == 0);
    CHECK(!ksi_gamepad_state_decode(wire, size - 1u, &decoded));
    wire[25u] |= 0x02u;
    CHECK(!ksi_gamepad_state_decode(wire, size, &decoded));
    return true;
}

/* The listing and the state read select gamepads out of the tracked set. A
 * device node that answers no ioctl stands in for hardware here: the reply is
 * still well formed, with nothing pressed and no axis read. */
static bool test_gamepad_selection(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    tracked_device_count = 2u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    tracked_devices[0].fd = fd;
    tracked_devices[0].device_id = 3u;
    tracked_devices[0].public_info = (ksi_device_info){
        .struct_size = sizeof(ksi_device_info), .device_id = 3u,
        .capabilities = KSI_DEVICE_KEYBOARD, .name = "Keyboard", .path = "/dev/input/event0",
    };
    tracked_devices[1].fd = fd;
    tracked_devices[1].device_id = 4u;
    tracked_devices[1].public_info = (ksi_device_info){
        .struct_size = sizeof(ksi_device_info), .device_id = 4u,
        .capabilities = KSI_DEVICE_GAMEPAD | KSI_DEVICE_ABSOLUTE, .name = "Pad",
        .path = "/dev/input/event1", .physical = "usb-0000:00:14.0-3/input0", .unique = "serial",
        .axis_count = 1u, .button_count = 2u, .button_codes = { BTN_SOUTH, BTN_EAST },
        .axes = {{ .struct_size = sizeof(ksi_device_axis_info), .code = ABS_X, .maximum = 255 }},
    };

    /* A third device makes the listing order observable: it sits after the pad
     * in discovery order but on a lower event node, so it is reported first. */
    tracked_device_count = 3u;
    memset(&tracked_devices[2], 0, sizeof(tracked_devices[2]));
    tracked_devices[2].fd = fd;
    tracked_devices[2].device_id = 5u;
    snprintf(tracked_devices[2].path, sizeof(tracked_devices[2].path), "/dev/input/event0");
    tracked_devices[2].public_info = (ksi_device_info){
        .struct_size = sizeof(ksi_device_info), .device_id = 5u,
        .capabilities = KSI_DEVICE_GAMEPAD, .name = "Stick", .path = "/dev/input/event0",
    };
    snprintf(tracked_devices[1].path, sizeof(tracked_devices[1].path), "/dev/input/event1");

    ksi_device_info entries[KSI_DEVICE_LIST_PAGE_SIZE];
    uint32_t next = 1u;
    CHECK(ksi_linux_gamepads_list(0u, entries, KSI_DEVICE_LIST_PAGE_SIZE, &next) == 2u);
    CHECK(next == 0u && entries[0].device_id == 5u && entries[1].device_id == 4u);
    CHECK(ksi_linux_gamepads_list(1u, entries, KSI_DEVICE_LIST_PAGE_SIZE, &next) == 1u);
    CHECK(next == 0u && entries[0].device_id == 4u && strcmp(entries[0].name, "Pad") == 0);
    CHECK(entries[0].button_count == 2u && entries[0].axes[0].maximum == 255);
    CHECK(entries[0].path[0] == '\0' && entries[0].physical[0] == '\0' && entries[0].unique[0] == '\0');
    CHECK(ksi_linux_devices_list(0u, entries, KSI_DEVICE_LIST_PAGE_SIZE, &next) == 3u);
    CHECK(strcmp(entries[1].path, "/dev/input/event1") == 0);

    ksi_gamepad_state state;
    CHECK(!ksi_linux_gamepad_state(3u, &state));
    CHECK(!ksi_linux_gamepad_state(99u, &state));
    CHECK(ksi_linux_gamepad_state(4u, &state));
    CHECK(state.device_id == 4u && state.button_count == 2u && state.axis_count == 0u);
    CHECK(state.buttons[0] == 0u && state.device_generation == ksi_linux_devices_generation());
    tracked_devices[1].fd = -1;
    CHECK(!ksi_linux_gamepad_state(4u, &state));
    tracked_device_count = 0u;
    close(fd);
    return true;
}

static bool test_raw_touchpad_observation(void)
{
    ksi_linux_tracked_device device = {
        .device_id = 33u, .raw_observation_candidate = true, .event_clock_monotonic = true,
    };
    struct input_event event = { .type = EV_ABS, .code = ABS_MT_POSITION_X, .value = 1920 };
    uint64_t fallback = 0;
    size_t count = 0;
    ksi_linux_devices_set_raw_observer_callback(capture_raw, &count);
    handle_input_event(&device, &event, &fallback);
    CHECK(count == 1u && raw_event.device_id == 33u && raw_event.value == 1920);
    CHECK(raw_event.type == EV_ABS && raw_event.code == ABS_MT_POSITION_X);
    CHECK(raw_event.flags == KSI_RAW_INPUT_MONOTONIC_TIME && !device.grabbed);
    event.type = EV_KEY; event.code = BTN_TOOL_PEN; event.value = 1;
    device.synchronizing = true;
    handle_input_event(&device, &event, &fallback);
    CHECK(count == 2u && (raw_event.flags & KSI_RAW_INPUT_SYNCHRONIZED) != 0u);
    event.type = EV_SYN; event.code = SYN_REPORT; event.value = 0;
    handle_input_event(&device, &event, &fallback);
    CHECK(count == 3u && raw_event.type == EV_SYN);
    device.injected_source = true;
    handle_input_event(&device, &event, &fallback);
    CHECK(count == 3u);
    ksi_linux_devices_set_raw_observer_callback(NULL, NULL);
    return true;
}

static bool test_forwarding_preserves_raw_input(void)
{
    ksi_linux_tracked_device device = {
        .device_id = 55u, .forwarding_target = 91u, .grabbed = true,
        .keyboard_candidate = true, .mouse_candidate = true,
        .mouse_hook_candidate = true, .mouse_block_candidate = true,
        .abs_x_max = 4095, .abs_y_max = 4095,
    };
    struct input_event raw = { .type = EV_KEY, .code = KEY_A, .value = 2 };
    dispatch_keyboard_event(&device, &raw, 0u, false);
    CHECK(last_replay.target == 91u && last_replay.count == 1u);
    CHECK(last_replay.events[0].code == KEY_A && last_replay.events[0].value == 2);
    raw.code = BTN_BACK; raw.value = 1;
    dispatch_mouse_button_event(&device, &raw, 0u, false);
    CHECK(mouse_event.message == KSI_MESSAGE_X_BUTTON_DOWN);
    CHECK(last_replay.events[0].code == BTN_BACK);
    raw.type = EV_ABS; raw.code = ABS_X; raw.value = 3000;
    queue_absolute_motion(&device, &raw, 0u, false);
    raw.code = ABS_Y; raw.value = 2000;
    queue_absolute_motion(&device, &raw, 0u, false);
    dispatch_pending_mouse_move(&device, false);
    CHECK(mouse_event.x == scale_abs_axis(3000, 0, 4095));
    CHECK(last_replay.events[0].value == 3000 && last_replay.events[1].value == 2000);
    CHECK(last_replay.events[0].type == EV_ABS && last_replay.count == 2u);
    /* An absolute report carries both axes, so the clone never pairs a new X
     * with a Y it missed. */
    raw.code = ABS_X; raw.value = 3100;
    queue_absolute_motion(&device, &raw, 0u, false);
    dispatch_pending_mouse_move(&device, false);
    CHECK(last_replay.count == 2u && last_replay.events[1].code == ABS_Y
        && last_replay.events[1].value == 2000);
    raw.type = EV_REL; raw.code = REL_X; raw.value = -43;
    queue_relative_motion(&device, &raw, 0u, false);
    dispatch_pending_mouse_move(&device, false);
    CHECK(last_replay.count == 1u && last_replay.events[0].type == EV_REL
        && last_replay.events[0].value == -43 && last_replay.flags == KSI_FORWARD_CLONE);

    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    forwarded_events = delivery_count = 0u;
    uint64_t fallback = 0u;
    raw = (struct input_event){ .type = EV_REL, .code = REL_X, .value = 7 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == 0u && delivery_count == 0u);
    raw.code = REL_DIAL; raw.value = 3;
    handle_input_event(&device, &raw, &fallback);
    CHECK(delivery_count == 2u && delivery_order[0] == 'H' && delivery_order[1] == 'F');
    CHECK(last_replay.events[0].code == REL_X && last_replay.events[0].value == 7);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.target == 91u);
    CHECK(forwarded_replay.events[0].code == REL_DIAL);

    raw = (struct input_event){ .type = EV_REL, .code = REL_Z, .value = -2 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.events[0].code == REL_Z);
    raw = (struct input_event){ .type = EV_KEY, .code = BTN_TASK, .value = 1 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.events[0].code == BTN_TASK);
    raw = (struct input_event){ .type = EV_SW, .code = SW_LID, .value = 1 };
    handle_input_event(&device, &raw, &fallback);
    /* Only a keyboard's keys and scan codes go to the sink. */
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.events[0].type == EV_SW
        && forwarded_replay.flags == KSI_FORWARD_CLONE);
    raw = (struct input_event){ .type = EV_MSC, .code = MSC_SCAN, .value = 30 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_KEYBOARD && forwarded_replay.events[0].type == EV_MSC);
    CHECK(forwarded_replay.flags == 0u);
    size_t before_sync = forwarded_events;
    raw = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == before_sync + 2u);
    CHECK(forwarded_replay.flags == KSI_FORWARD_CLONE && forwarded_replay.events[0].type == EV_SYN);
    CHECK(device.forward_report_lanes == 0u);

    /* Motion alone in a report carries the SYN, sparing a separate fragment. */
    before_sync = forwarded_events;
    raw = (struct input_event){ .type = EV_REL, .code = REL_Y, .value = 5 };
    handle_input_event(&device, &raw, &fallback);
    raw = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == before_sync
        && last_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE));
    CHECK(last_replay.count == 1u && last_replay.events[0].code == REL_Y);

    size_t before_block = forwarded_events;
    block_input_mask = KSI_BLOCK_MOUSE;
    raw = (struct input_event){ .type = EV_REL, .code = REL_Z, .value = 1 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == before_block);
    /* A switch is device state, not input, so blocking keeps it flowing. */
    block_input_mask = KSI_BLOCK_KEYBOARD;
    raw = (struct input_event){ .type = EV_SW, .code = SW_LID, .value = 0 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == ++before_block);
    block_input_mask = 0u;

    /* A combined compositor pointer grabbed for its keyboard still forwards
     * mouse buttons which cannot safely enter the raw mouse hook. */
    device.mouse_hook_candidate = false;
    block_input_mask = KSI_BLOCK_KEYBOARD;
    CHECK(needs_forwarding(&device));
    block_input_mask = 0u;
    raw = (struct input_event){ .type = EV_KEY, .code = BTN_LEFT, .value = 1 };
    handle_input_event(&device, &raw, &fallback);
    CHECK(forwarded_events == before_block + 1u);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.events[0].code == BTN_LEFT);
    device.mouse_hook_candidate = true;

    /* A keyboard hook on a combined device must forward its unblocked mouse. */
    CHECK(should_grab_device_for_masks(&device, KSI_OPERATION_HOOK_KEYBOARD, 0u));
    block_input_mask = KSI_BLOCK_KEYBOARD;
    CHECK(needs_forwarding(&device));
    block_input_mask |= KSI_BLOCK_MOUSE;
    CHECK(!needs_forwarding(&device));
    block_input_mask = 0u;
    /* A keyboard-only grab forwards wheels raw; the clone rebuilds the legacy
     * step from the high-resolution value, so the source's own is dropped. */
    ksi_linux_tracked_device keyboard = {
        .forwarding_target = 92u, .grabbed = true, .keyboard_candidate = true,
        .high_resolution_horizontal_wheel = true,
    };
    before_block = forwarded_events;
    raw = (struct input_event){ .type = EV_REL, .code = REL_HWHEEL, .value = 1 };
    handle_input_event(&keyboard, &raw, &fallback);
    CHECK(forwarded_events == before_block);
    raw = (struct input_event){ .type = EV_REL, .code = REL_HWHEEL_HI_RES, .value = 120 };
    handle_input_event(&keyboard, &raw, &fallback);
    CHECK(forwarded_events == before_block + 1u && forwarded_replay.events[0].code == REL_HWHEEL_HI_RES);

    /* A plain mouse keeps its whole report, scan codes included, on one lane. */
    ksi_linux_tracked_device mouse = {
        .forwarding_target = 93u, .grabbed = true, .mouse_candidate = true,
        .mouse_hook_candidate = true, .mouse_block_candidate = true,
    };
    raw = (struct input_event){ .type = EV_MSC, .code = MSC_SCAN, .value = 0x90001 };
    handle_input_event(&mouse, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.target == 93u);
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    return true;
}

/* A grab drops the desktop's LED writes to a keyboard, so the LEDs it sets on
 * the sink reach every grabbed keyboard; lock state is read back from them. */
static bool test_forwarding_led_feedback(void)
{
    ksi_linux_tracked_device sink = { .fd = 13, .injected_source = true, .forwarding_sink = true };
    struct input_event led = { .type = EV_LED, .code = LED_CAPSL, .value = 1 };
    uint64_t fallback = 0u;

    tracked_device_count = 4u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 11, .keyboard_candidate = true, .grabbed = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 12, .keyboard_candidate = true };
    tracked_devices[2] = (ksi_linux_tracked_device){ .fd = 13, .keyboard_candidate = true, .grabbed = true };
    tracked_devices[3] = (ksi_linux_tracked_device){ .fd = 12345, .mouse_candidate = true, .grabbed = true };
    memset(fake_leds, 0, sizeof(fake_leds));
    handle_input_event(&sink, &led, &fallback);
    CHECK(fake_leds[1] == 1u << LED_CAPSL && fake_leds[3] == 1u << LED_CAPSL);
    CHECK(fake_leds[2] == 0u && fake_leds[0] == 0u);
    CHECK(current_caps_lock && !current_num_lock);
    /* A keyboard's own LED echo only refreshes. */
    fake_leds[1] = 1u << LED_NUML;
    fake_leds[3] = 0u;
    handle_input_event(&tracked_devices[0], &led, &fallback);
    CHECK(!current_caps_lock && current_num_lock && fake_leds[2] == 0u && fake_leds[3] == 0u);
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 4u);
    memset(fake_leds, 0, sizeof(fake_leds));
    return true;
}

static bool test_forwarding_grab_lifecycle(void)
{
    ksi_linux_tracked_device device = {
        .fd = 12345, .forwarding_target = 1u,
        .mouse_hook_candidate = true, .mouse_block_candidate = true,
    };
    tracked_device_count = 0u;

    /* The source waits until udev has admitted its clone. */
    CHECK(set_device_grab(&device, true) == 0);
    CHECK(!device.grabbed && grab_calls == 0u);
    device.forwarding_ready = true;
    set_long_bit(held_keys[0], BTN_LEFT);
    CHECK(set_device_grab(&device, true) == 0);
    CHECK(!device.grabbed && device.grab_deferred);
    memset(held_keys[0], 0, sizeof(held_keys[0]));
    struct input_event up = { .type = EV_KEY, .code = BTN_LEFT, .value = 0 };
    const struct input_event report_end = { .type = EV_SYN, .code = SYN_REPORT };
    process_deferred_grab_event(&device, &up);
    CHECK(!device.grabbed && device.grab_deferred);
    process_deferred_grab_event(&device, &report_end);
    /* The retry starts the grab, after what is queued behind the report. */
    CHECK(!device.grabbed && !device.grab_deferred && grab_state_incomplete && last_grab_retry_ms == 0u);
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed && grab_calls == 1u && switch_syncs == 1u);

    /* Ungrabbing ends the clone's grab lifetime under a fresh target. */
    CHECK(set_device_grab(&device, false) == 0);
    CHECK(!device.grabbed && device.forwarding_target == 1001u);

    /* A dead clone fails open; the retry path replaces it. */
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed);
    forward_failed = true;
    CHECK(set_device_grab(&device, true) != 0);
    CHECK(!device.grabbed && forward_closes == 0u);
    forward_failed = false;

    /* Full blocking passes nothing on, so it needs no clone. */
    uint64_t clone = device.forwarding_target;
    device.forwarding_target = 0u;
    block_input_mask = KSI_BLOCK_MOUSE;
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed);
    CHECK(set_device_grab(&device, false) == 0);
    device.forwarding_target = clone;

    /* Once input must pass again, a BlockInput grab waits for its clone. */
    device.forwarding_ready = false;
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed);
    block_input_mask = 0u;
    CHECK(set_device_grab(&device, true) == 0 && !device.grabbed);
    device.forwarding_ready = true;

    /* A resting thumb does not hold off a grab, but a pen's barrel button does. */
    set_long_bit(held_keys[0], BTN_TOUCH);
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed && !device.grab_deferred);
    CHECK(set_device_grab(&device, false) == 0);
    set_long_bit(held_keys[0], BTN_STYLUS);
    CHECK(set_device_grab(&device, true) == 0 && !device.grabbed && device.grab_deferred);
    CHECK(set_device_grab(&device, false) == 0 && !device.grab_deferred);
    memset(held_keys[0], 0, sizeof(held_keys[0]));
    clone = device.forwarding_target;

    /* Contention keeps the healthy clone and records the foreign owner. */
    grab_busy = true;
    CHECK(set_device_grab(&device, true) != 0);
    CHECK(!device.grabbed && device.foreign_grab && device.forwarding_target == clone);
    CHECK(forward_closes == 0u);
    grab_busy = false;
    CHECK(set_device_grab(&device, true) == 0 && device.grabbed && !device.foreign_grab);
    CHECK(set_device_grab(&device, false) == 0);
    return true;
}

/* A tracked clone proves udev initialized it, so its waiting source retries
 * immediately. Only clones carrying our traffic count as our output. */
static bool test_forwarding_clone_admission(void)
{
    tracked_device_count = 2u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = -1, .forwarding_target = 88u,
        .keyboard_candidate = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 11, .injected_source = true,
        .forwarding_clone = true, .path = "/dev/null" };
    grab_state_incomplete = false;
    last_grab_retry_ms = 1u;
    forwarding_clone_admitted(&tracked_devices[1]);
    CHECK(tracked_devices[0].forwarding_ready && grab_state_incomplete && last_grab_retry_ms == 0u);

    /* Remappers that grab every keyboard also grab idle clones, so a clone
     * counts only while its source is grabbed. */
    probes = 0u;
    CHECK(!our_output_is_grabbed() && probes == 0u);
    tracked_devices[0].grabbed = true;
    CHECK(clone_source(&tracked_devices[1]) == &tracked_devices[0]);
    CHECK(our_output_is_grabbed() && probes == 1u);
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* Keys held at ungrab stay on the clone, where the desktop saw them pressed,
 * until the ungrabbed source releases them. A release the queue refuses is
 * settled later from the kernel's key state. */
static bool test_ungrab_keeps_clone_holds(void)
{
    ksi_linux_tracked_device *device = &tracked_devices[0];
    struct input_event key = { .type = EV_KEY, .code = KEY_LEFTCTRL, .value = 2 };
    ksi_key_state_payload state;
    uint64_t fallback = 0u;

    tracked_device_count = 1u;
    *device = (ksi_linux_tracked_device){ .fd = 12345, .device_id = 41u, .forwarding_target = 7u,
        .forwarding_ready = true, .grabbed = true, .keyboard_candidate = true };
    memset(held_keys, 0, sizeof(held_keys));
    set_long_bit(held_keys[0], KEY_LEFTSHIFT);
    set_long_bit(held_keys[0], KEY_LEFTCTRL);
    ksi_set_key_bit(fake_kept, KEY_LEFTSHIFT, true);
    ksi_set_key_bit(fake_kept, KEY_LEFTCTRL, true);
    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    CHECK(set_device_grab(device, false) == 0 && !device->grabbed);
    CHECK(device->forwarding_target == 1007u && ksi_key_bit(device->ungrab_held_keys, KEY_LEFTSHIFT));

    /* The desktop saw Shift pressed on the clone; the hook blocked Ctrl, so the
     * clone never held it and the source's own press is not logical state. */
    ksi_set_key_bit(fake_clone_output, KEY_LEFTSHIFT, true);
    CHECK(ksi_linux_devices_get_device_key_state(41u, &state));
    CHECK(ksi_key_bit(state.physical_keys, KEY_LEFTSHIFT) && ksi_key_bit(state.logical_keys, KEY_LEFTSHIFT));
    CHECK(ksi_key_bit(state.physical_keys, KEY_LEFTCTRL) && !ksi_key_bit(state.logical_keys, KEY_LEFTCTRL));

    /* A repeat is not the release; the release goes out as it happens. */
    forwarded_events = 0u;
    handle_input_event(device, &key, &fallback);
    CHECK(forwarded_events == 0u && ksi_key_bit(device->ungrab_held_keys, KEY_LEFTCTRL));
    key.value = 0;
    clear_long_bit(held_keys[0], KEY_LEFTCTRL);
    handle_input_event(device, &key, &fallback);
    CHECK(forwarded_events == 1u && forwarded_replay.events[0].code == KEY_LEFTCTRL);
    CHECK(forwarded_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED));
    CHECK(!ksi_key_bit(device->ungrab_held_keys, KEY_LEFTCTRL));

    key.code = KEY_LEFTSHIFT;
    forwarded_events = 0u;
    refuse_forward = true;
    handle_input_event(device, &key, &fallback);
    CHECK(forwarded_events == 0u && ksi_key_bit(device->ungrab_held_keys, KEY_LEFTSHIFT));
    refuse_forward = false;
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(forwarded_events == 0u);
    clear_long_bit(held_keys[0], KEY_LEFTSHIFT);
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(forwarded_events == 1u && forwarded_replay.target == 1007u);
    CHECK(forwarded_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED));
    CHECK(forwarded_replay.events[0].value == 0 && forwarded_hook_type == KSI_HOOK_KEYBOARD);
    handle_input_event(device, &key, &fallback);
    CHECK(forwarded_events == 1u);

    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    memset(fake_kept, 0, sizeof(fake_kept));
    memset(fake_clone_output, 0, sizeof(fake_clone_output));
    memset(held_keys, 0, sizeof(held_keys));
    tracked_device_count = 0u;
    return true;
}

/* A deferred source stays ungrabbed, so observers see its keys, and its grab
 * starts after the report ending the deferral, unhooked and unforwarded. Only a
 * press completes the panic chord, which spans keyboards but not our outputs. */
static bool test_deferred_grab_keeps_observers(void)
{
    ksi_linux_tracked_device *device = &tracked_devices[0];
    struct input_event key = { .type = EV_KEY, .code = KEY_A, .value = 0 };
    uint64_t fallback = 0u;
    size_t panics = 0u;

    tracked_device_count = 1u;
    *device = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 5u,
        .forwarding_ready = true, .keyboard_candidate = true };
    memset(held_keys, 0, sizeof(held_keys));
    set_long_bit(held_keys[0], KEY_A);
    CHECK(set_device_grab(device, true) == 0 && device->grab_deferred);
    memset(held_keys[0], 0, sizeof(held_keys[0]));
    observations = hooks = forwarded_events = grab_calls = 0u;
    ksi_linux_devices_set_observer_callback(capture, NULL, &observations);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    handle_input_event(device, &key, &fallback);
    CHECK(observations == 1u && keyboard_event.message == KSI_MESSAGE_KEY_UP);
    CHECK(!device->grabbed && device->grab_deferred);
    const struct input_event scan = { .type = EV_MSC, .code = MSC_SCAN, .value = 30 };
    const struct input_event report_end = { .type = EV_SYN, .code = SYN_REPORT };
    handle_input_event(device, &scan, &fallback);
    handle_input_event(device, &report_end, &fallback);
    CHECK(!device->grabbed && !device->grab_deferred && grab_state_incomplete);
    grab_hook_mask = KSI_OPERATION_HOOK_KEYBOARD;
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(device->grabbed && grab_calls == 1u && hooks == 0u && forwarded_events == 0u);

    ksi_linux_devices_set_panic_callback(count_panic, &panics);
    tracked_device_count = 2u;
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 11, .keyboard_candidate = true };
    set_long_bit(held_keys[1], KEY_BACKSPACE);
    set_long_bit(held_keys[0], KEY_ESC);
    set_long_bit(held_keys[0], KEY_ENTER);
    key.code = KEY_ENTER;
    for (int value = 0; value <= 2; value++) {
        key.value = value;
        handle_input_event(device, &key, &fallback);
    }
    CHECK(panics == 1u);
    tracked_devices[1].injected_source = true;
    key.value = 1;
    handle_input_event(device, &key, &fallback);
    CHECK(panics == 1u);
    /* Without a grab the desktop already has the input, so there is nothing
     * to release. */
    tracked_devices[1].injected_source = false;
    device->grabbed = false;
    handle_input_event(device, &key, &fallback);
    CHECK(panics == 1u);
    device->grabbed = true;

    ksi_linux_devices_set_panic_callback(NULL, NULL);
    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    CHECK(set_device_grab(device, false) == 0);
    grab_hook_mask = 0u;
    grab_state_incomplete = false;
    memset(held_keys, 0, sizeof(held_keys));
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* A device keeps each report on the lane of its role; switches follow an
 * ungrabbed source to its clone, which logind also reads. */
static bool test_forwarding_roles(void)
{
    ksi_linux_tracked_device touch = { .forwarding_target = 94u, .grabbed = true,
        .mouse_block_candidate = true };
    ksi_linux_tracked_device keyboard = { .forwarding_target = 95u, .grabbed = true,
        .keyboard_candidate = true };
    struct input_event raw = { .type = EV_MSC, .code = MSC_TIMESTAMP, .value = 1 };
    uint64_t fallback = 0u;
    size_t before;

    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    handle_input_event(&touch, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.target == 94u);
    raw = (struct input_event){ .type = EV_KEY, .code = BTN_0, .value = 1 };
    handle_input_event(&keyboard, &raw, &fallback);
    CHECK(forwarded_hook_type == KSI_HOOK_MOUSE && forwarded_replay.target == 95u
        && forwarded_replay.flags == KSI_FORWARD_CLONE);

    keyboard.grabbed = false;
    switch_syncs = 0u;
    before = forwarded_events;
    raw = (struct input_event){ .type = EV_SW, .code = SW_DOCK, .value = 1 };
    handle_input_event(&keyboard, &raw, &fallback);
    CHECK(switch_syncs == 1u && forwarded_events == before);
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    return true;
}

/* The downstream probe stalls output, so it runs only for a grab that can
 * start now, and only failures a retry can fix keep the retry running. */
static bool test_grab_retry_policy(void)
{
    ksi_linux_tracked_device *source = &tracked_devices[0];

    tracked_device_count = 3u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 3u,
        .keyboard_candidate = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = -1, .keyboard_candidate = true,
        .path = "/dev/input/event-gone" };
    tracked_devices[2] = (ksi_linux_tracked_device){ .fd = -1, .injected_source = true,
        .path = "/dev/null" };
    memset(held_keys, 0, sizeof(held_keys));
    grab_hook_mask = block_input_mask = 0u;
    grab_state_incomplete = false;
    probes = grab_calls = 0u;
    probe_result = 0;

    /* Neither source can grab yet; only the clone awaiting udev retries. */
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(probes == 0u && grab_calls == 0u && grab_state_incomplete);
    source->forwarding_ready = true;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(probes == 1u && source->grabbed && !grab_state_incomplete);

    /* A grab held off by keys probes only once it can start, and one the
     * probe then refuses is retried. */
    CHECK(set_grab_masks(0u, 0u) == 0 && !source->grabbed);
    set_long_bit(held_keys[0], KEY_A);
    probes = 0u;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(source->grab_deferred && probes == 0u && !grab_state_incomplete);
    memset(held_keys[0], 0, sizeof(held_keys[0]));
    probe_result = 1;
    const struct input_event up = { .type = EV_KEY, .code = KEY_A, .value = 0 };
    const struct input_event report_end = { .type = EV_SYN, .code = SYN_REPORT };
    process_deferred_grab_event(source, &up);
    process_deferred_grab_event(source, &report_end);
    CHECK(probes == 0u && grab_state_incomplete && last_grab_retry_ms == 0u);
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(probes == 1u && !source->grabbed && grab_state_incomplete);
    probe_result = 0;

    /* Another interceptor's grab is retried on the timer, without a probe. */
    CHECK(set_grab_masks(0u, 0u) == 0 && !source->grabbed);
    grab_busy = true;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(source->foreign_grab && grab_state_incomplete);
    probes = 0u;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0 && probes == 0u);
    grab_busy = false;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0 && source->grabbed);
    CHECK(!source->foreign_grab && !grab_state_incomplete);

    /* A failed clone fails its source open, and the retry replaces it, closing
     * the failed one through the daemon's queue. */
    size_t opens = forward_opens, closes = forward_closes;
    failed_target = source->forwarding_target;
    failure_pending_fake = true;
    forwarding_enabled = true;
    udev_monitor = (struct udev_monitor *)&step;
    last_grab_retry_ms = 0u;
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, queue_close, NULL);
    ksi_linux_devices_retry_incomplete_grabs();
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    CHECK(!source->grabbed && forward_closes == closes && queued_closes == 1u);
    CHECK(forward_opens == opens + 1u);
    CHECK(source->forwarding_target != failed_target && !source->forwarding_ready);
    CHECK(grab_state_incomplete);

    udev_monitor = NULL;
    forwarding_enabled = false;
    failed_target = 0u;
    probe_result = 1;
    grab_hook_mask = 0u;
    grab_state_incomplete = false;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 3u);
    return true;
}

/* A remapper that grabbed a source's idle clone sits downstream of that
 * source, so grabbing the source would feed it and then take its output. */
static bool test_own_clone_grabbed_downstream(void)
{
    ksi_linux_tracked_device *source = &tracked_devices[0];

    tracked_device_count = 2u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 88u,
        .forwarding_ready = true, .keyboard_candidate = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = -1, .injected_source = true,
        .forwarding_clone = true, .path = "/dev/null" };
    memset(held_keys, 0, sizeof(held_keys));
    grab_hook_mask = block_input_mask = 0u;
    probes = 0u;
    probe_result = 1;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(probes == 1u && !source->grabbed && grab_state_incomplete);
    probe_result = 0;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0 && source->grabbed);
    CHECK(set_grab_masks(0u, 0u) == 0);

    grab_state_incomplete = false;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* Releasing a grab, the downstream probe's included, lets the console set that
 * device's LEDs, so it gets back the state it had; a change the desktop makes
 * to another device meanwhile stays. */
static bool test_grab_release_keeps_leds(void)
{
    tracked_device_count = 2u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 12345, .keyboard_candidate = true,
        .grabbed = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 11, .injected_source = true,
        .forwarding_sink = true, .path = "/fake-slot/1" };
    fake_leds[0] = 1u << LED_CAPSL;
    fake_leds[1] = 1u << LED_SCROLLL;
    fake_leds[2] = 0u;
    console_leds = 1 << LED_NUML;
    compositor_leds = 1 << LED_CAPSL;
    CHECK(set_device_grab(&tracked_devices[0], false) == 0 && !tracked_devices[0].grabbed);
    CHECK(fake_leds[0] == 1u << LED_CAPSL && fake_leds[1] == 1u << LED_SCROLLL);
    CHECK(fake_leds[2] == 1u << LED_CAPSL);
    CHECK(!node_is_grabbed(&tracked_devices[1]));
    CHECK(fake_leds[0] == 1u << LED_CAPSL && fake_leds[1] == 1u << LED_SCROLLL);

    console_leds = compositor_leds = -1;
    memset(fake_leds, 0, sizeof(fake_leds));
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* What was queued before a grab changes is handled under the state it arrived
 * in: a press read during the downstream probe already reached the desktop and
 * holds the grab off, and what arrived under a grab still belongs to its hooks. */
static bool test_grab_change_drains_queue(void)
{
    ksi_linux_tracked_device *device = &tracked_devices[0];
    const struct input_event report_end = { .type = EV_SYN, .code = SYN_REPORT };

    tracked_device_count = 2u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 12345, .evdev = (struct libevdev *)&step,
        .forwarding_target = 5u, .forwarding_ready = true, .keyboard_candidate = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = -1, .injected_source = true, .path = "/dev/null" };
    memset(held_keys, 0, sizeof(held_keys));
    memset(results, 0, sizeof(results));
    step = step_count = 0u;
    observations = hooks = forwarded_events = 0u;
    probe_result = 0;
    ksi_linux_devices_set_observer_callback(capture, NULL, &observations);
    ksi_linux_devices_set_hook_event_callback(capture_hook, &hooks);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);

    probe_presses_key = true;
    CHECK(set_grab_masks(KSI_OPERATION_HOOK_KEYBOARD, 0u) == 0);
    CHECK(step == 2u && observations == 1u && hooks == 0u && forwarded_events == 0u);
    CHECK(!device->grabbed && device->grab_deferred);

    events[0] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 0 };
    events[1] = report_end;
    step = 0u;
    clear_long_bit(held_keys[0], KEY_A);
    process_device_events(device);
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(device->grabbed && observations == 2u && hooks == 0u && forwarded_events == 0u);

    events[0] = (struct input_event){ .type = EV_KEY, .code = KEY_B, .value = 1 };
    step = 0u;
    CHECK(set_grab_masks(0u, 0u) == 0 && !device->grabbed && step == 2u);
    CHECK(hooks == 1u && keyboard_event.scan_code == KEY_B && last_replay.flags == KSI_FORWARD_REPORT_END);

    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    step = step_count = 0u;
    probe_result = 1;
    grab_state_incomplete = false;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* A release the clone still owes goes out before a new grab, which would take
 * it; while the queue refuses it, the grab waits. */
static bool test_grab_waits_for_owed_release(void)
{
    ksi_linux_tracked_device *device = &tracked_devices[0];

    tracked_device_count = 1u;
    *device = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 7u,
        .forwarding_ready = true, .keyboard_candidate = true };
    ksi_set_key_bit(device->ungrab_held_keys, KEY_LEFTALT, true);
    memset(held_keys, 0, sizeof(held_keys));
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    forwarded_events = 0u;
    outputs_grabbed = -1;
    refuse_forward = true;
    CHECK(set_device_grab(device, true) == 0 && !device->grabbed);
    refuse_forward = false;
    CHECK(set_device_grab(device, true) == 0 && device->grabbed && forwarded_events == 1u);
    CHECK(forwarded_replay.events[0].code == KEY_LEFTALT && !ksi_any_key_bit(device->ungrab_held_keys));

    CHECK(set_device_grab(device, false) == 0);
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]));
    return true;
}

/* A wheel notch is one packet. A button the mouse hook cannot take keeps its
 * scan code on the raw path, blocking holds back its press but not its
 * release, and a blocked key's scan code does not reach the next report. */
static bool test_raw_report_packets(void)
{
    ksi_linux_tracked_device mouse = { .fd = -1, .evdev = (struct libevdev *)&step, .grabbed = true,
        .forwarding_target = 96u, .mouse_candidate = true, .mouse_hook_candidate = true,
        .mouse_block_candidate = true };
    ksi_linux_tracked_device combined = { .fd = -1, .evdev = (struct libevdev *)&step, .grabbed = true,
        .forwarding_target = 97u, .keyboard_candidate = true, .mouse_candidate = true,
        .mouse_block_candidate = true };

    memset(results, 0, sizeof(results));
    events[0] = (struct input_event){ .type = EV_REL, .code = REL_WHEEL, .value = -1 };
    events[1] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    step = 0u; step_count = 2u; hooks = forwarded_events = 0u;
    ksi_linux_devices_set_hook_event_callback(capture_hook, &hooks);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    process_device_events(&mouse);
    CHECK(hooks == 1u && forwarded_events == 0u
        && last_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE));
    CHECK(last_replay.count == 1u && last_replay.events[0].code == REL_WHEEL);

    events[0] = (struct input_event){ .type = EV_MSC, .code = MSC_SCAN, .value = 0x90001 };
    events[1] = (struct input_event){ .type = EV_KEY, .code = BTN_LEFT, .value = 1 };
    events[2] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    step = 0u; step_count = 3u; hooks = 0u;
    process_device_events(&combined);
    CHECK(hooks == 0u && forwarded_events == 1u && forwarded_hook_type == KSI_HOOK_MOUSE);
    CHECK(forwarded_replay.count == 2u && forwarded_replay.events[0].type == EV_MSC
        && forwarded_replay.events[1].code == BTN_LEFT
        && forwarded_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_CLONE));

    block_input_mask = KSI_BLOCK_MOUSE;
    step = 0u; forwarded_events = 0u;
    process_device_events(&combined);
    CHECK(forwarded_events == 0u && !combined.has_pending_scan);
    events[1].value = 0;
    step = 0u;
    process_device_events(&combined);
    CHECK(forwarded_events == 1u && forwarded_replay.events[1].value == 0);
    block_input_mask = 0u;

    events[0] = events[1];
    events[1] = events[2];
    step = 0u; step_count = 2u;
    process_device_events(&combined);
    CHECK(forwarded_events == 2u && forwarded_replay.count == 1u && forwarded_replay.events[0].code == BTN_LEFT);

    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    step = step_count = 0u;
    return true;
}

static void record_change(void *context, uint32_t kind, const ksi_device_info *device, uint64_t generation)
{
    (void)context; (void)kind; (void)device; (void)generation;
    if (delivery_count < sizeof(delivery_order)) delivery_order[delivery_count++] = 'R';
}

/* A read error met while completing a report closes the device only after the
 * event in hand is delivered, so its removal follows it. */
static bool test_read_error_closes_after_event(void)
{
    ksi_linux_tracked_device *device = &tracked_devices[0];

    tracked_device_count = 1u;
    *device = (ksi_linux_tracked_device){ .fd = 12345, .evdev = (struct libevdev *)&step, .grabbed = true,
        .keyboard_candidate = true, .forwarding_target = 8u };
    memset(results, 0, sizeof(results));
    events[0] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 1 };
    results[1] = -EIO;
    step = 0u; step_count = 2u; hooks = delivery_count = 0u;
    ksi_linux_devices_set_observer_callback(NULL, record_change, NULL);
    ksi_linux_devices_set_hook_event_callback(capture_hook, &hooks);
    process_device_events(device);
    CHECK(hooks == 1u && device->fd < 0 && device->evdev == NULL);
    CHECK(delivery_count == 2u && delivery_order[0] == 'H' && delivery_order[1] == 'R');

    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    results[1] = 0;
    step = step_count = 0u;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]));
    return true;
}

/* Our clones and gamepads are recognised from what the kernel reports, so a
 * keyboard is cloned once and neither a clone nor a pad is ever cloned. */
static bool test_device_classification(void)
{
    ksi_linux_device_info info;

    memset(&fake_node, 0, sizeof(fake_node));
    fake_node.name = "Keyboard";
    fake_node.phys = "usb-0000:00:14.0-1/input0";
    set_long_bit(fake_node.ev, EV_KEY);
    set_long_bit(fake_node.key, KEY_A);
    CHECK(read_device_info("/fake/event1", &info) == 0);
    CHECK(info.has_keyboard_keys && !info.is_gamepad && !info.is_synth_device);

    forwarding_enabled = true;
    tracked_device_count = 0u;
    forward_opens = 0u;
    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    clone_fake = false;
    track_device(&info, "test");
    track_device(&info, "test");
    CHECK(tracked_device_count == 1u && forward_opens == 1u && tracked_devices[0].forwarding_target != 0u);
    /* A keyboard without a clone waits only for the sink. */
    CHECK(last_open_keyboard && tracked_devices[0].forwarding_ready);
    clone_fake = true;

    fake_node.phys = KSI_FORWARD_PHYS_PREFIX "usb-0000:00:14.0-1/input0";
    CHECK(read_device_info("/fake/event2", &info) == 0 && info.is_synth_device);
    track_device(&info, "test");
    CHECK(tracked_device_count == 2u && forward_opens == 1u);
    CHECK(tracked_devices[1].injected_source && tracked_devices[1].forwarding_clone);

    fake_node.phys = "usb-0000:00:14.0-2/input0";
    set_long_bit(fake_node.ev, EV_ABS);
    set_long_bit(fake_node.abs, ABS_X);
    set_long_bit(fake_node.key, BTN_SOUTH);
    clear_long_bit(fake_node.key, KEY_A);
    set_long_bit(fake_node.key, KEY_RECORD);
    CHECK(read_device_info("/fake/event3", &info) == 0 && info.is_gamepad && !info.has_keyboard_keys);
    track_device(&info, "test");
    CHECK(tracked_device_count == 3u && forward_opens == 1u && !tracked_devices[2].keyboard_candidate);

    /* The synthesis keyboard is the sink: tracking it lets keyboards be grabbed. */
    fake_node.name = KSI_SYNTH_DEVICE_NAME;
    fake_node.phys = "";
    fake_node.id = (struct input_id){ .bustype = KSI_SYNTH_DEVICE_BUSTYPE,
        .vendor = KSI_SYNTH_DEVICE_VENDOR, .product = KSI_SYNTH_DEVICE_PRODUCT };
    set_long_bit(fake_node.key, KEY_A);
    CHECK(read_device_info("/fake/event4", &info) == 0 && info.is_synth_device);
    sink_admitted = grab_state_incomplete = false;
    last_grab_retry_ms = 1u;
    track_device(&info, "test");
    CHECK(tracked_device_count == 4u && forward_opens == 1u && tracked_devices[3].forwarding_sink);
    CHECK(tracked_devices[3].injected_source && sink_admitted && grab_state_incomplete && last_grab_retry_ms == 0u);
    const ksi_linux_tracked_device keyboard = { .fd = 12345, .forwarding_target = 7u,
        .forwarding_ready = true, .keyboard_candidate = true };
    CHECK(forwarding_usable(&keyboard));

    /* A recreated sink counts only once udev admits its node, whichever of the
     * two nodes goes last. */
    ksi_linux_forward_attach_sink(-1);
    CHECK(!forwarding_usable(&keyboard));
    CHECK(read_device_info("/fake/event5", &info) == 0);
    track_device(&info, "test");
    CHECK(tracked_device_count == 5u && forwarding_usable(&keyboard));
    untrack_device("/fake/event4");
    CHECK(tracked_device_count == 4u && forwarding_usable(&keyboard));

    /* The absolute pointer is ours but is not the sink. */
    fake_node.name = KSI_SYNTH_ABS_DEVICE_NAME;
    fake_node.id.product = KSI_SYNTH_ABS_DEVICE_PRODUCT;
    CHECK(read_device_info("/fake/event6", &info) == 0 && info.is_synth_device);
    track_device(&info, "test");
    CHECK(tracked_device_count == 5u && !tracked_devices[4].forwarding_sink);
    untrack_device("/fake/event6");
    CHECK(forwarding_usable(&keyboard));
    untrack_device("/fake/event5");
    CHECK(tracked_device_count == 3u && !sink_admitted && !forwarding_usable(&keyboard));
    sink_admitted = true;
    sink_admitted_generation = ksi_linux_forward_sink_generation();
    grab_state_incomplete = false;
    memset(&fake_node.id, 0, sizeof(fake_node.id));

    forwarding_enabled = false;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 3u);
    return true;
}

/* A keyboard's keys reach the desktop only through the sink, so its grab waits
 * for udev to admit a working sink, and fails open once the sink is lost; a
 * pointer's input does not use the sink. */
static bool test_keyboard_grab_waits_for_sink(void)
{
    ksi_linux_tracked_device *keyboard = &tracked_devices[0];
    ksi_linux_tracked_device mouse = { .fd = 12345, .forwarding_target = 8u, .forwarding_ready = true,
        .mouse_hook_candidate = true, .mouse_block_candidate = true };
    size_t closes = forward_closes;

    tracked_device_count = 1u;
    *keyboard = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 7u,
        .forwarding_ready = true, .keyboard_candidate = true };
    memset(held_keys, 0, sizeof(held_keys));
    outputs_grabbed = -1;
    sink_admitted = false;
    CHECK(set_device_grab(keyboard, true) == 0 && !keyboard->grabbed);
    CHECK(set_device_grab(&mouse, true) == 0 && mouse.grabbed);
    CHECK(set_device_grab(&mouse, false) == 0);
    sink_admitted = true;
    sink_ready_fake = false;
    CHECK(set_device_grab(keyboard, true) == 0 && !keyboard->grabbed);
    sink_ready_fake = true;
    CHECK(set_device_grab(keyboard, true) == 0 && keyboard->grabbed);

    /* The failure fails it open at once, before the timed retry. */
    sink_ready_fake = false;
    failure_pending_fake = true;
    grab_state_incomplete = false;
    last_grab_retry_ms = ksi_linux_monotonic_ms();
    ksi_linux_devices_retry_incomplete_grabs();
    CHECK(!keyboard->grabbed && forward_closes == closes && grab_state_incomplete);

    sink_ready_fake = true;
    grab_state_incomplete = false;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]));
    return true;
}

/* A keyboard's other buttons go to its clone, but BlockInput still treats
 * them as keyboard input. */
static bool test_keyboard_extras_block_as_keyboard(void)
{
    ksi_linux_tracked_device keyboard = { .forwarding_target = 96u, .grabbed = true,
        .keyboard_candidate = true };
    struct input_event button = { .type = EV_KEY, .code = BTN_0, .value = 1 };
    uint64_t fallback = 0u;

    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    forwarded_events = 0u;
    block_input_mask = KSI_BLOCK_KEYBOARD;
    handle_input_event(&keyboard, &button, &fallback);
    CHECK(forwarded_events == 0u);
    block_input_mask = KSI_BLOCK_MOUSE;
    handle_input_event(&keyboard, &button, &fallback);
    CHECK(forwarded_events == 1u && forwarded_hook_type == KSI_HOOK_MOUSE
        && (forwarded_replay.flags & KSI_FORWARD_CLONE) != 0u);
    block_input_mask = 0u;
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    return true;
}

/* An output found grabbed is probed first next time: a grabbed node refuses at
 * once, while an ungrabbed one stalls output until its probe grab is released. */
static bool test_probe_order(void)
{
    tracked_device_count = 2u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 11, .device_id = 41u,
        .injected_source = true, .path = "/fake-slot/1" };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 12, .device_id = 42u,
        .injected_source = true, .path = "/fake-slot/2" };
    probe_grabbed_slots = 1u << 2;
    probe_result = 0;
    probes = 0u;
    CHECK(our_output_is_grabbed() && probes == 2u);
    probes = 0u;
    CHECK(our_output_is_grabbed() && probes == 1u);
    probe_grabbed_slots = 0u;
    CHECK(!our_output_is_grabbed());
    probe_result = 1;
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]) * 2u);
    return true;
}

/* A mouse button held at ungrab is owed to the mouse's clone. */
static bool test_ungrab_owes_button_to_clone(void)
{
    ksi_linux_tracked_device *mouse = &tracked_devices[0];
    struct input_event button = { .type = EV_KEY, .code = BTN_LEFT, .value = 0 };
    uint64_t fallback = 0u;

    tracked_device_count = 1u;
    *mouse = (ksi_linux_tracked_device){ .fd = 12345, .forwarding_target = 9u, .forwarding_ready = true,
        .grabbed = true, .mouse_candidate = true, .mouse_block_candidate = true };
    memset(held_keys, 0, sizeof(held_keys));
    set_long_bit(held_keys[0], BTN_LEFT);
    ksi_set_key_bit(fake_kept, BTN_LEFT, true);
    ksi_linux_devices_set_forward_event_callback(capture_forward, NULL, NULL, NULL);
    CHECK(set_device_grab(mouse, false) == 0 && ksi_key_bit(mouse->ungrab_held_keys, BTN_LEFT));
    forwarded_events = 0u;
    clear_long_bit(held_keys[0], BTN_LEFT);
    handle_input_event(mouse, &button, &fallback);
    CHECK(forwarded_events == 1u && forwarded_hook_type == KSI_HOOK_MOUSE);
    CHECK(forwarded_replay.flags == (KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED | KSI_FORWARD_CLONE));
    ksi_linux_devices_set_forward_event_callback(NULL, NULL, NULL, NULL);
    memset(fake_kept, 0, sizeof(fake_kept));
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices[0]));
    return true;
}

/* The poll list never exceeds what the daemon sized for the table. */
static bool test_poll_list_is_bounded(void)
{
    struct pollfd fds[KSI_LINUX_MAX_POLL_FDS];

    tracked_device_count = KSI_MAX_TRACKED_DEVICES;
    for (size_t i = 0u; i < KSI_MAX_TRACKED_DEVICES; i++) tracked_devices[i].fd = 20;
    CHECK(ksi_linux_devices_poll_fds(fds, 10u) == 10u);
    CHECK(ksi_linux_devices_poll_fds(fds, KSI_LINUX_MAX_POLL_FDS) == KSI_MAX_TRACKED_DEVICES);
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices));
    return true;
}

static bool test_independent_device_key_states(void)
{
    tracked_device_count = 3u;
    tracked_devices[0] = (ksi_linux_tracked_device){ .fd = 11, .device_id = 31u, .keyboard_candidate = true };
    tracked_devices[1] = (ksi_linux_tracked_device){ .fd = 12, .device_id = 32u, .keyboard_candidate = true };
    tracked_devices[2] = (ksi_linux_tracked_device){ .fd = 13, .device_id = 33u, .mouse_candidate = true };
    memset(held_keys, 0, sizeof(held_keys));
    memset(fake_leds, 0, sizeof(fake_leds));
    set_long_bit(held_keys[2], KEY_A);
    ksi_key_state_payload state;
    CHECK(ksi_linux_devices_get_device_key_state(0u, &state) && ksi_key_bit(state.physical_keys, KEY_A));
    CHECK(ksi_key_bit(state.logical_keys, KEY_A));
    CHECK(ksi_linux_devices_get_device_key_state(31u, &state) && !ksi_key_bit(state.physical_keys, KEY_A));
    CHECK(ksi_linux_devices_get_device_key_state(32u, &state) && ksi_key_bit(state.physical_keys, KEY_A));
    /* A device query describes that device alone, the seat query every one. */
    set_long_bit(held_keys[1], KEY_B);
    CHECK(ksi_linux_devices_get_device_key_state(32u, &state) && !ksi_key_bit(state.logical_keys, KEY_B)
        && !ksi_key_bit(state.physical_keys, KEY_B));
    CHECK(ksi_linux_devices_get_device_key_state(0u, &state) && ksi_key_bit(state.logical_keys, KEY_B));
    clear_long_bit(held_keys[1], KEY_B);

    /* Suppression changes logical output, never the source's physical state,
     * and what a grabbed source passes is logical through its clone. */
    tracked_devices[1].grabbed = true;
    tracked_devices[1].forwarding_target = 123u;
    CHECK(ksi_linux_devices_get_device_key_state(32u, &state));
    CHECK(ksi_key_bit(state.physical_keys, KEY_A) && !ksi_key_bit(state.logical_keys, KEY_A));
    ksi_set_key_bit(fake_clone_output, KEY_A, true);
    CHECK(ksi_linux_devices_get_device_key_state(32u, &state) && ksi_key_bit(state.logical_keys, KEY_A));
    ksi_set_key_bit(fake_clone_output, KEY_A, false);

    /* A source another interceptor owns never reaches the desktop directly. */
    tracked_devices[1].grabbed = false;
    tracked_devices[1].foreign_grab = true;
    CHECK(ksi_linux_devices_get_device_key_state(0u, &state));
    CHECK(ksi_key_bit(state.physical_keys, KEY_A) && !ksi_key_bit(state.logical_keys, KEY_A));
    tracked_devices[1].foreign_grab = false;

    /* Locks and modifiers describe the seat even for a device query. */
    fake_leds[1] = 1u << LED_NUML;
    set_long_bit(held_keys[1], KEY_LEFTSHIFT);
    CHECK(ksi_linux_devices_get_device_key_state(32u, &state));
    CHECK(state.num_lock && !state.caps_lock && (state.modifiers_lr & 0x10u) != 0u);
    CHECK(!ksi_key_bit(state.physical_keys, KEY_LEFTSHIFT) && current_num_lock);

    set_long_bit(held_keys[3], BTN_BACK);
    CHECK(ksi_linux_devices_get_device_key_state(33u, &state) && ksi_key_bit(state.physical_keys, BTN_BACK));
    ksi_pointer_buttons_payload buttons;
    CHECK(ksi_linux_devices_get_pointer_buttons(&buttons) && buttons.physical_buttons == (1u << 3));

    tracked_devices[1].fd = -1;
    CHECK(!ksi_linux_devices_get_device_key_state(32u, &state));
    CHECK(ksi_linux_devices_get_device_key_state(0u, &state) && !ksi_key_bit(state.physical_keys, KEY_A));
    tracked_devices[2].injected_source = true;
    CHECK(!ksi_linux_devices_get_device_key_state(33u, &state));
    tracked_device_count = 0u;
    memset(tracked_devices, 0, sizeof(tracked_devices));
    memset(held_keys, 0, sizeof(held_keys));
    return true;
}

int main(void)
{
    sink_admitted = true;
    if (!test_sync_repairs_lost_release() || !test_keystroke_is_one_packet()
        || !test_observation_without_grab()
        || !test_high_resolution_wheel() || !test_device_metadata_codec()
        || !test_raw_touchpad_observation() || !test_gamepad_classification()
        || !test_gamepad_state_codec() || !test_gamepad_selection()
        || !test_forwarding_preserves_raw_input()
        || !test_forwarding_led_feedback()
        || !test_forwarding_grab_lifecycle()
        || !test_forwarding_clone_admission()
        || !test_ungrab_keeps_clone_holds()
        || !test_deferred_grab_keeps_observers()
        || !test_forwarding_roles()
        || !test_grab_retry_policy()
        || !test_own_clone_grabbed_downstream()
        || !test_grab_release_keeps_leds()
        || !test_grab_change_drains_queue()
        || !test_grab_waits_for_owed_release()
        || !test_raw_report_packets()
        || !test_read_error_closes_after_event()
        || !test_device_classification()
        || !test_keyboard_grab_waits_for_sink()
        || !test_keyboard_extras_block_as_keyboard()
        || !test_probe_order()
        || !test_ungrab_owes_button_to_clone()
        || !test_poll_list_is_bounded()
        || !test_independent_device_key_states()) return 1;
    puts("PASS device state synchronization, observation, forwarding, metadata and gamepads");
    return 0;
}
