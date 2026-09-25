#include "internal/linux_devices.h"

#include "internal/globals.h"
#include "internal/linux_synth.h"
#include "internal/protocol.h"
#include "linux_device_filter.h"
#include "linux_key_bits.h"
#include "linux_output.h"
#include "vk_evdev.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <libevdev/libevdev.h>
#include <libudev.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define KSI_INPUT_DIR "/dev/input"
#define KSI_EVENT_PREFIX "event"
#define KSI_DEVICE_NAME_LENGTH 256
/* A grab change handles everything already queued, up to this many reads. */
#define KSI_MAX_DRAIN_PASSES 16
#define KSI_MAX_DEVICE_EVENTS_PER_PASS 256
#define KSI_MAX_UDEV_EVENTS_PER_PASS 64
#define KSI_FORWARD_REPORT_KEYBOARD 0x01u
#define KSI_FORWARD_REPORT_MOUSE 0x02u

#define KSI_BITS_PER_LONG (sizeof(unsigned long) * CHAR_BIT)
#define KSI_BIT_WORD(bit) ((bit) / KSI_BITS_PER_LONG)
#define KSI_BIT_MASK(bit) (1UL << ((bit) % KSI_BITS_PER_LONG))
#define KSI_BIT_ARRAY_LENGTH(max_bit) (((max_bit) / KSI_BITS_PER_LONG) + 1)

typedef struct ksi_linux_device_info {
    ksi_device_info public_info;
    char path[PATH_MAX];
    char name[KSI_DEVICE_NAME_LENGTH];
    bool has_keys;
    bool has_relative;
    bool has_absolute;
    bool has_keyboard_keys;
    bool has_mouse_buttons;
    bool has_pointer_axes;
    bool requires_compositor_processing;
    bool high_resolution_wheel;
    bool high_resolution_horizontal_wheel;
    bool is_gamepad;
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
    bool is_synth_device;
} ksi_linux_device_info;

typedef struct ksi_linux_tracked_device {
    ksi_device_info public_info;
    char path[PATH_MAX];
    char name[KSI_DEVICE_NAME_LENGTH];
    int fd;
    struct libevdev *evdev;
    uint32_t device_id;
    bool grabbed;
    /* EVIOCGRAB returned EBUSY: another interceptor owns this source's stream. */
    bool foreign_grab;
    /* The last grab attempt deferred to a downstream interceptor. */
    bool deferred_to_tail;
    /* A read failed while the device was being handled; it closes afterwards. */
    int read_error;
    uint64_t forwarding_target;
    /* udev has initialized this source's clone, or it needs none. */
    bool forwarding_ready;
    /* This node is one of our clones rather than a source. */
    bool forwarding_clone;
    /* This node is the sink: the synthesis keyboard, which also carries every
     * grabbed keyboard's keys. sink_generation is the sink's when admitted. */
    bool forwarding_sink;
    uint32_t sink_generation;
    bool keyboard_candidate;
    bool mouse_candidate;
    bool mouse_hook_candidate;
    bool mouse_block_candidate;
    bool injected_source;
    bool raw_observation_candidate;
    bool event_clock_monotonic;
    bool grab_deferred;
    bool has_buffered_event;
    bool synchronizing;
    /* KSI_FORWARD_REPORT_* lanes carrying part of the current report. */
    uint32_t forward_report_lanes;
    /* A report's MSC_SCAN, held back to ride in its key's packet. */
    bool has_pending_scan;
    int32_t pending_scan;
    bool high_resolution_wheel;
    bool high_resolution_horizontal_wheel;
    struct input_event buffered_event;
    uint8_t deferred_down_keys[KSI_KEY_BITMAP_BYTES];
    /* Held when the source was ungrabbed. The desktop saw them pressed on
     * the source's outputs, which keep them until the source releases them. */
    uint8_t ungrab_held_keys[KSI_KEY_BITMAP_BYTES];
    bool has_pending_rel;
    int32_t pending_rel_x;
    int32_t pending_rel_y;
    uint64_t pending_rel_time_ms;
    uint64_t pending_rel_extra_info;
    bool pending_rel_injected;
    bool has_pending_abs;
    int32_t pending_abs_start_x;
    int32_t pending_abs_start_y;
    int32_t current_abs_x;
    int32_t current_abs_y;
    int32_t current_abs_x_raw;
    int32_t current_abs_y_raw;
    int32_t abs_x_min;
    int32_t abs_x_max;
    int32_t abs_y_min;
    int32_t abs_y_max;
    uint64_t pending_abs_time_ms;
    uint64_t pending_abs_extra_info;
    bool pending_abs_injected;
} ksi_linux_tracked_device;

static ksi_linux_tracked_device tracked_devices[KSI_MAX_TRACKED_DEVICES];
static size_t tracked_device_count;
static struct udev *udev_context;
static struct udev_monitor *udev_monitor;
static uint32_t next_device_id = 1;
static ksi_physical_hook_callback hook_event_callback;
static void *hook_event_context;
static ksi_physical_forward_callback forward_event_callback;
static ksi_forward_end_grab_callback end_grab_callback;
static ksi_forward_close_callback close_callback;
static void *forward_event_context;
static ksi_hook_event_callback observer_event_callback;
static ksi_raw_device_callback raw_observer_callback;
static void *raw_observer_context;
static ksi_device_change_callback device_change_callback;
static void *observer_event_context;
static uint64_t device_generation = 1u;
static ksi_panic_callback panic_callback;
static void *panic_context;
static uint32_t grab_hook_mask;
static uint32_t block_input_mask;
/* Set when the most recent set_grab_masks() could not apply the requested grab
 * state to every device. Forces the next call to re-evaluate (rather than
 * short-circuit on an unchanged mask) so a transient grab failure is retried. */
static bool grab_state_incomplete;
static bool forwarding_enabled;
/* udev has initialized a sink node, and the newest one's sink generation. */
static bool sink_admitted;
static uint32_t sink_admitted_generation;
/* Set while device events are read, so a grab change made from inside that
 * processing does not read them again. */
static bool reading_device_events;
/* Whether one of our outputs is grabbed downstream: -1 until probed, and
 * probed once per pass of grab changes; see grab_would_feed_downstream. */
static int outputs_grabbed = -1;

/* Rate limit for ksi_linux_devices_retry_incomplete_grabs(): a node that can
 * never be grabbed would otherwise retry and log on every main-loop tick. */
#define KSI_GRAB_RETRY_INTERVAL_MS 3000u
static uint64_t last_grab_retry_ms;

/* Current LED state, updated from EV_LED events on grabbed keyboards.
 * Included in every keyboard hook event so clients can maintain an
 * accurate indicator snapshot without a separate IPC round-trip. */
static bool current_caps_lock;
static bool current_num_lock;
static bool current_scroll_lock;
static ksi_pointer_position_payload current_pointer_position;
/* Device ingestion and protocol queries run on the daemon's main poll thread,
 * so this field is read and written serially. Zero means no observed input. */
static uint64_t last_input_activity_ms;

static int set_grab_masks(uint32_t hook_mask, uint32_t block_mask);
static void process_device_events(ksi_linux_tracked_device *device);
static void settle_ungrab_holds(ksi_linux_tracked_device *device);
static void refresh_sink_admission(void);
static bool grab_would_feed_downstream(const ksi_linux_tracked_device *source);

static bool test_bit(const unsigned long *bits, int bit)
{
    return (bits[KSI_BIT_WORD((size_t)bit)] & KSI_BIT_MASK((size_t)bit)) != 0;
}

static bool is_keyboard_key_code(unsigned int code)
{
    return ksi_linux_key_code_is_keyboard(code);
}

static bool is_mouse_button_code(unsigned int code)
{
    return ksi_linux_pointer_button_mask(code) != 0u;
}

static bool looks_like_keyboard(const unsigned long *key_bits)
{
    for (unsigned int code = KEY_RESERVED + 1u; code <= KEY_MAX; code++) {
        if (is_keyboard_key_code(code) && test_bit(key_bits, (int)code)) {
            return true;
        }
    }

    return false;
}

static bool looks_like_mouse_buttons(const unsigned long *key_bits)
{
    return test_bit(key_bits, BTN_LEFT)
        || test_bit(key_bits, BTN_RIGHT)
        || test_bit(key_bits, BTN_MIDDLE)
        || test_bit(key_bits, BTN_SIDE)
        || test_bit(key_bits, BTN_EXTRA)
        || test_bit(key_bits, BTN_FORWARD)
        || test_bit(key_bits, BTN_BACK);
}

static bool looks_like_gamepad(const unsigned long *key_bits, const unsigned long *abs_bits)
{
    if (!test_bit(abs_bits, ABS_X)) {
        return false;
    }

    for (unsigned int code = BTN_JOYSTICK; code < BTN_DIGI; code++) {
        if (ksi_linux_key_code_is_gamepad_identity(code) && test_bit(key_bits, (int)code)) {
            return true;
        }
    }

    return false;
}

/* Report the buttons in the order joydev numbers them, so a consumer's button
 * index matches what the kernel's own joystick interface would report. */
static void collect_gamepad_buttons(const unsigned long *key_bits, ksi_device_info *public)
{
    public->button_count = 0u;

    for (unsigned int code = BTN_JOYSTICK; code <= KEY_MAX; code++) {
        if (test_bit(key_bits, (int)code) && public->button_count < KSI_DEVICE_BUTTON_CAPACITY) {
            public->button_codes[public->button_count++] = (uint16_t)code;
        }
    }

    for (unsigned int code = BTN_MISC; code < BTN_JOYSTICK; code++) {
        if (test_bit(key_bits, (int)code) && public->button_count < KSI_DEVICE_BUTTON_CAPACITY) {
            public->button_codes[public->button_count++] = (uint16_t)code;
        }
    }
}

static bool looks_like_compositor_processed_pointer(const unsigned long *key_bits)
{
    return test_bit(key_bits, BTN_TOOL_FINGER)
        || test_bit(key_bits, BTN_TOOL_PEN)
        || test_bit(key_bits, BTN_TOOL_RUBBER);
}

static bool looks_like_pointer_axes(const unsigned long *rel_bits, const unsigned long *abs_bits)
{
    return (test_bit(rel_bits, REL_X) && test_bit(rel_bits, REL_Y))
        || (test_bit(abs_bits, ABS_X) && test_bit(abs_bits, ABS_Y));
}

static bool is_keysharp_synth_device_identity(
    const char *name,
    uint16_t bustype,
    uint16_t vendor,
    uint16_t product)
{
    bool name_matches = name != NULL
        && (strcmp(name, KSI_SYNTH_DEVICE_NAME) == 0
            || strcmp(name, KSI_SYNTH_ABS_DEVICE_NAME) == 0);
    bool id_matches = bustype == KSI_SYNTH_DEVICE_BUSTYPE
        && vendor == KSI_SYNTH_DEVICE_VENDOR
        && (product == KSI_SYNTH_DEVICE_PRODUCT
            || product == KSI_SYNTH_ABS_DEVICE_PRODUCT);

    return name_matches && id_matches;
}

static bool is_forwarding_phys(const char *phys)
{
    return strncmp(phys, KSI_FORWARD_PHYS_PREFIX, sizeof(KSI_FORWARD_PHYS_PREFIX) - 1u) == 0;
}

static bool is_sink_identity(const ksi_linux_device_info *info)
{
    return info->is_synth_device && info->product == KSI_SYNTH_DEVICE_PRODUCT
        && strcmp(info->name, KSI_SYNTH_DEVICE_NAME) == 0;
}

static int open_event_fd(const char *path)
{
    /* Every evdev open file description owns an independent event queue: these
     * reads cannot consume or suppress events for libinput, keyd, games, or
     * another observer. Interception is a separate EVIOCGRAB operation and is
     * issued only from set_grab_masks() for a non-zero hook/BlockInput mask.
     * EVIOCSCLOCKID below changes timestamps for this fd only. */
    /* O_CLOEXEC atomically at open (vs a post-open fcntl, which races a
     * concurrent fork+exec): a spawned helper (systemctl/udevadm/prompt worker)
     * must never inherit an evdev grab fd, or the grab would outlive this daemon
     * and strand the user's input even after the daemon is killed. */
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) {
        fprintf(stderr, "keysharp-input: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    return fd;
}

static int read_device_info(const char *path, ksi_linux_device_info *info)
{
    unsigned long event_bits[KSI_BIT_ARRAY_LENGTH(EV_MAX)];
    unsigned long key_bits[KSI_BIT_ARRAY_LENGTH(KEY_MAX)];
    unsigned long rel_bits[KSI_BIT_ARRAY_LENGTH(REL_MAX)];
    unsigned long abs_bits[KSI_BIT_ARRAY_LENGTH(ABS_MAX)];
    struct input_id input_id;
    int fd;

    memset(info, 0, sizeof(*info));
    memset(event_bits, 0, sizeof(event_bits));
    memset(key_bits, 0, sizeof(key_bits));
    memset(rel_bits, 0, sizeof(rel_bits));
    memset(abs_bits, 0, sizeof(abs_bits));

    (void)snprintf(info->path, sizeof(info->path), "%s", path);

    fd = open_event_fd(path);

    if (fd < 0) {
        return -1;
    }

    if (ioctl(fd, EVIOCGNAME(sizeof(info->name)), info->name) < 0) {
        (void)snprintf(info->name, sizeof(info->name), "unknown");
    }

    memset(&input_id, 0, sizeof(input_id));

    if (ioctl(fd, EVIOCGID, &input_id) == 0) {
        info->bustype = input_id.bustype;
        info->vendor = input_id.vendor;
        info->product = input_id.product;
        info->version = input_id.version;
    }

    if (ioctl(fd, EVIOCGBIT(0, sizeof(event_bits)), event_bits) < 0) {
        fprintf(stderr, "keysharp-input: cannot read capabilities for %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    info->has_keys = test_bit(event_bits, EV_KEY);
    info->has_relative = test_bit(event_bits, EV_REL);
    info->has_absolute = test_bit(event_bits, EV_ABS);

    if (info->has_keys && ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits) < 0) {
        fprintf(stderr, "keysharp-input: cannot read key capabilities for %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    if (info->has_relative && ioctl(fd, EVIOCGBIT(EV_REL, sizeof(rel_bits)), rel_bits) < 0) {
        fprintf(stderr, "keysharp-input: cannot read relative-axis capabilities for %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    if (info->has_absolute && ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(abs_bits)), abs_bits) < 0) {
        fprintf(stderr, "keysharp-input: cannot read absolute-axis capabilities for %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    info->is_gamepad = info->has_keys && looks_like_gamepad(key_bits, abs_bits);
    /* Some controllers report a key such as KEY_RECORD for a button. A keyboard
     * hook must not take a game's controller, nor clone it into a second one. */
    info->has_keyboard_keys = info->has_keys && !info->is_gamepad && looks_like_keyboard(key_bits);
    info->has_mouse_buttons = info->has_keys && looks_like_mouse_buttons(key_bits);
    info->has_pointer_axes = looks_like_pointer_axes(rel_bits, abs_bits);
    info->requires_compositor_processing = info->has_absolute
        && looks_like_compositor_processed_pointer(key_bits);
    info->high_resolution_wheel = test_bit(rel_bits, REL_WHEEL_HI_RES);
    info->high_resolution_horizontal_wheel = test_bit(rel_bits, REL_HWHEEL_HI_RES);
    info->is_synth_device = is_keysharp_synth_device_identity(
        info->name,
        info->bustype,
        info->vendor,
        info->product);

    ksi_device_info *public = &info->public_info;
    public->struct_size = sizeof(*public);
    public->bus_type = info->bustype;
    public->vendor = info->vendor;
    public->product = info->product;
    public->version = info->version;
    (void)snprintf(public->name, sizeof(public->name), "%s", info->name);
    (void)snprintf(public->path, sizeof(public->path), "%.*s",
        (int)sizeof(public->path) - 1, path);
    (void)ioctl(fd, EVIOCGPHYS(sizeof(public->physical) - 1u), public->physical);
    (void)ioctl(fd, EVIOCGUNIQ(sizeof(public->unique) - 1u), public->unique);
    info->is_synth_device |= is_forwarding_phys(public->physical);
    if (info->has_keyboard_keys) public->capabilities |= KSI_DEVICE_KEYBOARD | KSI_DEVICE_CAN_INTERCEPT_KEYBOARD;
    if (info->has_mouse_buttons && info->has_pointer_axes) public->capabilities |= KSI_DEVICE_MOUSE;
    if (test_bit(key_bits, BTN_TOOL_FINGER)) public->capabilities |= KSI_DEVICE_TOUCHPAD;
    if (test_bit(key_bits, BTN_TOOL_PEN) || test_bit(key_bits, BTN_TOOL_RUBBER)) public->capabilities |= KSI_DEVICE_TABLET;
    if (info->has_relative) public->capabilities |= KSI_DEVICE_RELATIVE;
    if (info->has_absolute) public->capabilities |= KSI_DEVICE_ABSOLUTE;
    if (info->requires_compositor_processing) public->capabilities |= KSI_DEVICE_RAW_OBSERVATION;
    if (info->is_gamepad) {
        public->capabilities |= KSI_DEVICE_GAMEPAD;
        collect_gamepad_buttons(key_bits, public);
    }
    if (info->high_resolution_wheel) public->capabilities |= KSI_DEVICE_HIGH_RESOLUTION_WHEEL;
    if (info->high_resolution_horizontal_wheel) public->capabilities |= KSI_DEVICE_HIGH_RESOLUTION_HORIZONTAL_WHEEL;
    if ((public->capabilities & KSI_DEVICE_MOUSE) != 0u && !info->requires_compositor_processing)
        public->capabilities |= KSI_DEVICE_CAN_INTERCEPT_MOUSE;
    for (uint32_t code = 0u; code < KSI_DEVICE_AXIS_CAPACITY; code++) {
        if (!test_bit(abs_bits, (int)code)) continue;
        struct input_absinfo abs;
        if (ioctl(fd, EVIOCGABS(code), &abs) != 0) continue;
        ksi_device_axis_info *axis = &public->axes[public->axis_count++];
        axis->struct_size = sizeof(*axis);
        axis->code = code;
        axis->minimum = abs.minimum;
        axis->maximum = abs.maximum;
        axis->fuzz = abs.fuzz;
        axis->flat = abs.flat;
        axis->resolution = abs.resolution;
    }

    close(fd);
    return 0;
}

static bool is_event_device_name(const char *name)
{
    return strncmp(name, KSI_EVENT_PREFIX, strlen(KSI_EVENT_PREFIX)) == 0;
}

static bool is_event_device_path(const char *path)
{
    const char *last_slash;

    if (path == NULL) {
        return false;
    }

    last_slash = strrchr(path, '/');
    return last_slash != NULL && is_event_device_name(last_slash + 1);
}

/* ID_SEAT is normally attached to the event node itself, but custom udev
 * rules may put it on an input parent. Walk the chain before applying the
 * documented default (no ID_SEAT anywhere means seat0). A missing or not-yet-
 * initialized udev object is different from a confirmed missing property:
 * metadata lookup races fail closed so a non-seat0 device is never opened
 * merely because its udev database record is incomplete. */
static bool udev_device_is_on_seat0(
    struct udev_device *device,
    const char **out_id_seat,
    bool *out_metadata_initialized)
{
    struct udev_device *current;
    const char *id_seat = NULL;
    bool metadata_initialized = false;

    if (device != NULL) {
        metadata_initialized = udev_device_get_is_initialized(device) > 0;
    }

    if (out_metadata_initialized != NULL) {
        *out_metadata_initialized = metadata_initialized;
    }

    if (metadata_initialized) {
        for (current = device; current != NULL; current = udev_device_get_parent(current)) {
            id_seat = ksi_linux_device_prefer_nearest_id_seat(
                id_seat,
                udev_device_get_property_value(current, "ID_SEAT"));

            if (id_seat != NULL) {
                break;
            }
        }
    }

    if (out_id_seat != NULL) {
        *out_id_seat = id_seat;
    }

    return ksi_linux_device_seat_metadata_is_admitted(
        metadata_initialized,
        id_seat);
}

static bool admit_udev_event_device(struct udev_device *device, const char *path, const char *reason)
{
    const char *id_seat = NULL;
    bool metadata_initialized = false;

    if (udev_device_is_on_seat0(device, &id_seat, &metadata_initialized)) {
        return true;
    }

    if (device == NULL || !metadata_initialized) {
        fprintf(stderr,
            "keysharp-input: %s %s ignored: udev metadata unavailable or not initialized "
            "(seat lookup failed closed)\n",
            reason,
            path);
    } else {
        fprintf(stderr,
            "keysharp-input: %s %s ignored: ID_SEAT=\"%s\" is outside seat0\n",
            reason,
            path,
            id_seat != NULL ? id_seat : "");
    }

    return false;
}

static bool udev_property_is_true(const char *value)
{
    return value != NULL && strcmp(value, "1") == 0;
}

static bool udev_hierarchy_requires_compositor_processing(struct udev_device *device)
{
    for (struct udev_device *current = device;
         current != NULL;
         current = udev_device_get_parent(current)) {
        if (udev_property_is_true(udev_device_get_property_value(current, "ID_INPUT_TOUCHPAD"))
            || udev_property_is_true(udev_device_get_property_value(current, "ID_INPUT_TOUCHSCREEN"))
            || udev_property_is_true(udev_device_get_property_value(current, "ID_INPUT_TABLET"))
            || udev_property_is_true(udev_device_get_property_value(current, "ID_INPUT_TABLET_PAD"))) {
            return true;
        }
    }

    return false;
}

static void apply_udev_device_metadata(
    ksi_linux_device_info *info,
    struct udev_device *device)
{
    if (info == NULL || device == NULL) {
        return;
    }

    info->requires_compositor_processing = info->requires_compositor_processing
        || udev_hierarchy_requires_compositor_processing(device);
    if (info->requires_compositor_processing) {
        info->public_info.capabilities &= ~(uint32_t)KSI_DEVICE_CAN_INTERCEPT_MOUSE;
        info->public_info.capabilities |= KSI_DEVICE_RAW_OBSERVATION;
    }
}

static bool is_candidate(const ksi_linux_device_info *info)
{
    return info->has_keyboard_keys || (info->has_mouse_buttons && info->has_pointer_axes);
}

/* Devices opened solely for idle tracking are never grabbed or hook-dispatched.
 * EV_KEY covers touchscreens/pens/gamepads/media keys as well as keyboards;
 * EV_REL covers pointer-like devices which may not advertise mouse buttons.
 * Deliberately exclude absolute-only sensors (accelerometers, light sensors):
 * their continuous EV_ABS reports are not evidence of user activity. */
static bool is_idle_candidate(const ksi_linux_device_info *info)
{
    return is_candidate(info) || info->has_keys || info->has_relative;
}

static bool is_keyboard_candidate(const ksi_linux_device_info *info)
{
    return info->has_keyboard_keys;
}

static bool is_mouse_candidate(const ksi_linux_device_info *info)
{
    return info->has_mouse_buttons && info->has_pointer_axes;
}

static bool is_mouse_hook_candidate(const ksi_linux_device_info *info)
{
    return is_mouse_candidate(info) && !info->requires_compositor_processing;
}

static bool is_mouse_block_candidate(const ksi_linux_device_info *info)
{
    return (info->has_mouse_buttons || info->requires_compositor_processing)
        && info->has_pointer_axes;
}

static void log_device(const ksi_linux_device_info *info, const char *prefix)
{
    fprintf(stderr, "keysharp-input: %s %s: \"%s\" candidate=%s%s%s%s%s%s%s\n",
        prefix,
        info->path,
        info->name,
        is_keyboard_candidate(info) ? "keyboard" : "",
        is_keyboard_candidate(info) && is_mouse_candidate(info) ? "," : "",
        is_mouse_candidate(info) ? "mouse" : "",
        info->has_relative ? " rel" : "",
        info->has_absolute ? " abs" : "",
        info->requires_compositor_processing ? " compositor-processed" : "",
        info->is_synth_device ? " injected" : "");
}

static ssize_t find_tracked_device(const char *path)
{
    for (size_t i = 0; i < tracked_device_count; i++) {
        if (strcmp(tracked_devices[i].path, path) == 0) {
            return (ssize_t)i;
        }
    }

    return -1;
}

static ssize_t find_tracked_device_by_fd(int fd)
{
    for (size_t i = 0; i < tracked_device_count; i++) {
        if (tracked_devices[i].fd == fd) {
            return (ssize_t)i;
        }
    }

    return -1;
}

static int read_leds(int fd)
{
    unsigned char leds;
    return fd >= 0 && ioctl(fd, EVIOCGLED(sizeof(leds)), &leds) >= 0 ? leds : -1;
}

/* Releasing a grab lets the console keyboard handler set that device's LEDs
 * to the console's state, so the state it had is written back. */
static void restore_leds(int fd, int saved)
{
    struct input_event events[CHAR_BIT + 1];
    int now = read_leds(fd);
    size_t count = 0u;

    if (saved < 0 || now < 0 || now == saved) return;
    for (uint16_t code = 0u; code < CHAR_BIT; code++)
        if (((now ^ saved) >> code & 1) != 0)
            events[count++] = (struct input_event){ .type = EV_LED, .code = code,
                .value = saved >> code & 1 };
    events[count++] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
    (void)ksi_linux_output_write(fd, events, count);
}

static int release_grab(int fd)
{
    int saved = read_leds(fd);
    int result = ioctl(fd, EVIOCGRAB, 0);
    int error = errno;

    restore_leds(fd, saved);
    errno = error;
    return result;
}

static void close_forwarding_device(ksi_linux_tracked_device *device)
{
    if (device->forwarding_target == 0u) {
    } else if (close_callback != NULL) {
        close_callback(forward_event_context, device->forwarding_target);
    } else {
        ksi_linux_forward_close(device->forwarding_target);
        ksi_linux_forward_apply_close(device->forwarding_target);
    }
    device->forwarding_target = 0u;
    device->forwarding_ready = false;
    memset(device->ungrab_held_keys, 0, sizeof(device->ungrab_held_keys));
}

/* A report read before a route change must not be completed on the new route. */
static void discard_pending_report(ksi_linux_tracked_device *device)
{
    device->has_pending_rel = false;
    device->has_pending_abs = false;
    device->pending_rel_x = device->pending_rel_y = 0;
    device->forward_report_lanes = 0u;
    device->has_pending_scan = false;
}

static void close_tracked_device(ksi_linux_tracked_device *device)
{
    close_forwarding_device(device);
    if (device->fd >= 0 && !device->injected_source) {
        device_generation++;
        if (device_change_callback != NULL)
            device_change_callback(observer_event_context, KSI_OBSERVER_DEVICE_REMOVED,
                &device->public_info, device_generation);
    }
    if (device->grabbed && device->fd >= 0) {
        (void)release_grab(device->fd);
        device->grabbed = false;
    }

    if (device->evdev != NULL) {
        libevdev_free(device->evdev);
        device->evdev = NULL;
    }

    if (device->fd >= 0) {
        close(device->fd);
        device->fd = -1;
    }

    device->grab_deferred = false;
    device->foreign_grab = false;
    device->deferred_to_tail = false;
    device->read_error = 0;
    device->event_clock_monotonic = false;
    device->has_buffered_event = false;
    device->synchronizing = false;
    discard_pending_report(device);
    memset(&device->buffered_event, 0, sizeof(device->buffered_event));
    memset(device->deferred_down_keys, 0, sizeof(device->deferred_down_keys));
    if (device->forwarding_sink) refresh_sink_admission();
}

/* Our own outputs are read only for the desktop's LED writes, so nothing we
 * write to them wakes the reader. */
static void read_leds_only(int fd)
{
    static const unsigned int types[] = { EV_KEY, EV_REL, EV_ABS, EV_MSC, EV_SW };

    for (size_t i = 0u; i < sizeof(types) / sizeof(types[0]); i++) {
        struct input_mask mask = { .type = types[i] };
        (void)ioctl(fd, EVIOCSMASK, &mask);
    }
}

static int open_tracked_device(ksi_linux_tracked_device *device)
{
    int fd;
    int result;
    int clock_id = CLOCK_MONOTONIC;

    close_tracked_device(device);

    /* Write access lets desktop LED state reach a grabbed keyboard. */
    fd = open(device->path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) fd = open_event_fd(device->path);

    if (fd < 0) {
        return -1;
    }

    /* Make evdev input_event timestamps comparable with daemon monotonic time.
     * Older kernels may reject this; in that case event ordering still works
     * best-effort with the device's default clock. */
    device->event_clock_monotonic = ioctl(fd, EVIOCSCLOCKID, &clock_id) == 0;

    result = libevdev_new_from_fd(fd, &device->evdev);

    if (result < 0) {
        fprintf(stderr, "keysharp-input: cannot initialize libevdev for %s: %s\n",
            device->path,
            strerror(-result));
        close(fd);
        device->evdev = NULL;
        return -1;
    }

    device->fd = fd;
    if (device->injected_source) read_leds_only(fd);
    return 0;
}

static int scale_abs_axis(int32_t value, int32_t minimum, int32_t maximum)
{
    int64_t numerator;
    int64_t denominator;

    if (maximum <= minimum) {
        return value;
    }

    if (value < minimum) {
        value = minimum;
    } else if (value > maximum) {
        value = maximum;
    }

    numerator = (int64_t)(value - minimum) * 65535;
    denominator = (int64_t)maximum - minimum;
    return (int32_t)(numerator / denominator);
}

static void update_absolute_axis_ranges(ksi_linux_tracked_device *device)
{
    const struct input_absinfo *abs_x;
    const struct input_absinfo *abs_y;

    device->abs_x_min = 0;
    device->abs_x_max = 65535;
    device->abs_y_min = 0;
    device->abs_y_max = 65535;
    device->current_abs_x = 0;
    device->current_abs_y = 0;
    device->current_abs_x_raw = 0;
    device->current_abs_y_raw = 0;

    if (device->evdev == NULL) {
        return;
    }

    abs_x = libevdev_get_abs_info(device->evdev, ABS_X);
    abs_y = libevdev_get_abs_info(device->evdev, ABS_Y);

    if (abs_x != NULL) {
        device->abs_x_min = abs_x->minimum;
        device->abs_x_max = abs_x->maximum;
        device->current_abs_x_raw = abs_x->value;
        device->current_abs_x = scale_abs_axis(abs_x->value, device->abs_x_min, device->abs_x_max);
    }

    if (abs_y != NULL) {
        device->abs_y_min = abs_y->minimum;
        device->abs_y_max = abs_y->maximum;
        device->current_abs_y_raw = abs_y->value;
        device->current_abs_y = scale_abs_axis(abs_y->value, device->abs_y_min, device->abs_y_max);
    }
}

static bool needs_forwarding(const ksi_linux_tracked_device *device)
{
    return (device->keyboard_candidate && (block_input_mask & KSI_BLOCK_KEYBOARD) == 0u)
        || (device->mouse_block_candidate && (block_input_mask & KSI_BLOCK_MOUSE) == 0u);
}

/* Every source that may be grabbed keeps forwarding registered, since a clone
 * made on hook demand would make the client wait for udev. A failed clone is
 * retired first so the kernel releases whatever it still holds. */
static void ensure_forwarding(ksi_linux_tracked_device *device)
{
    if (!forwarding_enabled || device->injected_source || device->fd < 0
        || !(device->keyboard_candidate || device->mouse_block_candidate)
        || !ksi_linux_forward_failed(device->forwarding_target, KSI_FORWARD_ENQUEUED))
        return;
    close_forwarding_device(device);
    device->forwarding_target = ksi_linux_forward_open(device->fd, device->keyboard_candidate);
    device->forwarding_ready = device->forwarding_target != 0u
        && !ksi_linux_forward_has_clone(device->forwarding_target);
    if (device->forwarding_target == 0u)
        fprintf(stderr, "keysharp-input: cannot create forwarding clone for %s (\"%s\")\n",
            device->path, device->name);
}

/* Passed input reaches the desktop only through outputs udev has admitted: a
 * keyboard's keys go to the sink, and the rest of a source to its clone. */
static bool forwarding_usable(const ksi_linux_tracked_device *device)
{
    return device->forwarding_ready
        && !ksi_linux_forward_failed(device->forwarding_target, KSI_FORWARD_ENQUEUED)
        && (!device->keyboard_candidate || (sink_admitted && ksi_linux_forward_sink_ready()
            && sink_admitted_generation == ksi_linux_forward_sink_generation()));
}

/* A recreated sink replaces the node the reader admitted, so admission counts
 * only for a node udev initialized after the old sink was detached. */
static void refresh_sink_admission(void)
{
    sink_admitted = false;
    for (size_t i = 0u; i < tracked_device_count; i++) {
        const ksi_linux_tracked_device *device = &tracked_devices[i];

        if (!device->forwarding_sink || device->fd < 0) continue;
        if (!sink_admitted || device->sink_generation > sink_admitted_generation)
            sink_admitted_generation = device->sink_generation;
        sink_admitted = true;
    }
}

/* The end of a grab must reach both key-state views at one queue position,
 * so the daemon queues it; without a daemon it applies at once. */
static uint64_t end_forward_grab(uint64_t target, uint8_t *kept)
{
    uint64_t next;

    if (end_grab_callback != NULL) return end_grab_callback(forward_event_context, target, kept);
    next = ksi_linux_forward_end_grab(target, kept);
    ksi_linux_forward_apply_end_grab(next, NULL);
    return next;
}

/* Tool and touch codes stay down under a resting pen or thumb; a pen's barrel
 * buttons are pressed like any other button. */
static bool is_contact_code(unsigned int code)
{
    return (code >= BTN_TOOL_PEN && code <= BTN_TOOL_QUINTTAP) || code == BTN_TOUCH
        || (code >= BTN_TOOL_DOUBLETAP && code <= BTN_TOOL_QUADTAP);
}

/* A grab taken mid-press would leave the desktop holding what it saw pressed
 * on the source, so it waits until every key and button is released. */
static bool defer_grab_while_held(ksi_linux_tracked_device *device)
{
    (void)ksi_read_key_bytes(device->fd, device->deferred_down_keys);
    for (uint16_t code = BTN_DIGI; code <= BTN_TOOL_QUADTAP; code++)
        if (is_contact_code(code)) ksi_set_key_bit(device->deferred_down_keys, code, false);
    device->grab_deferred = ksi_any_key_bit(device->deferred_down_keys);
    if (device->grab_deferred)
        fprintf(stderr, "keysharp-input: deferred grab %s until active keys are released\n", device->path);
    return device->grab_deferred;
}

/* Handles everything already queued under the grab state it arrived in. */
static void drain_device_events(ksi_linux_tracked_device *device)
{
    for (int pass = 0; pass < KSI_MAX_DRAIN_PASSES && !reading_device_events && device->evdev != NULL
            && (device->has_buffered_event || libevdev_has_event_pending(device->evdev) == 1); pass++)
        process_device_events(device);
}

static int set_device_grab(ksi_linux_tracked_device *device, bool enabled)
{
    if (device->fd < 0) {
        device->grab_deferred = false;
        return 0;
    }

    if (device->injected_source) {
        device->grab_deferred = false;

        if (device->grabbed) {
            if (release_grab(device->fd) != 0) {
                fprintf(stderr,
                    "keysharp-input: EVIOCGRAB(off) failed for injected source %s: %s; closing device\n",
                    device->path,
                    strerror(errno));
                close_tracked_device(device);
                return -1;
            }

            device->grabbed = false;
            fprintf(stderr, "keysharp-input: ungrabbed injected source %s\n", device->path);
        }

        return 0;
    }

    if (!enabled && device->grabbed) {
        drain_device_events(device);
        if (device->fd < 0) return 0;
    }

    if (!enabled) {
        device->grab_deferred = false;
        device->deferred_to_tail = false;

        if (!device->grabbed) {
            device->foreign_grab = false;
            return 0;
        }
    } else if (device->grabbed) {
        /* A grab taken for BlockInput alone may now have to pass input on. */
        if (!needs_forwarding(device) || forwarding_usable(device)) return 0;
        if (set_device_grab(device, false) != 0) return -1;
    }

    if (enabled && needs_forwarding(device)) {
        /* Without working outputs the source stays ungrabbed; the retry path
         * replaces a failed clone, and each output's udev admission regrabs. */
        if (ksi_linux_forward_failed(device->forwarding_target, KSI_FORWARD_ENQUEUED)) return -1;
        if (!forwarding_usable(device)) return 0;
    }

    if (enabled && defer_grab_while_held(device)) return 0;

    if (enabled && !device->foreign_grab && grab_would_feed_downstream(device)) {
        if (!device->deferred_to_tail)
            fprintf(stderr,
                "keysharp-input: not grabbing %s (\"%s\"): our output is grabbed downstream; "
                "deferring to the tail interceptor\n",
                device->path, device->name);
        device->deferred_to_tail = true;
        return 0;
    }

    if (enabled) {
        /* The probe is slow: what arrived during it already reached the
         * desktop, a key pressed during it holds the grab off, and releases
         * still owed downstream go out before the grab would lose them. */
        drain_device_events(device);
        settle_ungrab_holds(device);
        if (device->fd < 0 || defer_grab_while_held(device)
            || ksi_any_key_bit(device->ungrab_held_keys)) return 0;
    }

    if ((enabled ? ioctl(device->fd, EVIOCGRAB, 1) : release_grab(device->fd)) != 0) {
        int error = errno;
        bool foreign = enabled && error == EBUSY;

        /* Another interceptor keeps a source until it exits, so say so once. */
        if (!foreign || !device->foreign_grab)
            fprintf(stderr, "keysharp-input: EVIOCGRAB(%s) failed for %s: %s\n",
                enabled ? "on" : "off", device->path, strerror(error));
        device->foreign_grab = foreign;
        if (!enabled) {
            /* Closing the evdev fd is the kernel-level fail-open fallback when
             * EVIOCGRAB(off) itself fails. */
            close_tracked_device(device);
        }

        return -1;
    }

    device->grabbed = enabled;
    device->foreign_grab = false;
    device->deferred_to_tail = false;
    discard_pending_report(device);

    if (enabled) {
        ksi_linux_forward_sync_switches(device->forwarding_target);
    } else if (device->forwarding_target != 0u) {
        device->forwarding_target = end_forward_grab(device->forwarding_target,
            device->ungrab_held_keys);
    }
    fprintf(stderr, "keysharp-input: %s %s\n", enabled ? "grabbed" : "ungrabbed", device->path);
    return 0;
}

/* A deferred grab starts from the main loop once a report leaves nothing held,
 * so what is still queued behind that report is handled as ungrabbed first. */
static void process_deferred_grab_event(ksi_linux_tracked_device *device, const struct input_event *event)
{
    if (!device->grab_deferred) return;
    if (event->type == EV_KEY && event->code <= KEY_MAX && !is_contact_code(event->code)) {
        ksi_set_key_bit(device->deferred_down_keys, event->code, event->value != 0);
    } else if (event->type == EV_SYN && event->code == SYN_REPORT
        && !ksi_any_key_bit(device->deferred_down_keys)) {
        device->grab_deferred = false;
        grab_state_incomplete = true;
        last_grab_retry_ms = 0u;
    }
}

static bool should_grab_device_for_masks(
    const ksi_linux_tracked_device *device,
    uint32_t hook_mask,
    uint32_t block_mask)
{
    if (device == NULL || device->injected_source) {
        return false;
    }

    return (((hook_mask & KSI_OPERATION_HOOK_KEYBOARD) != 0
             || (block_mask & KSI_BLOCK_KEYBOARD) != 0)
            && device->keyboard_candidate)
        || ((hook_mask & KSI_OPERATION_HOOK_MOUSE) != 0
            && device->mouse_hook_candidate)
        || ((block_mask & KSI_BLOCK_MOUSE) != 0
            && device->mouse_block_candidate);
}

static ksi_linux_tracked_device *clone_source(const ksi_linux_tracked_device *clone)
{
    uint64_t target = ksi_linux_forward_target_for_path(clone->path);

    for (size_t i = 0; target != 0u && i < tracked_device_count; i++)
        if (tracked_devices[i].forwarding_target == target) return &tracked_devices[i];
    return NULL;
}

/* evdev has no query for a grab, so the node is probed on a fresh descriptor;
 * one that cannot be opened is gone. The probe's own release resets the
 * node's LEDs, which the tracked descriptor writes back. */
static bool node_is_grabbed(const ksi_linux_tracked_device *output)
{
    int saved = read_leds(output->fd);
    int fd = open(output->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    bool grabbed = fd >= 0 && ksi_linux_output_probe_grabbed(fd) > 0;

    restore_leds(output->fd, saved);
    if (fd >= 0) close(fd);
    return grabbed;
}

/* Whether another process holds an output carrying our traffic. Remappers
 * that match by name or vendor also grab idle clones, so a clone counts only
 * while its source is grabbed. */
static bool output_carries_traffic(const ksi_linux_tracked_device *output)
{
    const ksi_linux_tracked_device *source;

    return output->injected_source && (!output->forwarding_clone
        || ((source = clone_source(output)) != NULL && source->grabbed));
}

/* A probe of an ungrabbed output waits for the kernel to release its own grab,
 * stalling all output meanwhile, while a grabbed one refuses at once, so the
 * output found grabbed last time is probed first. */
static bool our_output_is_grabbed(void)
{
    static uint32_t last_grabbed_id;

    for (size_t i = 0; i < tracked_device_count; i++)
        if (tracked_devices[i].device_id == last_grabbed_id && output_carries_traffic(&tracked_devices[i])
            && node_is_grabbed(&tracked_devices[i]))
            return true;
    for (size_t i = 0; i < tracked_device_count; i++) {
        if (tracked_devices[i].device_id == last_grabbed_id || !output_carries_traffic(&tracked_devices[i])
            || !node_is_grabbed(&tracked_devices[i])) continue;
        last_grabbed_id = tracked_devices[i].device_id;
        return true;
    }
    return false;
}

/* Only the tail of an interceptor chain grabs, or our output would come back to
 * us. The probe stalls output, so it runs once per pass and only for a grab that
 * can start now; a grab it allows adds only its own clone, probed here. */
static bool grab_would_feed_downstream(const ksi_linux_tracked_device *source)
{
    if (outputs_grabbed < 0) outputs_grabbed = our_output_is_grabbed() ? 1 : 0;
    if (outputs_grabbed > 0) return true;
    for (size_t i = 0; i < tracked_device_count; i++)
        if (tracked_devices[i].forwarding_clone && clone_source(&tracked_devices[i]) == source)
            return node_is_grabbed(&tracked_devices[i]);
    return false;
}

/* udev admits a node only after initializing it, so tracking a clone is what
 * makes its source safe to grab: the desktop can already read the clone. */
static void forwarding_clone_admitted(const ksi_linux_tracked_device *clone)
{
    ksi_linux_tracked_device *source = clone_source(clone);

    if (source == NULL || source->forwarding_ready) return;
    source->forwarding_ready = true;
    grab_state_incomplete = true;
    last_grab_retry_ms = 0u;
}

/* Applies the current masks to one device; true when a later retry is needed.
 * A deferred grab starts itself once the device's keys are released. */
static bool apply_grab_masks(ksi_linux_tracked_device *device)
{
    bool should_grab = should_grab_device_for_masks(device, grab_hook_mask, block_input_mask);

    if (set_device_grab(device, should_grab) != 0) return true;
    return should_grab && !device->grabbed && !device->grab_deferred && device->fd >= 0;
}

static void track_device(const ksi_linux_device_info *info, const char *reason)
{
    ssize_t existing_index = find_tracked_device(info->path);
    ksi_linux_tracked_device *target;

    if (!is_idle_candidate(info)) {
        return;
    }

    if (existing_index >= 0) {
        target = &tracked_devices[existing_index];
    } else {
        if (tracked_device_count >= KSI_MAX_TRACKED_DEVICES) {
            fprintf(stderr, "keysharp-input: cannot track %s: device table is full\n", info->path);
            return;
        }

        target = &tracked_devices[tracked_device_count++];
        memset(target, 0, sizeof(*target));
        target->fd = -1;
    }

    (void)snprintf(target->path, sizeof(target->path), "%s", info->path);
    (void)snprintf(target->name, sizeof(target->name), "%s", info->name);
    target->keyboard_candidate = is_keyboard_candidate(info);
    target->mouse_candidate = is_mouse_candidate(info);
    target->mouse_hook_candidate = is_mouse_hook_candidate(info);
    target->mouse_block_candidate = is_mouse_block_candidate(info);
    target->injected_source = info->is_synth_device;
    target->raw_observation_candidate = info->requires_compositor_processing;
    target->high_resolution_wheel = info->high_resolution_wheel;
    target->high_resolution_horizontal_wheel = info->high_resolution_horizontal_wheel;
    target->forwarding_clone = is_forwarding_phys(info->public_info.physical);
    target->forwarding_sink = is_sink_identity(info);
    bool newly_opened = target->fd < 0;
    /* A new or reopened node gets a new identity, like a replugged device. */
    if (newly_opened) target->device_id = next_device_id++;
    ksi_device_info public_info = info->public_info;
    public_info.device_id = target->device_id;
    bool changed = memcmp(&target->public_info, &public_info, sizeof(public_info)) != 0;
    target->public_info = public_info;

    if (newly_opened) {
        if (open_tracked_device(target) != 0) {
            return;
        }

        update_absolute_axis_ranges(target);
        if (target->forwarding_clone) forwarding_clone_admitted(target);
        /* Keyboards wait for the sink as sources wait for their clones. */
        if (target->forwarding_sink) {
            target->sink_generation = ksi_linux_forward_sink_generation();
            refresh_sink_admission();
            grab_state_incomplete = true;
            last_grab_retry_ms = 0u;
        }
    }

    ensure_forwarding(target);

    if (!target->injected_source && (changed || newly_opened)) {
        device_generation++;
        if (device_change_callback != NULL)
            device_change_callback(observer_event_context,
                newly_opened ? KSI_OBSERVER_DEVICE_ADDED : KSI_OBSERVER_DEVICE_CHANGED,
                &target->public_info, device_generation);
    }

    outputs_grabbed = -1;
    grab_state_incomplete |= apply_grab_masks(target);

    log_device(info, reason);
}

static void untrack_device(const char *path)
{
    ssize_t existing_index = find_tracked_device(path);
    size_t index;

    if (existing_index < 0) {
        return;
    }

    index = (size_t)existing_index;

    fprintf(stderr, "keysharp-input: remove %s: \"%s\"\n",
        tracked_devices[index].path,
        tracked_devices[index].name);

    close_tracked_device(&tracked_devices[index]);

    for (size_t i = index; i + 1 < tracked_device_count; i++) {
        tracked_devices[i] = tracked_devices[i + 1];
    }

    tracked_device_count--;
}

static void scan_existing_devices(void)
{
    DIR *dir;
    struct dirent *entry;
    struct udev *scan_udev;
    int devices_seen = 0;
    int candidates_seen = 0;

    dir = opendir(KSI_INPUT_DIR);

    if (dir == NULL) {
        fprintf(stderr, "keysharp-input: cannot open %s: %s\n", KSI_INPUT_DIR, strerror(errno));
        return;
    }

    /* The monitor owns the long-lived context when available. In degraded
     * no-monitor mode, create a temporary context solely for admission. */
    scan_udev = udev_context != NULL ? udev_ref(udev_context) : udev_new();

    if (scan_udev == NULL) {
        fprintf(stderr,
            "keysharp-input: cannot create udev context for seat0 filtering; skipping input devices\n");
        closedir(dir);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        ksi_linux_device_info info;
        struct udev_device *udev_device;
        bool idle_candidate;

        if (!is_event_device_name(entry->d_name)) {
            continue;
        }

        if (snprintf(path, sizeof(path), "%s/%s", KSI_INPUT_DIR, entry->d_name) >= (int)sizeof(path)) {
            fprintf(stderr, "keysharp-input: skipping too-long input path for %s\n", entry->d_name);
            continue;
        }

        devices_seen++;

        udev_device = udev_device_new_from_subsystem_sysname(
            scan_udev,
            "input",
            entry->d_name);

        if (!admit_udev_event_device(udev_device, path, "existing")) {
            if (udev_device != NULL) {
                udev_device_unref(udev_device);
            }

            continue;
        }

        if (read_device_info(path, &info) != 0) {
            udev_device_unref(udev_device);
            continue;
        }

        apply_udev_device_metadata(&info, udev_device);
        udev_device_unref(udev_device);

        idle_candidate = is_idle_candidate(&info);

        if (idle_candidate) {
            candidates_seen++;
            track_device(&info, "existing");
        }
    }

    udev_unref(scan_udev);
    closedir(dir);

    fprintf(stderr, "keysharp-input: scanned %d event devices, found %d user-input candidates\n",
        devices_seen,
        candidates_seen);
}

void ksi_linux_devices_enable_forwarding(void)
{
    forwarding_enabled = true;
    scan_existing_devices();
}

static void stop_udev_monitor(void)
{
    if (udev_monitor != NULL) {
        udev_monitor_unref(udev_monitor);
        udev_monitor = NULL;
    }

    if (udev_context != NULL) {
        udev_unref(udev_context);
        udev_context = NULL;
    }
}

static int start_udev_monitor(void)
{
    udev_context = udev_new();

    if (udev_context == NULL) {
        fprintf(stderr, "keysharp-input: failed to create udev context\n");
        return -1;
    }

    udev_monitor = udev_monitor_new_from_netlink(udev_context, "udev");

    if (udev_monitor == NULL) {
        fprintf(stderr, "keysharp-input: failed to create udev monitor\n");
        stop_udev_monitor();
        return -1;
    }

    if (udev_monitor_filter_add_match_subsystem_devtype(
            udev_monitor,
            "input",
            NULL) < 0) {
        fprintf(stderr, "keysharp-input: failed to install udev input filter\n");
        stop_udev_monitor();
        return -1;
    }

    if (udev_monitor_enable_receiving(udev_monitor) < 0) {
        fprintf(stderr, "keysharp-input: failed to enable udev monitor\n");
        stop_udev_monitor();
        return -1;
    }

    fprintf(stderr, "keysharp-input: udev hotplug monitor enabled\n");
    return 0;
}

static void handle_device_add_or_change(
    struct udev_device *udev_device,
    const char *path,
    const char *action)
{
    ksi_linux_device_info info;

    if (!admit_udev_event_device(udev_device, path, action)) {
        /* A change event can move an already-tracked device to another seat.
         * Release its grab and fd before any further event processing. */
        untrack_device(path);
        return;
    }

    if (read_device_info(path, &info) != 0) {
        return;
    }

    apply_udev_device_metadata(&info, udev_device);

    if (!is_idle_candidate(&info)) {
        fprintf(stderr, "keysharp-input: %s %s ignored: not a user-input candidate\n", action, path);
        return;
    }

    track_device(&info, action);
}

int ksi_linux_devices_start(void)
{
    tracked_device_count = 0;
    grab_hook_mask = 0;
    block_input_mask = 0;
    grab_state_incomplete = false;
    memset(&current_pointer_position, 0, sizeof(current_pointer_position));
    last_input_activity_ms = 0u;

    /* Start the udev monitor BEFORE enumerating existing devices -- the same
     * order keyd itself uses (evloop.c: devmon_create() before device_scan()).
     * A device that appears between udev_monitor_enable_receiving() and the
     * enumeration below queues on the (now-open) netlink socket and is picked
     * up later by process_udev_events(); track_device() dedups by path, so a
     * device that both paths independently see is a harmless no-op on the
     * second sighting. The reverse order (enumerate-then-watch) leaves a gap
     * where a device created after the enumeration finishes but before the
     * monitor goes live is invisible to both paths, permanently -- notably
     * including keyd's own persistent virtual keyboard, which (unlike a
     * physical device) is never recreated on a later replug to give the
     * monitor a second chance. */
    if (start_udev_monitor() != 0) {
        fprintf(stderr, "keysharp-input: warning: udev monitor unavailable; hotplug disabled\n");
        /* Continue in degraded mode: existing devices are tracked but newly
         * plugged devices will not be detected at runtime. */
    }

    scan_existing_devices();

    return 0;
}

static void forward_release_after_ungrab(
    ksi_linux_tracked_device *device, const struct input_event *event);

/* A release owed to the source's outputs can be refused by a full queue, or
 * taken by another program that grabbed the source; the kernel's key state
 * settles it. */
static void settle_ungrab_holds(ksi_linux_tracked_device *device)
{
    uint8_t keys[KSI_KEY_BITMAP_BYTES];

    if (device->grabbed || !ksi_any_key_bit(device->ungrab_held_keys)
        || !ksi_read_key_bytes(device->fd, keys)) return;
    for (size_t byte = 0u; byte < KSI_KEY_BITMAP_BYTES; byte++) {
        for (unsigned int bits = device->ungrab_held_keys[byte] & (uint8_t)~keys[byte];
                bits != 0u; bits &= bits - 1u) {
            const struct input_event release = { .type = EV_KEY,
                .code = (uint16_t)(byte * 8u + (unsigned int)__builtin_ctz(bits)), .value = 0 };
            forward_release_after_ungrab(device, &release);
        }
    }
}

/* Settles owed releases, retries incomplete grabs after transient contention
 * clears, and replaces clones whose writes failed. */
void ksi_linux_devices_retry_incomplete_grabs(void)
{
    uint64_t now;

    for (size_t i = 0u; i < tracked_device_count; i++)
        settle_ungrab_holds(&tracked_devices[i]);

    if (ksi_linux_forward_take_failure()) {
        for (size_t i = 0u; i < tracked_device_count; i++) {
            ksi_linux_tracked_device *device = &tracked_devices[i];
            bool clone_failed = device->forwarding_target != 0u
                && ksi_linux_forward_failed(device->forwarding_target, KSI_FORWARD_ENQUEUED);

            if (!clone_failed && (!device->grabbed || !needs_forwarding(device) || forwarding_usable(device)))
                continue;
            /* A dead output cannot pass input on, so its source fails open. */
            if (device->grabbed) (void)set_device_grab(device, false);
            if (clone_failed) close_forwarding_device(device);
            grab_state_incomplete = true;
        }
    }
    if (!grab_state_incomplete) return;

    now = ksi_linux_monotonic_ms();

    if (now != 0 && last_grab_retry_ms != 0 && now - last_grab_retry_ms < KSI_GRAB_RETRY_INTERVAL_MS) {
        return;
    }

    last_grab_retry_ms = now;
    /* Without a hotplug monitor, only a rescan admits newly initialized clones. */
    if (udev_monitor == NULL && forwarding_enabled) scan_existing_devices();
    for (size_t i = 0u; i < tracked_device_count; i++)
        if (should_grab_device_for_masks(&tracked_devices[i], grab_hook_mask, block_input_mask))
            ensure_forwarding(&tracked_devices[i]);
    (void)set_grab_masks(grab_hook_mask, block_input_mask);
}

void ksi_linux_devices_stop(void)
{
    for (size_t i = 0; i < tracked_device_count; i++) {
        close_tracked_device(&tracked_devices[i]);
    }

    stop_udev_monitor();

    tracked_device_count = 0;
    forwarding_enabled = false;
    memset(&current_pointer_position, 0, sizeof(current_pointer_position));
    last_input_activity_ms = 0u;
}

bool ksi_linux_devices_has_candidates(void)
{
    for (size_t i = 0; i < tracked_device_count; i++) {
        if (!tracked_devices[i].injected_source
            && (tracked_devices[i].keyboard_candidate
                || tracked_devices[i].mouse_candidate
                || tracked_devices[i].mouse_block_candidate)) {
            return true;
        }
    }

    return false;
}

static int set_grab_masks(uint32_t hook_mask, uint32_t block_mask)
{
    bool incomplete = false;

    if (!grab_state_incomplete
        && grab_hook_mask == hook_mask
        && block_input_mask == block_mask) {
        return 0;
    }

    /* set_device_grab reads block_input_mask through needs_forwarding. */
    grab_hook_mask = hook_mask;
    block_input_mask = block_mask;

    /* Each device on its own: one node that cannot be grabbed, such as a
     * wireless receiver's extra consumer-control node, must not stop the
     * others from hooking or blocking. */
    outputs_grabbed = -1;
    for (size_t i = 0; i < tracked_device_count; i++)
        incomplete |= apply_grab_masks(&tracked_devices[i]);
    grab_state_incomplete = incomplete;
    ksi_linux_devices_refresh_indicator_state();
    return 0;
}

int ksi_linux_devices_set_grab_hook_mask(uint32_t hook_mask)
{
    return set_grab_masks(hook_mask, block_input_mask);
}

int ksi_linux_devices_set_block_input_mask(uint32_t block_mask)
{
    return set_grab_masks(grab_hook_mask, block_mask);
}

static nfds_t add_poll_fd(struct pollfd *fds, nfds_t max_fds, nfds_t count, int fd)
{
    if (fd < 0 || count >= max_fds) {
        return count;
    }

    fds[count].fd = fd;
    fds[count].events = POLLIN;
    return count + 1;
}

nfds_t ksi_linux_devices_poll_fds(struct pollfd *fds, nfds_t max_fds)
{
    nfds_t count = 0;

    if (udev_monitor != NULL) {
        count = add_poll_fd(fds, max_fds, count, udev_monitor_get_fd(udev_monitor));
    }

    for (size_t i = 0; i < tracked_device_count; i++) {
        count = add_poll_fd(fds, max_fds, count, tracked_devices[i].fd);
    }

    return count;
}

static uint64_t event_time_ms(const struct input_event *event)
{
    uint64_t seconds = (uint64_t)event->input_event_sec;
    uint64_t useconds = (uint64_t)event->input_event_usec;
    return (seconds * 1000u) + (useconds / 1000u);
}

static uint64_t event_time_ns(const struct input_event *event)
{
    uint64_t seconds = (uint64_t)event->input_event_sec;
    uint64_t useconds = (uint64_t)event->input_event_usec;
    return (seconds * 1000000000u) + (useconds * 1000u);
}

static uint32_t evdev_key_to_vk(unsigned int code)
{
    return ksi_evdev_to_vk(code);
}

static uint32_t evdev_key_to_message(const struct input_event *event)
{
    if (event->value == 0) {
        return KSI_MESSAGE_KEY_UP;
    }

    return KSI_MESSAGE_KEY_DOWN;
}

static uint32_t evdev_key_to_flags(const struct input_event *event)
{
    uint32_t flags = 0;

    switch (event->code) {
        case KEY_RIGHTCTRL:
        case KEY_RIGHTALT:
        case KEY_INSERT:
        case KEY_DELETE:
        case KEY_HOME:
        case KEY_END:
        case KEY_PAGEUP:
        case KEY_PAGEDOWN:
        case KEY_UP:
        case KEY_DOWN:
        case KEY_LEFT:
        case KEY_RIGHT:
        case KEY_KPSLASH:
        case KEY_KPENTER:
            flags |= KSI_KEYBOARD_HOOK_EXTENDED;
            break;
        default:
            break;
    }

    if (event->value == 0) {
        flags |= KSI_KEYBOARD_HOOK_UP;
    }
    if (event->value == 2) {
        flags |= KSI_KEYBOARD_HOOK_REPEAT;
    }

    return flags;
}

static uint32_t keyboard_injected_flags(bool is_injected)
{
    return is_injected ? KSI_KEYBOARD_HOOK_INJECTED : 0u;
}

static uint32_t keyboard_indicator_flags(void)
{
    uint32_t flags = 0;
    if (current_caps_lock)   flags |= KSI_KEYBOARD_HOOK_CAPS_LOCK_ON;
    if (current_num_lock)    flags |= KSI_KEYBOARD_HOOK_NUM_LOCK_ON;
    if (current_scroll_lock) flags |= KSI_KEYBOARD_HOOK_SCROLL_LOCK_ON;
    return flags;
}

static uint32_t mouse_injected_flags(bool is_injected)
{
    return is_injected ? KSI_MOUSE_HOOK_INJECTED : 0u;
}

static bool should_dispatch_hook_input(const ksi_linux_tracked_device *device)
{
    return device != NULL && device->grabbed && !device->injected_source;
}

/* Each lane carrying part of a report must also carry its SYN_REPORT. */
static void mark_forward_report_lane(
    ksi_linux_tracked_device *device, uint32_t hook_type,
    const ksi_forward_packet *replay)
{
    if (replay->count == 0u || (replay->flags & KSI_FORWARD_REPORT_END) != 0u
        || !device->grabbed || device->forwarding_target == 0u) return;
    device->forward_report_lanes |= hook_type == KSI_HOOK_MOUSE
        ? KSI_FORWARD_REPORT_MOUSE : KSI_FORWARD_REPORT_KEYBOARD;
}

static void append_forward_event(ksi_forward_packet *packet, uint16_t type, uint16_t code, int32_t value)
{
    packet->events[packet->count].type = type;
    packet->events[packet->count].code = code;
    packet->events[packet->count++].value = value;
}

static bool buffer_next_device_event(ksi_linux_tracked_device *device);

/* The kernel queues a report whole, so the rest of it is already readable. */
static const struct input_event *peek_report_event(ksi_linux_tracked_device *device)
{
    return buffer_next_device_event(device) ? &device->buffered_event : NULL;
}

/* Each lane's packets go to the device that carries its events, so a lane
 * ends its report where it wrote: the keyboard lane on the sink, the mouse
 * lane on the source's clone. */
static ksi_forward_packet lane_packet(const ksi_linux_tracked_device *device, uint32_t hook_type)
{
    return (ksi_forward_packet){ .target = device->forwarding_target,
        .flags = hook_type == KSI_HOOK_MOUSE ? KSI_FORWARD_CLONE : 0u };
}

/* A key or button carries its report's scan code, and a key, button or wheel
 * step that is its report's only fragment carries the report's SYN_REPORT, so
 * a keystroke or wheel notch is one packet. */
static ksi_forward_packet forward_fragment(
    ksi_linux_tracked_device *device, uint32_t hook_type, const struct input_event *event)
{
    ksi_forward_packet packet = lane_packet(device, hook_type);
    const struct input_event *next;

    if (device->has_pending_scan && event->type == EV_KEY)
        append_forward_event(&packet, EV_MSC, MSC_SCAN, device->pending_scan);
    device->has_pending_scan = false;
    append_forward_event(&packet, event->type, event->code, event->value);
    if ((event->type == EV_KEY || event->type == EV_REL) && device->grabbed
        && device->forward_report_lanes == 0u && (next = peek_report_event(device)) != NULL
        && next->type == EV_SYN && next->code == SYN_REPORT)
        packet.flags |= KSI_FORWARD_REPORT_END;
    return packet;
}

static bool hooks_event(const ksi_linux_tracked_device *device, uint32_t hook_type)
{
    return should_dispatch_hook_input(device) && hook_event_callback != NULL
        && (hook_type != KSI_HOOK_MOUSE || device->mouse_hook_candidate);
}

static void deliver_device_event(ksi_linux_tracked_device *device,
    uint32_t hook_type, const void *event, size_t size, const ksi_forward_packet *replay)
{
    if (observer_event_callback != NULL && !device->injected_source)
        observer_event_callback(observer_event_context, hook_type, event, size);
    if (hooks_event(device, hook_type)) {
        mark_forward_report_lane(device, hook_type, replay);
        hook_event_callback(hook_event_context, hook_type, event, size, replay);
    }
}

/* The packet is built only for a hook, since building it takes the report's
 * scan code, which an unhooked event forwards itself. */
static void deliver_physical_event(ksi_linux_tracked_device *device,
    uint32_t hook_type, const void *event, size_t size, const struct input_event *raw)
{
    ksi_forward_packet replay = { 0 };

    if (hooks_event(device, hook_type)) replay = forward_fragment(device, hook_type, raw);
    deliver_device_event(device, hook_type, event, size, &replay);
}

static bool evdev_button_to_mouse_message(unsigned int code, int value, uint32_t *message)
{
    if (value != 0 && value != 1) {
        return false;
    }

    switch (code) {
        case BTN_LEFT:
            *message = value != 0 ? KSI_MESSAGE_LEFT_BUTTON_DOWN : KSI_MESSAGE_LEFT_BUTTON_UP;
            return true;
        case BTN_RIGHT:
            *message = value != 0 ? KSI_MESSAGE_RIGHT_BUTTON_DOWN : KSI_MESSAGE_RIGHT_BUTTON_UP;
            return true;
        case BTN_MIDDLE:
            *message = value != 0 ? KSI_MESSAGE_MIDDLE_BUTTON_DOWN : KSI_MESSAGE_MIDDLE_BUTTON_UP;
            return true;
        case BTN_SIDE:
        case BTN_BACK:
        case BTN_EXTRA:
        case BTN_FORWARD:
            *message = value != 0 ? KSI_MESSAGE_X_BUTTON_DOWN : KSI_MESSAGE_X_BUTTON_UP;
            return true;
        default:
            return false;
    }
}

static uint32_t evdev_button_mouse_data(unsigned int code)
{
    if (code == BTN_SIDE || code == BTN_BACK) {
        return KSI_XBUTTON1 << 16;
    }

    if (code == BTN_EXTRA || code == BTN_FORWARD) {
        return KSI_XBUTTON2 << 16;
    }

    return 0u;
}

static void dispatch_keyboard_event(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t extra_info,
    bool is_injected)
{
    if (!should_dispatch_hook_input(device) && observer_event_callback == NULL) {
        return;
    }

    ksi_keyboard_hook_event hook_event = {
        .message = evdev_key_to_message(event),
        .vk_code = evdev_key_to_vk((unsigned int)event->code),
        .scan_code = (uint32_t)event->code,
        .flags = evdev_key_to_flags(event) | keyboard_injected_flags(is_injected) | keyboard_indicator_flags()
            | (device->synchronizing ? KSI_KEYBOARD_HOOK_SYNCHRONIZED : 0u),
        .time_ms = event_time_ms(event),
        .extra_info = extra_info,
        .device_id = device->device_id,
    };

    if (g_verbose) {
        printf("keysharp-input: key %s vk=0x%02x scan=%u value=%d flags=0x%x time=%llu device=\"%s\"\n",
            hook_event.message == KSI_MESSAGE_KEY_UP ? "up" : "down",
            hook_event.vk_code,
            hook_event.scan_code,
            event->value,
            hook_event.flags,
            (unsigned long long)hook_event.time_ms,
            device->name);
    }

    deliver_physical_event(device, KSI_HOOK_KEYBOARD, &hook_event, sizeof(hook_event), event);
}

static void dispatch_mouse_button_event(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t extra_info,
    bool is_injected)
{
    uint32_t message;

    if (!should_dispatch_hook_input(device) && observer_event_callback == NULL) {
        return;
    }

    if (!evdev_button_to_mouse_message((unsigned int)event->code, event->value, &message)) {
        return;
    }

    ksi_mouse_hook_event hook_event = {
        .message = message,
        /* Button events carry no cursor position; report the sentinel, not a bogus (0,0). */
        .x = KSI_MOUSE_COORD_UNSPECIFIED,
        .y = KSI_MOUSE_COORD_UNSPECIFIED,
        .mouse_data = evdev_button_mouse_data((unsigned int)event->code),
        .flags = mouse_injected_flags(is_injected),
        .time_ms = event_time_ms(event),
        .extra_info = extra_info,
        .device_id = device->device_id,
    };

    if (g_verbose) {
        printf("keysharp-input: mouse button message=0x%x data=0x%x time=%llu device=\"%s\"\n",
            hook_event.message,
            hook_event.mouse_data,
            (unsigned long long)hook_event.time_ms,
            device->name);
    }

    deliver_physical_event(device, KSI_HOOK_MOUSE, &hook_event, sizeof(hook_event), event);
}

/* A move completing a report with no other mouse-lane fragment carries the
 * report's SYN, which saves a lane event and a write per report. */
static void dispatch_pending_mouse_move(ksi_linux_tracked_device *device, bool report_end)
{
    ksi_mouse_hook_event hook_event;
    bool end = report_end && (device->forward_report_lanes & KSI_FORWARD_REPORT_MOUSE) == 0u;

    if (device->has_pending_rel) {
        memset(&hook_event, 0, sizeof(hook_event));
        hook_event.message = KSI_MESSAGE_MOUSE_MOVE;
        hook_event.x = device->pending_rel_x;
        hook_event.y = device->pending_rel_y;
        hook_event.delta_x = hook_event.x;
        hook_event.delta_y = hook_event.y;
        hook_event.flags = mouse_injected_flags(device->pending_rel_injected);
        hook_event.time_ms = device->pending_rel_time_ms;
        hook_event.extra_info = device->pending_rel_extra_info;
        hook_event.device_id = device->device_id;

        if (g_verbose && should_dispatch_hook_input(device)) {
            printf("keysharp-input: mouse move dx=%d dy=%d time=%llu device=\"%s\"\n",
                hook_event.x,
                hook_event.y,
                (unsigned long long)hook_event.time_ms,
                device->name);
        }

        device->has_pending_rel = false;
        device->pending_rel_x = 0;
        device->pending_rel_y = 0;
        device->pending_rel_time_ms = 0;
        device->pending_rel_extra_info = 0;
        device->pending_rel_injected = false;

        /* The input core drops zero relative values, so none are forwarded. */
        ksi_forward_packet replay = lane_packet(device, KSI_HOOK_MOUSE);
        if (end && !device->has_pending_abs) replay.flags |= KSI_FORWARD_REPORT_END;
        if (hook_event.x != 0) append_forward_event(&replay, EV_REL, REL_X, hook_event.x);
        if (hook_event.y != 0) append_forward_event(&replay, EV_REL, REL_Y, hook_event.y);
        deliver_device_event(device, KSI_HOOK_MOUSE, &hook_event, sizeof(hook_event), &replay);
    }

    if (device->has_pending_abs) {
        memset(&hook_event, 0, sizeof(hook_event));
        hook_event.message = KSI_MESSAGE_MOUSE_MOVE;
        hook_event.x = device->current_abs_x;
        hook_event.y = device->current_abs_y;
        hook_event.delta_x = hook_event.x - device->pending_abs_start_x;
        hook_event.delta_y = hook_event.y - device->pending_abs_start_y;
        hook_event.mouse_data = KSI_MOUSE_ABSOLUTE;
        hook_event.flags = mouse_injected_flags(device->pending_abs_injected);
        hook_event.time_ms = device->pending_abs_time_ms;
        hook_event.extra_info = device->pending_abs_extra_info;
        hook_event.device_id = device->device_id;

        if (g_verbose && should_dispatch_hook_input(device)) {
            printf("keysharp-input: mouse move abs x=%d y=%d dx=%d dy=%d time=%llu device=\"%s\"\n",
                hook_event.x, hook_event.y, hook_event.delta_x, hook_event.delta_y,
                (unsigned long long)hook_event.time_ms,
                device->name);
        }

        device->has_pending_abs = false;
        device->pending_abs_time_ms = 0;
        device->pending_abs_extra_info = 0;
        device->pending_abs_injected = false;

        /* Both axes, so a clone that missed moves while ungrabbed or blocked
         * cannot pair a new X with a stale Y. The kernel drops unchanged values. */
        ksi_forward_packet replay = lane_packet(device, KSI_HOOK_MOUSE);
        if (end) replay.flags |= KSI_FORWARD_REPORT_END;
        append_forward_event(&replay, EV_ABS, ABS_X, device->current_abs_x_raw);
        append_forward_event(&replay, EV_ABS, ABS_Y, device->current_abs_y_raw);
        deliver_device_event(device, KSI_HOOK_MOUSE, &hook_event, sizeof(hook_event), &replay);
    }
}

static void queue_relative_motion(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t extra_info,
    bool is_injected)
{
    if (device->has_pending_rel && device->pending_rel_injected != is_injected) {
        dispatch_pending_mouse_move(device, false);
    }

    if (event->code == REL_X) {
        device->pending_rel_x += event->value;
    } else {
        device->pending_rel_y += event->value;
    }

    device->pending_rel_time_ms = event_time_ms(event);
    device->pending_rel_extra_info = extra_info;
    device->pending_rel_injected = is_injected;
    device->has_pending_rel = true;

    /* A relative movement makes any cached absolute position stale: the cursor has moved but we
     * have no absolute coordinate for its new location. Invalidate so GET_POINTER_POSITION reports
     * "unknown" (valid = 0) rather than a stale absolute value -- callers must only trust the
     * absolute position when the most recent movement was itself absolute. */
    current_pointer_position.valid = 0u;
}

/* Forwarding rebuilds legacy wheel steps from the high-resolution value, so
 * the source's own legacy step would scroll twice. */
static bool is_shadowed_legacy_wheel(
    const ksi_linux_tracked_device *device, const struct input_event *event)
{
    return event->type == EV_REL
        && ((event->code == REL_WHEEL && device->high_resolution_wheel)
            || (event->code == REL_HWHEEL && device->high_resolution_horizontal_wheel));
}

static bool is_hooked_relative_code(uint16_t code)
{
    return code == REL_X || code == REL_Y || code == REL_WHEEL || code == REL_HWHEEL
        || code == REL_WHEEL_HI_RES || code == REL_HWHEEL_HI_RES;
}

static void dispatch_relative_event(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t extra_info,
    bool is_injected)
{
    if (event->code == REL_X || event->code == REL_Y) {
        queue_relative_motion(device, event, extra_info, is_injected);
        return;
    }

    if (!is_shadowed_legacy_wheel(device, event)) {
        bool vertical = event->code == REL_WHEEL || event->code == REL_WHEEL_HI_RES;
        int64_t delta = event->value;
        if (event->code == REL_WHEEL || event->code == REL_HWHEEL) {
            delta *= 120;
        }
        if (delta > INT16_MAX) delta = INT16_MAX;
        if (delta < INT16_MIN) delta = INT16_MIN;
        ksi_mouse_hook_event hook_event = {
            .message = vertical ? KSI_MESSAGE_MOUSE_WHEEL : KSI_MESSAGE_MOUSE_HORIZONTAL_WHEEL,
            /* Wheel events carry no cursor position; report the sentinel, not a bogus (0,0). */
            .x = KSI_MOUSE_COORD_UNSPECIFIED,
            .y = KSI_MOUSE_COORD_UNSPECIFIED,
            .mouse_data = (uint32_t)delta << 16,
            .flags = mouse_injected_flags(is_injected),
            .time_ms = event_time_ms(event),
            .extra_info = extra_info,
            .device_id = device->device_id,
        };

        dispatch_pending_mouse_move(device, false);

        if (g_verbose && should_dispatch_hook_input(device)) {
            printf("keysharp-input: mouse wheel message=0x%x delta=%d time=%llu device=\"%s\"\n",
                hook_event.message,
                event->value * 120,
                (unsigned long long)hook_event.time_ms,
                device->name);
        }

        deliver_physical_event(device, KSI_HOOK_MOUSE, &hook_event, sizeof(hook_event), event);
    }
}

static void queue_absolute_motion(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t extra_info,
    bool is_injected)
{
    int32_t previous_abs_x = device->current_abs_x;
    int32_t previous_abs_y = device->current_abs_y;

    if (device->has_pending_abs && device->pending_abs_injected != is_injected) {
        dispatch_pending_mouse_move(device, false);
    }

    if (event->code == ABS_X) {
        device->current_abs_x_raw = event->value;
        device->current_abs_x = scale_abs_axis(event->value, device->abs_x_min, device->abs_x_max);
    } else {
        device->current_abs_y_raw = event->value;
        device->current_abs_y = scale_abs_axis(event->value, device->abs_y_min, device->abs_y_max);
    }

    /* Hook coordinates are normalized; forwarding retains the physical units. */
    if (!device->has_pending_abs) {
        device->pending_abs_start_x = previous_abs_x;
        device->pending_abs_start_y = previous_abs_y;
    }
    device->pending_abs_time_ms = event_time_ms(event);
    device->pending_abs_extra_info = extra_info;
    device->pending_abs_injected = is_injected;
    device->has_pending_abs = true;

    current_pointer_position.valid = 1u;
    current_pointer_position.x = device->current_abs_x_raw;
    current_pointer_position.y = device->current_abs_y_raw;
    current_pointer_position.x_min = device->abs_x_min;
    current_pointer_position.x_max = device->abs_x_max;
    current_pointer_position.y_min = device->abs_y_min;
    current_pointer_position.y_max = device->abs_y_max;
}

/* The sink carries a keyboard's keyboard keys and their scan codes, on the
 * keyboard lane; the rest of any source goes to its clone, on the mouse lane. */
static uint32_t raw_forward_hook_type(
    const ksi_linux_tracked_device *device, const struct input_event *event)
{
    bool sink = device->keyboard_candidate
        && ((event->type == EV_KEY && is_keyboard_key_code(event->code))
            || (event->type == EV_MSC && event->code == MSC_SCAN));

    return sink ? KSI_HOOK_KEYBOARD : KSI_HOOK_MOUSE;
}

/* BlockInput follows the input's class, not the device replaying it: only a
 * pointer's own events are mouse input. */
static uint32_t raw_block_bit(
    const ksi_linux_tracked_device *device, const struct input_event *event)
{
    bool pointer_event = event->type == EV_REL || event->type == EV_ABS
        || (event->type == EV_KEY && event->code >= BTN_MISC && event->code < KEY_OK);

    return !device->keyboard_candidate || (device->mouse_block_candidate && pointer_event)
        ? KSI_BLOCK_MOUSE : KSI_BLOCK_KEYBOARD;
}

static void forward_raw_packet(
    ksi_linux_tracked_device *device, uint32_t hook_type,
    const struct input_event *event)
{
    const ksi_forward_packet replay = forward_fragment(device, hook_type, event);
    forward_event_callback(forward_event_context, hook_type, &replay);
    mark_forward_report_lane(device, hook_type, &replay);
}

static void forward_unhandled_event(
    ksi_linux_tracked_device *device, const struct input_event *event)
{
    if (!device->grabbed) {
        /* logind reads switches from clones too. */
        if (event->type == EV_SW && device->forwarding_target != 0u)
            ksi_linux_forward_sync_switches(device->forwarding_target);
        return;
    }
    if (device->forwarding_target == 0u
        || forward_event_callback == NULL || event->type == EV_REP
        || event->type == EV_FF || is_shadowed_legacy_wheel(device, event)) return;

    if (event->type == EV_SYN) {
        uint32_t pending = device->forward_report_lanes;
        if ((pending & KSI_FORWARD_REPORT_KEYBOARD) != 0u)
            forward_raw_packet(device, KSI_HOOK_KEYBOARD, event);
        if ((pending & KSI_FORWARD_REPORT_MOUSE) != 0u)
            forward_raw_packet(device, KSI_HOOK_MOUSE, event);
        if (event->code == SYN_REPORT) device->forward_report_lanes = 0u;
        return;
    }

    /* Blocking suppresses input, but never a release or a switch's state. */
    if ((block_input_mask & raw_block_bit(device, event)) != 0u && event->type != EV_SW
        && !(event->type == EV_KEY && event->value == 0)) return;
    forward_raw_packet(device, raw_forward_hook_type(device, event), event);
}

/* The source's outputs kept the keys held at ungrab; each ends there when the
 * source releases it. A refused release stays pending for settle_ungrab_holds. */
static void forward_release_after_ungrab(
    ksi_linux_tracked_device *device, const struct input_event *event)
{
    uint32_t hook_type = raw_forward_hook_type(device, event);
    ksi_forward_packet release = lane_packet(device, hook_type);

    if (event->value != 0 || event->code > KEY_MAX
        || !ksi_key_bit(device->ungrab_held_keys, event->code)) return;
    release.flags |= KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED;
    append_forward_event(&release, EV_KEY, event->code, 0);
    if (forward_event_callback == NULL || forward_event_callback(forward_event_context, hook_type, &release))
        ksi_set_key_bit(device->ungrab_held_keys, event->code, false);
}

/* Backspace+Esc+Enter held together, on any keyboards, releases every grab.
 * Only a press can complete it. */
static const uint16_t panic_chord[] = { KEY_BACKSPACE, KEY_ESC, KEY_ENTER };

static bool is_panic_key(uint16_t code)
{
    return code == KEY_BACKSPACE || code == KEY_ESC || code == KEY_ENTER;
}

/* Only a grab can hold input from the desktop, so without one nothing
 * reads every keyboard's state for the chord. */
static bool any_grabbed(void)
{
    for (size_t i = 0; i < tracked_device_count; i++)
        if (tracked_devices[i].grabbed) return true;
    return false;
}

static bool panic_chord_down(void)
{
    uint32_t down = 0u;

    for (size_t i = 0; i < tracked_device_count; i++) {
        uint8_t keys[KSI_KEY_BITMAP_BYTES];
        if (tracked_devices[i].injected_source || tracked_devices[i].fd < 0
            || !ksi_read_key_bytes(tracked_devices[i].fd, keys)) continue;
        for (size_t c = 0u; c < sizeof(panic_chord) / sizeof(panic_chord[0]); c++)
            if (ksi_key_bit(keys, panic_chord[c])) down |= 1u << c;
    }
    return down == (1u << (sizeof(panic_chord) / sizeof(panic_chord[0]))) - 1u;
}

/* A compositor keeping lock state per keyboard lights only the sink, which
 * now receives the keys, so grabbed keyboards copy its LEDs. */
static void relay_sink_led(const struct input_event *event)
{
    for (size_t i = 0u; i < tracked_device_count; i++)
        if (tracked_devices[i].grabbed && tracked_devices[i].keyboard_candidate)
            (void)ksi_linux_output_write(tracked_devices[i].fd, event, 1u);
}

static void handle_input_event(
    ksi_linux_tracked_device *device,
    const struct input_event *event,
    uint64_t *fallback_activity_time_ms)
{
    uint64_t extra_info = 0;
    bool is_injected = false;
    const struct input_event *next;

    /* Desktop LED feedback also arrives on our virtual keyboards. */
    if (event->type == EV_LED) {
        if (device->forwarding_sink) relay_sink_led(event);
        ksi_linux_devices_refresh_indicator_state();
        return;
    }

    /* The replay/synthesis device is a downstream copy, not new
     * physical activity. Reject it at first ingress so it cannot reset idle
     * time or re-enter hook dispatch. */
    if (device->injected_source) {
        return;
    }

    if (raw_observer_callback != NULL && device->raw_observation_candidate
        && (event->type == EV_ABS || event->type == EV_KEY || event->type == EV_SYN)) {
        const ksi_raw_input_event raw = {
            .struct_size = sizeof(raw), .device_id = device->device_id,
            .time_ms = event_time_ms(event), .type = event->type, .code = event->code,
            .value = event->value,
            .flags = (device->synchronizing ? KSI_RAW_INPUT_SYNCHRONIZED : 0u)
                | (device->event_clock_monotonic ? KSI_RAW_INPUT_MONOTONIC_TIME : 0u),
        };
        raw_observer_callback(raw_observer_context, &raw);
    }

    /* Count activity at raw evdev ingress, before hook callbacks or deferred
     * processing can create re-entrant events. Synchronization packets, LED
     * output, and zero relative deltas can occur without user-visible input and
     * do not reset the clock. */
    if (event->type == EV_KEY
        || (event->type == EV_REL && event->value != 0)
        || event->type == EV_ABS) {
        uint64_t activity_time_ms;

        /* EVIOCSCLOCKID makes this kernel timestamp CLOCK_MONOTONIC, so the hot
         * path is only integer arithmetic. Fall back to clock_gettime only on
         * old kernels which rejected that ioctl. Using the event time rather
         * than processing time also preserves accuracy through a queue backlog. */
        if (device->event_clock_monotonic) {
            activity_time_ms = event_time_ms(event);
        } else {
            /* Query once, on the first real activity event in this readable
             * batch. This remains before hook dispatch while avoiding a clock
             * syscall for every event on kernels without EVIOCSCLOCKID. */
            if (*fallback_activity_time_ms == 0u) {
                *fallback_activity_time_ms = ksi_linux_monotonic_ms();
            }

            activity_time_ms = *fallback_activity_time_ms;
        }

        if (activity_time_ms > last_input_activity_ms) {
            last_input_activity_ms = activity_time_ms;
        }
    }

    if (event->type == EV_KEY && !device->grabbed) forward_release_after_ungrab(device, event);

    if (!device->keyboard_candidate && !device->mouse_candidate) {
        forward_unhandled_event(device, event);
    } else if (event->type == EV_SYN) {
        if (event->code == SYN_REPORT) {
            dispatch_pending_mouse_move(device, true);
            /* A blocked key leaves its scan code behind. */
            device->has_pending_scan = false;
        }
        forward_unhandled_event(device, event);
    } else if (event->type == EV_KEY) {
        dispatch_pending_mouse_move(device, false);

        if (device->keyboard_candidate && event->value == 1 && is_panic_key(event->code)
            && panic_callback != NULL && any_grabbed() && panic_chord_down()) {
            panic_callback(panic_context);
        }

        if (device->mouse_candidate && is_mouse_button_code(event->code)) {
            dispatch_mouse_button_event(device, event, extra_info, is_injected);
            /* Compositor-processed pointer devices cannot participate in the
             * mouse hook, but a keyboard grab can still cover a combined
             * event node. Preserve its buttons through the forwarding lane. */
            if (!device->mouse_hook_candidate) forward_unhandled_event(device, event);
        } else if (device->keyboard_candidate && is_keyboard_key_code(event->code)) {
            dispatch_keyboard_event(device, event, extra_info, is_injected);
        } else {
            forward_unhandled_event(device, event);
        }
    } else if (device->mouse_hook_candidate && event->type == EV_REL
        && is_hooked_relative_code(event->code)) {
        dispatch_relative_event(device, event, extra_info, is_injected);
    } else if (device->mouse_hook_candidate && event->type == EV_ABS
        && (event->code == ABS_X || event->code == ABS_Y)) {
        queue_absolute_motion(device, event, extra_info, is_injected);
    } else if (event->type == EV_MSC && event->code == MSC_SCAN && device->grabbed
        && (next = peek_report_event(device)) != NULL && next->type == EV_KEY) {
        device->has_pending_scan = true;
        device->pending_scan = event->value;
    } else {
        dispatch_pending_mouse_move(device, false);
        forward_unhandled_event(device, event);
    }

    /* After dispatch: a deferred source is still ungrabbed, so observers see
     * its keys, and none of the report that ends the deferral is forwarded by
     * the grab it starts. */
    process_deferred_grab_event(device, event);
}

void ksi_linux_devices_get_indicator_state(bool *caps_lock, bool *num_lock, bool *scroll_lock)
{
    if (caps_lock)   *caps_lock   = current_caps_lock;
    if (num_lock)    *num_lock    = current_num_lock;
    if (scroll_lock) *scroll_lock = current_scroll_lock;
}

bool ksi_linux_devices_get_pointer_position(ksi_pointer_position_payload *position)
{
    if (position == NULL) {
        return false;
    }

    *position = current_pointer_position;
    return position->valid != 0u;
}

bool ksi_linux_devices_get_idle_time(ksi_idle_time_payload *result)
{
    uint64_t now;

    if (result == NULL) {
        return false;
    }

    memset(result, 0, sizeof(*result));

    if (last_input_activity_ms == 0u) {
        return false;
    }

    now = ksi_linux_monotonic_ms();
    result->valid = 1u;
    result->idle_time_ms = now >= last_input_activity_ms
        ? now - last_input_activity_ms
        : 0u;
    return true;
}

static bool collect_key_state(uint32_t device_id, ksi_key_state_payload *result);

bool ksi_linux_devices_get_pointer_buttons(ksi_pointer_buttons_payload *result)
{
    if (result == NULL) return false;
    ksi_key_state_payload keys;
    bool any = false;

    (void)collect_key_state(0u, &keys);
    for (size_t i = 0u; i < tracked_device_count; i++)
        any |= tracked_devices[i].mouse_candidate && !tracked_devices[i].injected_source
            && tracked_devices[i].fd >= 0;
    memset(result, 0, sizeof(*result));
    for (unsigned int code = BTN_LEFT; code <= BTN_BACK; code++) {
        uint32_t mask = ksi_linux_pointer_button_mask(code);
        if (ksi_key_bit(keys.physical_keys, (uint16_t)code)) result->physical_buttons |= mask;
        if (ksi_key_bit(keys.logical_keys, (uint16_t)code)) result->logical_buttons |= mask;
    }
    result->valid = any ? 1u : 0u;
    return any;
}

/* Keyboards without lock LEDs report none, so an OR across sources gives the
 * desktop's lock state. */
void ksi_linux_devices_refresh_indicator_state(void)
{
    unsigned char seat = 0u;

    for (size_t i = 0; i < tracked_device_count; i++) {
        unsigned char leds = 0u;
        if (tracked_devices[i].fd >= 0 && tracked_devices[i].keyboard_candidate
            && !tracked_devices[i].injected_source
            && ioctl(tracked_devices[i].fd, EVIOCGLED(sizeof(leds)), &leds) >= 0)
            seat |= leds;
    }
    current_caps_lock = (seat & (1u << LED_CAPSL)) != 0u;
    current_num_lock = (seat & (1u << LED_NUML)) != 0u;
    current_scroll_lock = (seat & (1u << LED_SCROLLL)) != 0u;
}

static uint32_t modifiers_from_key_bitmap(const uint8_t *keys)
{
    uint32_t mods = 0;

    if (ksi_key_bit(keys, KEY_LEFTCTRL))   mods |= 0x01u; /* MOD_LCONTROL */
    if (ksi_key_bit(keys, KEY_RIGHTCTRL))  mods |= 0x02u; /* MOD_RCONTROL */
    if (ksi_key_bit(keys, KEY_LEFTALT))    mods |= 0x04u; /* MOD_LALT     */
    if (ksi_key_bit(keys, KEY_RIGHTALT))   mods |= 0x08u; /* MOD_RALT     */
    if (ksi_key_bit(keys, KEY_LEFTSHIFT))  mods |= 0x10u; /* MOD_LSHIFT   */
    if (ksi_key_bit(keys, KEY_RIGHTSHIFT)) mods |= 0x20u; /* MOD_RSHIFT   */
    if (ksi_key_bit(keys, KEY_LEFTMETA))   mods |= 0x40u; /* MOD_LWIN     */
    if (ksi_key_bit(keys, KEY_RIGHTMETA))  mods |= 0x80u; /* MOD_RWIN     */

    return mods;
}


_Static_assert(KSI_KEY_STATE_BITMAP_BYTES == KSI_KEY_BITMAP_BYTES, "key-state payloads are key bitmaps");

/* Physical state is the kernel's, which it keeps under another grab too.
 * Logical state is what the desktop sees: ungrabbed sources' keys, what grabbed
 * ones hold downstream, and synthesis. */
static bool collect_key_state(uint32_t device_id, ksi_key_state_payload *result)
{
    uint8_t seat_logical[KSI_KEY_BITMAP_BYTES] = {0};
    bool found = false;

    memset(result, 0, sizeof(*result));
    for (size_t i = 0; i < tracked_device_count; i++) {
        const ksi_linux_tracked_device *device = &tracked_devices[i];
        uint8_t keys[KSI_KEY_BITMAP_BYTES];
        uint8_t logical[KSI_KEY_BITMAP_BYTES] = {0};
        bool selected = device_id == 0u || device_id == device->device_id;

        if (device->injected_source || device->fd < 0 || !ksi_read_key_bytes(device->fd, keys))
            continue;
        found |= selected;
        /* The desktop saw keys held at ungrab on the outputs, not the source. */
        for (size_t b = 0u; !device->grabbed && !device->foreign_grab && b < sizeof(keys); b++)
            logical[b] = keys[b] & (uint8_t)~device->ungrab_held_keys[b];
        if (device->forwarding_target != 0u)
            ksi_linux_forward_add_key_state(device->forwarding_target, logical, sizeof(logical));
        for (size_t b = 0u; b < sizeof(keys); b++) {
            seat_logical[b] |= logical[b];
            if (selected) {
                result->physical_keys[b] |= keys[b];
                result->logical_keys[b] |= logical[b];
            }
        }
    }
    ksi_linux_synth_add_logical_key_state(seat_logical, sizeof(seat_logical));
    if (device_id == 0u) memcpy(result->logical_keys, seat_logical, sizeof(seat_logical));
    result->modifiers_lr = modifiers_from_key_bitmap(seat_logical);
    return found;
}

bool ksi_linux_devices_get_device_key_state(uint32_t device_id, ksi_key_state_payload *result)
{
    bool found;

    if (result == NULL) return false;
    found = collect_key_state(device_id, result);
    ksi_linux_devices_refresh_indicator_state();
    result->caps_lock = current_caps_lock;
    result->num_lock = current_num_lock;
    result->scroll_lock = current_scroll_lock;
    return found;
}

bool ksi_linux_devices_get_modifier_state(ksi_modifier_state_payload *result)
{
    ksi_key_state_payload keys;
    bool available;

    if (result == NULL) {
        return false;
    }

    memset(result, 0, sizeof(*result));
    available = ksi_linux_devices_get_device_key_state(0u, &keys);
    result->logical_modifiers_lr = keys.modifiers_lr;
    result->physical_modifiers_lr =
        modifiers_from_key_bitmap(keys.physical_keys);
    result->caps_lock = keys.caps_lock;
    result->num_lock = keys.num_lock;
    result->scroll_lock = keys.scroll_lock;
    return available;
}

void ksi_linux_devices_set_hook_event_callback(ksi_physical_hook_callback callback, void *context)
{
    hook_event_callback = callback;
    hook_event_context = context;
}

void ksi_linux_devices_set_forward_event_callback(ksi_physical_forward_callback callback,
    ksi_forward_end_grab_callback end_grab, ksi_forward_close_callback close_source, void *context)
{
    forward_event_callback = callback;
    end_grab_callback = end_grab;
    close_callback = close_source;
    forward_event_context = context;
}

void ksi_linux_devices_set_observer_callback(ksi_hook_event_callback callback,
    ksi_device_change_callback device_callback, void *context)
{
    observer_event_callback = callback;
    device_change_callback = device_callback;
    observer_event_context = context;
}

void ksi_linux_devices_set_raw_observer_callback(ksi_raw_device_callback callback, void *context)
{
    raw_observer_callback = callback;
    raw_observer_context = context;
}

uint64_t ksi_linux_devices_generation(void)
{
    return device_generation;
}

static const ksi_linux_tracked_device *find_listed_device(size_t index)
{
    const ksi_linux_tracked_device *device = &tracked_devices[index];
    return device->fd >= 0 && !device->injected_source ? device : NULL;
}

size_t ksi_linux_devices_list(uint32_t offset, ksi_device_info *entries,
    size_t capacity, uint32_t *next_offset)
{
    size_t count = 0u;
    size_t index = offset;
    for (; index < tracked_device_count && count < capacity; index++) {
        const ksi_linux_tracked_device *device = find_listed_device(index);
        if (device != NULL)
            entries[count++] = device->public_info;
    }
    *next_offset = index < tracked_device_count ? (uint32_t)index : 0u;
    return count;
}

static long event_node_index(const char *path)
{
    const char *name = strrchr(path, '/');
    name = name != NULL ? name + 1 : path;
    if (!is_event_device_name(name)) return LONG_MAX;
    char *end;
    long index = strtol(name + strlen(KSI_EVENT_PREFIX), &end, 10);
    return *end == '\0' && index >= 0 ? index : LONG_MAX;
}

/* Discovery walks the directory in filesystem order, which is neither sorted
 * nor stable across restarts, so order gamepads by their event node instead: a
 * consumer that addresses "the second gamepad" must keep meaning the same one. */
static size_t collect_gamepads(size_t *ordered)
{
    size_t count = 0u;
    for (size_t index = 0u; index < tracked_device_count; index++) {
        const ksi_linux_tracked_device *device = find_listed_device(index);
        if (device == NULL || (device->public_info.capabilities & KSI_DEVICE_GAMEPAD) == 0u)
            continue;
        long node = event_node_index(device->path);
        size_t position = count++;
        for (; position > 0u && event_node_index(tracked_devices[ordered[position - 1u]].path) > node;
             position--)
            ordered[position] = ordered[position - 1u];
        ordered[position] = index;
    }
    return count;
}

size_t ksi_linux_gamepads_list(uint32_t offset, ksi_device_info *entries,
    size_t capacity, uint32_t *next_offset)
{
    size_t ordered[KSI_MAX_TRACKED_DEVICES];
    size_t total = collect_gamepads(ordered);
    size_t count = 0u;
    size_t index = offset;
    for (; index < total && count < capacity; index++) {
        /* This listing is ungated, so it carries only what a gamepad consumer
         * needs. The node path and the physical and unique identifiers stay
         * behind Input Monitoring in ksi_linux_devices_list. */
        ksi_device_info *entry = &entries[count++];
        *entry = tracked_devices[ordered[index]].public_info;
        memset(entry->path, 0, sizeof(entry->path));
        memset(entry->physical, 0, sizeof(entry->physical));
        memset(entry->unique, 0, sizeof(entry->unique));
    }
    *next_offset = index < total ? (uint32_t)index : 0u;
    return count;
}

bool ksi_linux_gamepad_state(uint32_t device_id, ksi_gamepad_state *state)
{
    uint8_t key_state[KSI_KEY_BITMAP_BYTES];

    for (size_t index = 0u; index < tracked_device_count; index++) {
        const ksi_linux_tracked_device *device = find_listed_device(index);

        if (device == NULL || device->device_id != device_id
            || (device->public_info.capabilities & KSI_DEVICE_GAMEPAD) == 0u) {
            continue;
        }

        memset(state, 0, sizeof(*state));
        state->struct_size = sizeof(*state);
        state->device_id = device_id;
        state->device_generation = device_generation;
        state->button_count = device->public_info.button_count;

        /* The kernel holds the current position of every axis and button, so
         * one pair of ioctls answers a poll without replaying the event
         * stream, and a client that starts mid-press still sees it held. */
        (void)ksi_read_key_bytes(device->fd, key_state);
        for (uint32_t i = 0u; i < state->button_count; i++) {
            if (ksi_key_bit(key_state, device->public_info.button_codes[i])) {
                state->buttons[i >> 3] |= (uint8_t)(1u << (i & 7u));
            }
        }

        for (uint32_t i = 0u; i < device->public_info.axis_count; i++) {
            struct input_absinfo abs;
            uint32_t code = device->public_info.axes[i].code;

            if (ioctl(device->fd, EVIOCGABS(code), &abs) != 0) {
                continue;
            }

            ksi_gamepad_axis_state *axis = &state->axes[state->axis_count++];
            axis->struct_size = sizeof(*axis);
            axis->code = code;
            axis->value = abs.value;
        }

        return true;
    }

    return false;
}

void ksi_linux_devices_set_panic_callback(ksi_panic_callback callback, void *context)
{
    panic_callback = callback;
    panic_context = context;
}

static int next_device_event(ksi_linux_tracked_device *device, struct input_event *event)
{
    for (;;) {
        int result = libevdev_next_event(device->evdev,
            device->synchronizing ? LIBEVDEV_READ_FLAG_SYNC : LIBEVDEV_READ_FLAG_NORMAL,
            event);

        if (result == LIBEVDEV_READ_STATUS_SYNC) {
            if (device->synchronizing) {
                return 0;
            }
            /* Incomplete motion reports cannot be replayed after the state jump.
             * Fragments already forwarded still need the sync burst's SYN. */
            uint32_t forwarded = device->forward_report_lanes;
            device->synchronizing = true;
            discard_pending_report(device);
            device->forward_report_lanes = forwarded;
            continue;
        }
        if (result == -EAGAIN && device->synchronizing) {
            device->synchronizing = false;
            continue;
        }
        return result;
    }
}

static void read_device_events(ksi_linux_tracked_device *device)
{
    uint64_t fallback_activity_time_ms = 0u;

    for (size_t processed = 0; processed < KSI_MAX_DEVICE_EVENTS_PER_PASS; processed++) {
        struct input_event event;
        int result;

        if (device->evdev == NULL) {
            return;
        }

        if (device->has_buffered_event) {
            event = device->buffered_event;
            device->has_buffered_event = false;
            memset(&device->buffered_event, 0, sizeof(device->buffered_event));
            result = 0;
        } else {
            result = next_device_event(device, &event);
        }

        if (result == 0) {
            handle_input_event(device, &event, &fallback_activity_time_ms);
            if (device->read_error == 0) continue;
            close_tracked_device(device);
            return;
        }

        if (result == -EAGAIN) {
            dispatch_pending_mouse_move(device, false);
            return;
        }

        fprintf(stderr, "keysharp-input: failed reading %s: %s\n",
            device->path,
            strerror(-result));
        close_tracked_device(device);
        return;
    }

    /* Leave remaining events readable for another poll iteration. This keeps a
     * continuously busy device from starving other devices and cleanup work. */
    dispatch_pending_mouse_move(device, false);
}

static void process_device_events(ksi_linux_tracked_device *device)
{
    bool nested = reading_device_events;

    reading_device_events = true;
    read_device_events(device);
    reading_device_events = nested;
}

static bool buffer_next_device_event(ksi_linux_tracked_device *device)
{
    if (device == NULL || device->evdev == NULL) {
        return false;
    }

    if (device->has_buffered_event) {
        return true;
    }

    for (;;) {
        struct input_event event;
        int result = next_device_event(device, &event);

        if (result == 0) {
            device->buffered_event = event;
            device->has_buffered_event = true;
            return true;
        }

        if (result == -EAGAIN) {
            return false;
        }

        fprintf(stderr, "keysharp-input: failed peeking %s: %s\n",
            device->path,
            strerror(-result));
        /* Closing mid-dispatch would announce the removal before the event. */
        if (reading_device_events) device->read_error = result;
        else close_tracked_device(device);
        return false;
    }
}

bool ksi_linux_devices_peek_oldest_pending_event(int *out_fd, uint64_t *out_time_ns)
{
    bool found = false;
    uint64_t oldest_time = 0;
    int oldest_fd = -1;

    for (size_t i = 0; i < tracked_device_count; i++) {
        ksi_linux_tracked_device *device = &tracked_devices[i];
        uint64_t time_ms;

        if (!device->grabbed || device->injected_source || device->fd < 0) {
            continue;
        }

        if (!buffer_next_device_event(device)) {
            continue;
        }

        time_ms = event_time_ns(&device->buffered_event);

        if (!found || time_ms < oldest_time) {
            found = true;
            oldest_time = time_ms;
            oldest_fd = device->fd;
        }
    }

    if (!found) {
        return false;
    }

    if (out_fd != NULL) {
        *out_fd = oldest_fd;
    }

    if (out_time_ns != NULL) {
        *out_time_ns = oldest_time;
    }

    return true;
}

static void process_udev_events(void)
{
    for (size_t processed = 0; processed < KSI_MAX_UDEV_EVENTS_PER_PASS; processed++) {
        struct udev_device *device;
        const char *action;
        const char *devnode;

        if (udev_monitor == NULL) {
            return;
        }

        device = udev_monitor_receive_device(udev_monitor);

        if (device == NULL) {
            return;
        }

        action = udev_device_get_action(device);
        devnode = udev_device_get_devnode(device);

        if (devnode != NULL && is_event_device_path(devnode)) {
            if (action != NULL && strcmp(action, "remove") == 0) {
                untrack_device(devnode);
            } else if (action != NULL && (strcmp(action, "add") == 0 || strcmp(action, "change") == 0)) {
                handle_device_add_or_change(device, devnode, action);
            }
        }

        udev_device_unref(device);
    }
}

void ksi_linux_devices_process_fd(int fd)
{
    ssize_t device_index;

    if (udev_monitor != NULL && fd == udev_monitor_get_fd(udev_monitor)) {
        process_udev_events();
        return;
    }

    device_index = find_tracked_device_by_fd(fd);

    if (device_index >= 0) {
        process_device_events(&tracked_devices[device_index]);
    }
}

/* An idle-time request can share one poll wakeup with device input. Client RPC
 * is normally serviced first to keep hook decisions responsive, so explicitly
 * drain every currently-readable upstream device queue before calculating
 * idle duration.
 * The returned idle time therefore comes from the newest ingested kernel event
 * timestamp; it is never replaced with a fabricated zero merely because data
 * was queued. process_device_events retains its normal 256-event inner budget,
 * and this outer loop repeats until every device reaches EAGAIN. */
void ksi_linux_devices_drain_pending_input(void)
{
    for (;;) {
        bool found_pending = false;

        for (size_t i = 0u; i < tracked_device_count; i++) {
            ksi_linux_tracked_device *device = &tracked_devices[i];

            if (device->injected_source || device->fd < 0 || device->evdev == NULL
                || (!device->has_buffered_event
                    && libevdev_has_event_pending(device->evdev) != 1)) {
                continue;
            }

            found_pending = true;
            ksi_linux_devices_process_fd(device->fd);
        }

        if (!found_pending) {
            break;
        }
    }
}
