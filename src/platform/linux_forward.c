#include "internal/linux_forward.h"
#include "linux_device_filter.h"
#include "linux_key_bits.h"
#include "linux_output.h"
#include "linux_wheel.h"

#include <errno.h>
#include <fcntl.h>
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <linux/uinput.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Downstream readers get this long to consume releases before removal can
 * discard them. */
#define KSI_FORWARD_DRAIN_MS 100u
#define KSI_SWITCH_BITMAP_BYTES ((SW_MAX + 8u) / 8u)

_Static_assert(KSI_MAX_FORWARDING_DEVICES < 256u, "targets encode the slot in their low byte");

typedef struct forward_keys {
    uint8_t output[KSI_KEY_BITMAP_BYTES];
    uint8_t source[KSI_KEY_BITMAP_BYTES];
    uint8_t displaced[KSI_KEY_BITMAP_BYTES];
} forward_keys;

/* One grabbed source. Its keyboard keys go to the sink and everything else it
 * reports to its own clone, which a plain keyboard does not need. */
typedef struct forwarding_device {
    uint64_t target[2];
    bool open;
    /* Closed for admitted output; written output retires it in queue order. */
    bool closing;
    bool keyboard;
    struct libevdev_uinput *output;
    int source_fd;
    bool failed;
    bool retiring;
    uint64_t retire_ms;
    /* A written fragment still waits for its report's SYN on that output. */
    bool sink_report_open;
    bool clone_report_open;
    bool wheel;
    bool horizontal_wheel;
    int32_t wheel_remainder;
    int32_t horizontal_remainder;
    uint8_t switches[KSI_SWITCH_BITMAP_BYTES];
    forward_keys views[2];
} forwarding_device;

/* The reader owns source lifetimes and the sequencer writes passed input; this
 * lock fences every sink and clone write against retirement and target
 * changes. */
static pthread_mutex_t devices_mutex = PTHREAD_MUTEX_INITIALIZER;
static forwarding_device devices[KSI_MAX_FORWARDING_DEVICES];
/* Slots at and above this bound have never held a source. */
static size_t slot_limit;
static uint64_t next_serial = 1u;
static atomic_uint target_epoch;
static atomic_uint retiring_count;
static atomic_bool failure_pending;
static atomic_uint sink_generation;
/* The main thread asks often; this spares it the lock the sequencer holds
 * across writes. */
static atomic_bool sink_ready_flag;

/* The generic keyboard device. A compositor applies each device's queue whole,
 * so keys stay in written order only on one device: every keyboard source and
 * synthesis share this one, which holds a key while any of them does. */
static struct {
    int fd;
    bool failed;
    uint8_t down[KSI_KEY_BITMAP_BYTES];
    uint8_t synth[KSI_KEY_BITMAP_BYTES];
} sink = { .fd = -1 };

static uint64_t new_target_locked(const forwarding_device *device)
{
    return (next_serial++ << 8) | (uint64_t)(device - devices + 1);
}

static forwarding_device *find_device_locked(uint64_t target, ksi_forward_view view)
{
    size_t slot = (size_t)(target & 0xffu);
    forwarding_device *device;

    if (slot == 0u || slot > KSI_MAX_FORWARDING_DEVICES) return NULL;
    device = &devices[slot - 1u];
    return device->target[view] == target && !device->retiring ? device : NULL;
}

static bool live(const forwarding_device *device)
{
    return device->open && !device->retiring;
}

static bool on_sink(const forwarding_device *device, uint16_t code)
{
    return device->keyboard && ksi_linux_key_code_is_keyboard(code);
}

static forwarding_device *find_path_locked(const char *path)
{
    for (size_t i = 0u; i < slot_limit; i++) {
        const char *node = live(&devices[i]) && devices[i].output != NULL
            ? libevdev_uinput_get_devnode(devices[i].output) : NULL;
        if (node != NULL && strcmp(node, path) == 0) return &devices[i];
    }
    return NULL;
}

static int write_locked(forwarding_device *device, const struct input_event *events, size_t count)
{
    if (device->failed) return -1;
    if (ksi_linux_output_write(libevdev_uinput_get_fd(device->output), events, count) == 0)
        return 0;
    device->failed = true;
    atomic_store(&failure_pending, true);
    return -1;
}

static int write_key_locked(forwarding_device *device, uint16_t code, int32_t value)
{
    const struct input_event events[] = {
        { .type = EV_KEY, .code = code, .value = value },
        { .type = EV_SYN, .code = SYN_REPORT },
    };
    return write_locked(device, events, 2u);
}

/* A partial write may still have applied a press. */
static void note_written_keys(uint8_t *keys, const struct input_event *events, size_t count, int result)
{
    for (size_t i = 0u; i < count; i++)
        if (events[i].type == EV_KEY && events[i].code <= KEY_MAX && events[i].value != 2
            && (result == 0 || events[i].value != 0))
            ksi_set_key_bit(keys, events[i].code, events[i].value != 0);
}

static int write_sink_locked(const struct input_event *events, size_t count)
{
    int result = -1;

    if (sink.fd >= 0 && !sink.failed) {
        result = ksi_linux_output_write(sink.fd, events, count);
        sink.failed = result != 0;
        if (sink.failed) {
            atomic_store(&sink_ready_flag, false);
            atomic_store(&failure_pending, true);
        }
    }
    note_written_keys(sink.down, events, count, result);
    return result;
}

static bool sink_wants_locked(uint16_t code)
{
    if (ksi_key_bit(sink.synth, code)) return true;
    for (size_t i = 0u; i < slot_limit; i++)
        if (live(&devices[i]) && on_sink(&devices[i], code)
            && ksi_key_bit(devices[i].views[KSI_FORWARD_APPLIED].output, code)) return true;
    return false;
}

/* Returns the number of events written, or -1. */
static int reconcile_locked(uint16_t code)
{
    bool want = sink_wants_locked(code);
    const struct input_event events[] = {
        { .type = EV_KEY, .code = code, .value = want },
        { .type = EV_SYN, .code = SYN_REPORT },
    };

    if (want == ksi_key_bit(sink.down, code)) return 0;
    return write_sink_locked(events, 2u) == 0 ? 2 : -1;
}

/* Sets whether the source holds code downstream; APPLIED writes the change. */
static void set_output_locked(forwarding_device *device, ksi_forward_view view, uint16_t code, bool held)
{
    ksi_set_key_bit(device->views[view].output, code, held);
    if (view != KSI_FORWARD_APPLIED) return;
    if (on_sink(device, code)) (void)reconcile_locked(code);
    else if (device->output != NULL) (void)write_key_locked(device, code, held);
}

/* Keeps only the holds in keep, releasing the others for APPLIED. */
static void release_outputs_locked(forwarding_device *device, ksi_forward_view view, const uint8_t *keep)
{
    forward_keys *keys = &device->views[view];

    for (size_t byte = 0u; byte < KSI_KEY_BITMAP_BYTES; byte++) {
        uint8_t kept = keep != NULL ? keep[byte] : 0u;
        for (unsigned int bits = keys->output[byte] & (uint8_t)~kept; bits != 0u; bits &= bits - 1u)
            set_output_locked(device, view, (uint16_t)(byte * 8u + (unsigned int)__builtin_ctz(bits)), false);
        keys->displaced[byte] &= kept;
    }
}

/* A grab can end between a report's fragments and its SYN, which is then
 * dropped as stale, so the report is ended here rather than left open. */
static void end_open_reports_locked(forwarding_device *device)
{
    static const struct input_event report_end = { .type = EV_SYN, .code = SYN_REPORT };

    if (device->sink_report_open) (void)write_sink_locked(&report_end, 1u);
    if (device->clone_report_open) (void)write_locked(device, &report_end, 1u);
    device->sink_report_open = device->clone_report_open = false;
}

/* The source's releases now reach only its node, so keep the holds it still has
 * at this view's queue position; the reader forwards their releases. Nothing is
 * restored: a later synthetic press holds for synthesis, which the release ends. */
static void end_grab_locked(forwarding_device *device, ksi_forward_view view, const uint8_t *keep)
{
    forward_keys *keys = &device->views[view];

    if (view == KSI_FORWARD_APPLIED) end_open_reports_locked(device);
    release_outputs_locked(device, view, keep != NULL ? keep : keys->source);
    memset(keys->displaced, 0, sizeof(keys->displaced));
    atomic_fetch_add(&target_epoch, 1u);
}

/* libevdev never issues UI_SET_PHYS, and the kernel accepts it only before
 * creation, so the clone's identity needs a caller-owned uinput handle. */
static int create_output(const struct libevdev *source, const char *phys,
    struct libevdev_uinput **output)
{
    int fd = open(KSI_UINPUT_PATH, O_RDWR | O_CLOEXEC);
    int result;

    if (fd < 0) return -errno;
    result = ioctl(fd, UI_SET_PHYS, phys) == 0
        ? libevdev_uinput_create_from_device(source, fd, output) : -errno;
    if (result < 0) close(fd);
    return result;
}

static void destroy_output(struct libevdev_uinput *output)
{
    int fd = libevdev_uinput_get_fd(output);
    libevdev_uinput_destroy(output);
    close(fd);
}

static bool has_codes(const struct libevdev *source, unsigned int type, unsigned int max)
{
    for (unsigned int code = 0u; code <= max; code++)
        if (libevdev_has_event_code(source, type, code)) return true;
    return false;
}

uint64_t ksi_linux_forward_open(int source_fd, bool keyboard)
{
    struct libevdev *source = NULL;
    struct libevdev_uinput *output = NULL;
    forwarding_device created = { .open = true, .keyboard = keyboard, .source_fd = source_fd };
    char phys[512];
    uint64_t target = 0u;
    int result = 0;

    /* Only the reader opens sources, so a slot free now is still free below. */
    pthread_mutex_lock(&devices_mutex);
    size_t slot = 0u;
    while (slot < KSI_MAX_FORWARDING_DEVICES && devices[slot].open) slot++;
    pthread_mutex_unlock(&devices_mutex);
    if (slot == KSI_MAX_FORWARDING_DEVICES || libevdev_new_from_fd(source_fd, &source) < 0) return 0u;

    const char *original = libevdev_get_phys(source);
    (void)snprintf(phys, sizeof(phys), "%s%s", KSI_FORWARD_PHYS_PREFIX,
        original != NULL ? original : "");
    /* Evdev already delivers physical repeats. Force feedback is not relayed,
     * and rfkill-input would treat a clone's initial SW_RFKILL_ALL=0 as an
     * emergency power-off request. The desktop drives lock LEDs on the sink. */
    (void)libevdev_disable_event_type(source, EV_REP);
    (void)libevdev_disable_event_type(source, EV_FF);
    (void)libevdev_disable_event_type(source, EV_LED);
    (void)libevdev_disable_event_code(source, EV_SW, SW_RFKILL_ALL);
    /* udev would take a keyboard clone left with joystick buttons for a
     * joystick, which gets a session ACL. */
    for (unsigned int code = 0u; keyboard && code <= KEY_MAX; code++)
        if (ksi_linux_key_code_is_keyboard(code) || (code >= BTN_JOYSTICK && code < BTN_DIGI)
            || code >= BTN_TRIGGER_HAPPY)
            (void)libevdev_disable_event_code(source, EV_KEY, code);
    created.wheel = libevdev_has_event_code(source, EV_REL, REL_WHEEL) != 0;
    created.horizontal_wheel = libevdev_has_event_code(source, EV_REL, REL_HWHEEL) != 0;
    for (uint16_t code = 0u; code <= SW_MAX; code++)
        ksi_set_key_bit(created.switches, code, libevdev_has_event_code(source, EV_SW, code) != 0);

    if (has_codes(source, EV_KEY, KEY_MAX) || has_codes(source, EV_REL, REL_MAX)
        || has_codes(source, EV_ABS, ABS_MAX) || has_codes(source, EV_SW, SW_MAX)) {
        result = create_output(source, phys, &output);
    }
    libevdev_free(source);
    if (result < 0) {
        fprintf(stderr, "keysharp-input: cannot create forwarding device: %s\n", strerror(-result));
        return 0u;
    }

    created.output = output;
    pthread_mutex_lock(&devices_mutex);
    devices[slot] = created;
    target = devices[slot].target[0] = devices[slot].target[1] = new_target_locked(&devices[slot]);
    if (slot_limit <= slot) slot_limit = slot + 1u;
    pthread_mutex_unlock(&devices_mutex);
    /* uinput cannot preset switch state. */
    ksi_linux_forward_sync_switches(target);
    return target;
}

bool ksi_linux_forward_has_clone(uint64_t target)
{
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, KSI_FORWARD_ENQUEUED);
    bool clone = device != NULL && device->output != NULL;
    pthread_mutex_unlock(&devices_mutex);
    return clone;
}

uint64_t ksi_linux_forward_end_grab(uint64_t target, uint8_t *held)
{
    memset(held, 0, KSI_KEY_BITMAP_BYTES);
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, KSI_FORWARD_ENQUEUED);
    if (device != NULL) {
        memcpy(held, device->views[KSI_FORWARD_ENQUEUED].source, KSI_KEY_BITMAP_BYTES);
        end_grab_locked(device, KSI_FORWARD_ENQUEUED, NULL);
        target = device->target[KSI_FORWARD_ENQUEUED] = new_target_locked(device);
    }
    pthread_mutex_unlock(&devices_mutex);
    return target;
}

/* Targets only grow, so an end that arrives after a later one is stale. */
void ksi_linux_forward_apply_end_grab(uint64_t next, const uint8_t *held)
{
    size_t slot = (size_t)(next & 0xffu);

    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = slot != 0u && slot <= KSI_MAX_FORWARDING_DEVICES
        ? &devices[slot - 1u] : NULL;
    if (device != NULL && live(device) && device->target[KSI_FORWARD_APPLIED] < next) {
        end_grab_locked(device, KSI_FORWARD_APPLIED, held);
        device->target[KSI_FORWARD_APPLIED] = next;
    }
    pthread_mutex_unlock(&devices_mutex);
}

void ksi_linux_forward_close(uint64_t target)
{
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, KSI_FORWARD_ENQUEUED);
    if (device != NULL) {
        memset(&device->views[KSI_FORWARD_ENQUEUED], 0, sizeof(device->views[0]));
        device->target[KSI_FORWARD_ENQUEUED] = 0u;
        device->closing = true;
        atomic_fetch_add(&target_epoch, 1u);
    }
    pthread_mutex_unlock(&devices_mutex);
}

/* A clone retires until readers have drained its releases; a source without
 * one leaves nothing to drain. The slot stays taken until this runs, so a
 * pending end of an earlier grab cannot reach a reused slot. */
void ksi_linux_forward_apply_close(uint64_t target)
{
    size_t slot = (size_t)(target & 0xffu);

    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = slot != 0u && slot <= KSI_MAX_FORWARDING_DEVICES
        ? &devices[slot - 1u] : NULL;
    if (device != NULL && device->closing && live(device)) {
        end_open_reports_locked(device);
        release_outputs_locked(device, KSI_FORWARD_APPLIED, NULL);
        if (device->output == NULL) {
            memset(device, 0, sizeof(*device));
        } else {
            memset(device->views, 0, sizeof(device->views));
            device->retiring = true;
            device->retire_ms = ksi_linux_monotonic_ms();
            atomic_fetch_add(&retiring_count, 1u);
        }
        atomic_fetch_add(&target_epoch, 1u);
    }
    pthread_mutex_unlock(&devices_mutex);
}

bool ksi_linux_forward_failed(uint64_t target, ksi_forward_view view)
{
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, view);
    bool failed = device == NULL || device->failed;
    pthread_mutex_unlock(&devices_mutex);
    return failed;
}

bool ksi_linux_forward_take_failure(void)
{
    return atomic_exchange(&failure_pending, false);
}

uint64_t ksi_linux_forward_target_for_path(const char *path)
{
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_path_locked(path);
    uint64_t target = device != NULL ? device->target[KSI_FORWARD_ENQUEUED] : 0u;
    pthread_mutex_unlock(&devices_mutex);
    return target;
}

void ksi_linux_forward_sync_switches(uint64_t target)
{
    uint8_t state[KSI_SWITCH_BITMAP_BYTES] = {0};
    struct input_event events[SW_CNT + 1u];
    size_t count = 0u;

    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, KSI_FORWARD_ENQUEUED);
    if (device != NULL && device->output != NULL
        && ioctl(device->source_fd, EVIOCGSW(sizeof(state)), state) >= 0) {
        for (uint16_t code = 0u; code <= SW_MAX; code++)
            if (ksi_key_bit(device->switches, code))
                events[count++] = (struct input_event){ .type = EV_SW, .code = code,
                    .value = ksi_key_bit(state, code) };
        if (count != 0u) {
            events[count++] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };
            (void)write_locked(device, events, count);
        }
    }
    pthread_mutex_unlock(&devices_mutex);
}

int ksi_linux_forward_write(const ksi_forward_packet *packet)
{
    /* Each event may add a legacy wheel step, and the packet may end its report. */
    struct input_event events[KSI_FORWARD_PACKET_EVENTS * 2u + 1u];
    size_t count = 0u;
    int result;

    if (packet == NULL || packet->count > KSI_FORWARD_PACKET_EVENTS) return -1;

    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(packet->target, KSI_FORWARD_APPLIED);
    bool clone = (packet->flags & KSI_FORWARD_CLONE) != 0u;
    /* A key packet ends with its key. Releasing one the source does not hold
     * changes nothing downstream, but the scan code would still make a report. */
    const uint8_t *output = device != NULL ? device->views[KSI_FORWARD_APPLIED].output : NULL;
    const struct ksi_forward_event *key = packet->count != 0u ? &packet->events[packet->count - 1u] : NULL;
    if (key != NULL && (key->type != EV_KEY || key->code > KEY_MAX)) key = NULL;
    if (device == NULL || (clone ? device->output == NULL : !device->keyboard)
        || (key != NULL && key->value == 0
            && !ksi_key_bit(output, key->code) && !ksi_key_bit(output, ksi_button_alias(key->code)))) {
        pthread_mutex_unlock(&devices_mutex);
        return 0;
    }
    for (uint32_t i = 0u; i < packet->count; i++) {
        uint16_t type = packet->events[i].type, code = packet->events[i].code;
        int32_t value = packet->events[i].value;
        bool vertical = code == REL_WHEEL_HI_RES && device->wheel;
        bool horizontal = code == REL_HWHEEL_HI_RES && device->horizontal_wheel;

        events[count++] = (struct input_event){ .type = type, .code = code, .value = value };
        if (type == EV_REL && (vertical || horizontal)) {
            int32_t steps = ksi_linux_wheel_steps(value,
                vertical ? &device->wheel_remainder : &device->horizontal_remainder);
            if (steps != 0)
                events[count++] = (struct input_event){ .type = EV_REL,
                    .code = vertical ? REL_WHEEL : REL_HWHEEL, .value = steps };
        }
    }
    if ((packet->flags & KSI_FORWARD_REPORT_END) != 0u)
        events[count++] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT };

    const ksi_forward_event *last = packet->count != 0u ? &packet->events[packet->count - 1u] : NULL;
    bool ends_report = (packet->flags & KSI_FORWARD_REPORT_END) != 0u
        || (last != NULL && last->type == EV_SYN && last->code == SYN_REPORT);
    if (clone) {
        result = write_locked(device, events, count);
        device->clone_report_open = !ends_report;
        note_written_keys(device->views[KSI_FORWARD_APPLIED].output, events, count, result);
    } else {
        /* The sink changes only when its first holder presses or its last
         * releases, and repeats only a key it holds. */
        if (key != NULL && key->value != 2)
            ksi_set_key_bit(device->views[KSI_FORWARD_APPLIED].output, key->code, key->value != 0);
        if (key != NULL && (key->value == 2 ? !ksi_key_bit(sink.down, key->code)
                : sink_wants_locked(key->code) == ksi_key_bit(sink.down, key->code))) {
            pthread_mutex_unlock(&devices_mutex);
            return 0;
        }
        result = write_sink_locked(events, count);
        device->sink_report_open = !ends_report;
    }
    pthread_mutex_unlock(&devices_mutex);

    if (result == 0) ksi_linux_output_pace(count);
    return result;
}

static void note_keys(const ksi_forward_packet *packet, ksi_forward_view view, bool source)
{
    if (packet->count > KSI_FORWARD_PACKET_EVENTS
        || (ksi_forward_key_values(packet) & (KSI_FORWARD_KEY_UP | KSI_FORWARD_KEY_DOWN)) == 0u)
        return;

    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(packet->target, view);
    for (uint32_t i = 0u; device != NULL && i < packet->count; i++) {
        uint16_t code = packet->events[i].code;
        int32_t value = packet->events[i].value;
        forward_keys *keys = &device->views[view];

        if (packet->events[i].type != EV_KEY || code > KEY_MAX || value == 2) continue;
        ksi_set_key_bit(source ? keys->source : keys->output, code, value != 0);
        /* A released source leaves nothing to restore. */
        if (source && value == 0) ksi_set_key_bit(keys->displaced, code, false);
    }
    pthread_mutex_unlock(&devices_mutex);
}

void ksi_linux_forward_note_output(const ksi_forward_packet *packet)
{
    note_keys(packet, KSI_FORWARD_ENQUEUED, false);
}

void ksi_linux_forward_note_source(const ksi_forward_packet *packet, ksi_forward_view view)
{
    note_keys(packet, view, true);
}

/* Moves code and its button alias between each source's held and displaced
 * sets; a key on the sink changes there once its last holder lets go. */
static bool shift_key(uint16_t code, ksi_forward_view view, bool restore)
{
    const uint16_t codes[] = { code, ksi_button_alias(code) };
    bool shifted = false;

    if (code > KEY_MAX) return false;
    pthread_mutex_lock(&devices_mutex);
    for (size_t i = 0u; i < slot_limit; i++) {
        forward_keys *keys = &devices[i].views[view];

        if (!live(&devices[i])) continue;
        for (size_t c = 0u; c < (codes[1] != code ? 2u : 1u); c++) {
            if (!ksi_key_bit(restore ? keys->displaced : keys->output, codes[c])) continue;
            ksi_set_key_bit(keys->displaced, codes[c], !restore && ksi_key_bit(keys->source, codes[c]));
            set_output_locked(&devices[i], view, codes[c], restore);
            shifted = true;
        }
    }
    pthread_mutex_unlock(&devices_mutex);
    return shifted;
}

void ksi_linux_forward_release_key(uint16_t code, ksi_forward_view view)
{
    (void)shift_key(code, view, false);
}

bool ksi_linux_forward_restore_key(uint16_t code, ksi_forward_view view)
{
    return shift_key(code, view, true);
}

void ksi_linux_forward_release_all(ksi_forward_view view)
{
    pthread_mutex_lock(&devices_mutex);
    for (size_t i = 0u; i < slot_limit; i++)
        if (live(&devices[i])) release_outputs_locked(&devices[i], view, NULL);
    pthread_mutex_unlock(&devices_mutex);
}

void ksi_linux_forward_add_key_state(uint64_t target, uint8_t *keys, size_t size)
{
    pthread_mutex_lock(&devices_mutex);
    forwarding_device *device = find_device_locked(target, KSI_FORWARD_ENQUEUED);
    for (size_t i = 0u; device != NULL && i < size && i < KSI_KEY_BITMAP_BYTES; i++)
        keys[i] |= device->views[KSI_FORWARD_ENQUEUED].output[i];
    pthread_mutex_unlock(&devices_mutex);
}

/* A new sink starts with nothing held: the desktop released what the old one
 * held when it disappeared. Detaching starts a generation, so the reader waits
 * for udev to admit the next sink, and notifies it to fail keyboards open. */
void ksi_linux_forward_attach_sink(int fd)
{
    if (fd < 0) {
        atomic_fetch_add(&sink_generation, 1u);
        atomic_store(&failure_pending, true);
    }
    pthread_mutex_lock(&devices_mutex);
    sink.fd = fd;
    sink.failed = false;
    atomic_store(&sink_ready_flag, fd >= 0);
    memset(sink.down, 0, sizeof(sink.down));
    memset(sink.synth, 0, sizeof(sink.synth));
    pthread_mutex_unlock(&devices_mutex);
}

uint32_t ksi_linux_forward_sink_generation(void)
{
    return atomic_load(&sink_generation);
}

bool ksi_linux_forward_sink_ready(void)
{
    return atomic_load(&sink_ready_flag);
}

int ksi_linux_forward_sink_key(uint16_t code, bool held)
{
    int written;

    if (code > KEY_MAX) return 0;
    pthread_mutex_lock(&devices_mutex);
    ksi_set_key_bit(sink.synth, code, held);
    written = reconcile_locked(code);
    pthread_mutex_unlock(&devices_mutex);
    return written;
}

int ksi_linux_forward_sink_tap(uint16_t code)
{
    int result;

    if (code > KEY_MAX) return -1;
    pthread_mutex_lock(&devices_mutex);
    bool down = ksi_key_bit(sink.down, code);
    const struct input_event events[] = {
        { .type = EV_KEY, .code = code, .value = !down },
        { .type = EV_SYN, .code = SYN_REPORT },
        { .type = EV_KEY, .code = code, .value = down },
        { .type = EV_SYN, .code = SYN_REPORT },
    };
    result = write_sink_locked(events, 4u);
    pthread_mutex_unlock(&devices_mutex);
    return result == 0 ? 4 : -1;
}

void ksi_linux_forward_sink_clear_synth(void)
{
    pthread_mutex_lock(&devices_mutex);
    for (size_t byte = 0u; byte < KSI_KEY_BITMAP_BYTES; byte++) {
        unsigned int bits = sink.synth[byte];
        sink.synth[byte] = 0u;
        for (; bits != 0u; bits &= bits - 1u)
            (void)reconcile_locked((uint16_t)(byte * 8u + (unsigned int)__builtin_ctz(bits)));
    }
    pthread_mutex_unlock(&devices_mutex);
}

uint32_t ksi_linux_forward_epoch(void)
{
    return atomic_load(&target_epoch);
}

void ksi_linux_forward_collect(bool shutdown)
{
    struct libevdev_uinput *expired[KSI_MAX_FORWARDING_DEVICES];
    size_t count = 0u;

    if (atomic_load(&retiring_count) == 0u) return;
    if (shutdown) ksi_linux_sleep_ns(KSI_FORWARD_DRAIN_MS * 1000000L);

    uint64_t now = ksi_linux_monotonic_ms();
    pthread_mutex_lock(&devices_mutex);
    for (size_t i = 0u; i < slot_limit; i++) {
        if (!devices[i].retiring
            || (!shutdown && now - devices[i].retire_ms < KSI_FORWARD_DRAIN_MS)) continue;
        expired[count++] = devices[i].output;
        memset(&devices[i], 0, sizeof(devices[i]));
    }
    pthread_mutex_unlock(&devices_mutex);

    atomic_fetch_sub(&retiring_count, (unsigned int)count);
    for (size_t i = 0u; i < count; i++) destroy_output(expired[i]);
}
