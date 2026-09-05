#include <libevdev/libevdev.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "device_codec.h"
#include "platform/linux_wheel.h"

bool g_verbose = false;
static int fake_next_event(struct libevdev *device, unsigned int flags, struct input_event *event);
#define libevdev_next_event fake_next_event
#include "../src/platform/linux_devices.c"
#undef libevdev_next_event

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

static bool test_sync_repairs_lost_release(void)
{
    ksi_linux_tracked_device device = {
        .fd = -1, .evdev = (struct libevdev *)&step, .device_id = 4u,
        .grabbed = true, .keyboard_candidate = true,
        .has_pending_rel = true, .pending_rel_x = 17,
    };
    set_bit(device.physical_down_keys, KEY_A);
    step = 0u; step_count = 4u; wrong_flag = false; hooks = 0u;
    expected_flags[0] = LIBEVDEV_READ_FLAG_NORMAL;
    expected_flags[1] = LIBEVDEV_READ_FLAG_SYNC;
    expected_flags[2] = LIBEVDEV_READ_FLAG_SYNC;
    expected_flags[3] = LIBEVDEV_READ_FLAG_NORMAL;
    results[0] = results[1] = LIBEVDEV_READ_STATUS_SYNC;
    results[2] = results[3] = -EAGAIN;
    events[0] = (struct input_event){ .type = EV_SYN, .code = SYN_DROPPED };
    events[1] = (struct input_event){ .type = EV_KEY, .code = KEY_A, .value = 0 };
    ksi_linux_devices_set_hook_event_callback(capture, &hooks);
    process_device_events(&device);
    CHECK(step == 4u && !wrong_flag && !device.synchronizing);
    CHECK(!test_bit(device.physical_down_keys, KEY_A));
    CHECK(hooks == 1u && keyboard_event.message == KSI_MESSAGE_KEY_UP);
    CHECK((keyboard_event.flags & KSI_KEYBOARD_HOOK_SYNCHRONIZED) != 0u);
    CHECK(!device.has_pending_rel && device.pending_rel_x == 0);

    /* The admission peeker must preserve the same synchronization contract. */
    step = 0u; wrong_flag = false;
    CHECK(buffer_next_device_event(&device));
    CHECK(device.has_buffered_event && device.buffered_event.code == KEY_A);
    CHECK(!wrong_flag && step == 2u);
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
    };
    ksi_device_info decoded;
    uint8_t wire[KSI_DEVICE_INFO_WIRE_SIZE];
    ksi_device_encode(wire, &original);
    CHECK(ksi_device_decode(wire, sizeof(wire), &decoded));
    CHECK(memcmp(&decoded, &original, sizeof(original)) == 0);
    memset(wire + 24u, 'x', KSI_DEVICE_NAME_CAPACITY);
    CHECK(!ksi_device_decode(wire, sizeof(wire), &decoded));
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

int main(void)
{
    if (!test_sync_repairs_lost_release() || !test_observation_without_grab()
        || !test_high_resolution_wheel() || !test_device_metadata_codec()
        || !test_raw_touchpad_observation()) return 1;
    puts("PASS device state synchronization, passive observation, wheel precision and metadata");
    return 0;
}
