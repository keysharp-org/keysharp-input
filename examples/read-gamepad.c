#include <keysharp_input/client.h>
#include <stdio.h>

typedef struct gamepad {
    uint32_t device_id;
    char name[KSI_DEVICE_NAME_CAPACITY];
    uint32_t axis_count;
    ksi_device_axis_info axes[KSI_DEVICE_AXIS_CAPACITY];
} gamepad;

/* Returning false stops the enumeration, which reports CANCELLED. */
static bool take_first(const ksi_device_info *device, void *context)
{
    gamepad *found = context;
    found->device_id = device->device_id;
    snprintf(found->name, sizeof(found->name), "%s", device->name);
    found->axis_count = device->axis_count;
    for (uint32_t i = 0u; i < device->axis_count; i++) found->axes[i] = device->axes[i];
    printf("%s: %u buttons, %u axes\n", device->name, device->button_count, device->axis_count);
    return false;
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_gamepad_state state;
    gamepad found = { 0 };
    uint64_t generation = 0u;
    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    /* Gamepads need no scope, so this connection requests none. */
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "%s\n", error.message);
        return 1;
    }
    ksi_status status = ksi_gamepads_list(connection, take_first, &found, &generation, &error);
    if ((status != KSI_STATUS_OK && status != KSI_STATUS_CANCELLED) || found.device_id == 0u) {
        fprintf(stderr, "No gamepad is connected.\n");
        ksi_disconnect(connection);
        return 1;
    }
    ksi_gamepad_state_init(&state);
    /* The listing's generation makes this the device the listing described. */
    if (ksi_get_gamepad_state(connection, found.device_id, generation, &state, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "%s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    for (uint32_t i = 0u; i < state.button_count; i++) {
        if ((state.buttons[i >> 3] & (1u << (i & 7u))) != 0u) printf("button %u is down\n", i + 1u);
    }
    for (uint32_t i = 0u; i < state.axis_count && i < found.axis_count; i++) {
        int32_t range = found.axes[i].maximum - found.axes[i].minimum;
        printf("axis %u: %d%%\n", state.axes[i].code, range != 0
            ? 100 * (state.axes[i].value - found.axes[i].minimum) / range : 0);
    }
    ksi_disconnect(connection);
    return 0;
}
