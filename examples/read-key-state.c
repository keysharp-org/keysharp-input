#include <keysharp_input/client.h>
#include <stdio.h>

static bool select_device(const ksi_device_info *device, void *context)
{
    if ((device->capabilities & (KSI_DEVICE_KEYBOARD | KSI_DEVICE_MOUSE)) == 0u) return true;
    *(uint32_t *)context = device->device_id;
    printf("%u %s\n", device->device_id, device->name);
    return false;
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_permission_scopes granted;
    uint64_t generation;
    uint32_t device_id = 0u;
    ksi_key_state state;
    ksi_key_state_init(&state);
    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.requested_scopes = KSI_SCOPE_INPUT_MONITORING;
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK
        || ksi_authorize(connection, KSI_AUTH_REQUEST, KSI_SCOPE_INPUT_MONITORING,
            &granted, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "%s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    ksi_status status = ksi_devices_list(connection, select_device, &device_id, &generation, &error);
    if ((status != KSI_STATUS_OK && status != KSI_STATUS_CANCELLED) || device_id == 0u
        || ksi_get_device_key_state(connection, device_id, &state, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "No readable keyboard or mouse: %s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    for (unsigned int code = 0u; code < KSI_KEY_STATE_BITMAP_BITS; code++)
        if ((state.physical_keys[code / 8u] & (1u << (code % 8u))) != 0u)
            printf("physical evdev code %u is held\n", code);
    ksi_disconnect(connection);
    return 0;
}
