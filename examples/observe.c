#include <keysharp_input/client.h>
#include <stdio.h>

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_permission_scopes granted;
    ksi_operations active;
    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.role = KSI_ROLE_OBSERVER_STREAM;
    options.requested_scopes = KSI_SCOPE_INPUT_MONITORING;
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK
        || ksi_authorize(connection, KSI_AUTH_REQUEST, KSI_SCOPE_INPUT_MONITORING,
            &granted, &error) != KSI_STATUS_OK
        || ksi_hook_subscribe(connection, KSI_HOOK_KEYBOARD, &active, &error) != KSI_STATUS_OK
        || ksi_hook_subscribe(connection, KSI_HOOK_MOUSE, &active, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "%s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    for (;;) {
        ksi_observer_message message;
        ksi_observer_message_init(&message);
        if (ksi_observer_next(connection, UINT32_MAX, &message, &error) != KSI_STATUS_OK) break;
        if (message.kind == KSI_OBSERVER_INPUT && message.data.input.hook_type == KSI_HOOK_KEYBOARD) {
            printf("device %u, scan %u\n", message.data.input.event.keyboard.device_id,
                message.data.input.event.keyboard.scan_code);
        } else if (message.kind == KSI_OBSERVER_RAW_INPUT) {
            const ksi_raw_input_event *raw = &message.data.raw_input;
            printf("device %u, raw type %u code %u value %d\n", raw->device_id,
                raw->type, raw->code, raw->value);
        } else if (message.kind == KSI_OBSERVER_OVERFLOW) {
            fprintf(stderr, "Observer lost events; refresh any cached state.\n");
        } else if (message.kind == KSI_OBSERVER_SESSION_REVOKED) break;
    }
    ksi_disconnect(connection);
    return 0;
}
