#include <keysharp_input/client.h>
#include <stdio.h>

static void device_changed(const ksi_observer_message *message, void *context)
{
    (void)context;
    if (message->kind >= KSI_OBSERVER_DEVICE_ADDED
        && message->kind <= KSI_OBSERVER_DEVICE_CHANGED)
        printf("device %u: %s, unique %s\n", message->data.device.device_id,
            message->data.device.name, message->data.device.unique);
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_connection *lease = NULL;
    ksi_permission_scopes granted = 0u;
    ksi_operations active = 0u;
    const ksi_permission_scopes wanted =
        KSI_SCOPE_INPUT_MONITORING | KSI_SCOPE_INPUT_CONTROL;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.role = KSI_ROLE_AUTHORIZATION_LEASE;
    options.requested_scopes = 0u;

    if (ksi_connect(&options, &lease, &info, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "connect: %s\n", error.message);
        return 1;
    }
    if (ksi_authorize(lease, KSI_AUTH_REQUEST, wanted, &granted, &error)
            != KSI_STATUS_OK) {
        fprintf(stderr, "authorize: %s\n", error.message);
        ksi_disconnect(lease);
        return 1;
    }
    options.role = KSI_ROLE_CALLBACK_STREAM;
    options.lease_id = info.lease_id;
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK
        || ksi_set_device_change_handler(connection, device_changed, NULL, &error)
            != KSI_STATUS_OK
        || ksi_devices_subscribe(connection, &error) != KSI_STATUS_OK
        || ksi_hook_subscribe(connection, KSI_HOOK_KEYBOARD, &active, &error)
            != KSI_STATUS_OK) {
        fprintf(stderr, "subscribe: %s\n", error.message);
        ksi_disconnect(connection);
        ksi_disconnect(lease);
        return 1;
    }

    for (;;) {
        ksi_hook_message message;
        ksi_hook_reply reply;

        ksi_hook_message_init(&message);
        if (ksi_hook_next(connection, UINT32_MAX, &message, &error)
                != KSI_STATUS_OK)
            break;
        if (message.kind != KSI_HOOK_MESSAGE_EVENT)
            continue;

        ksi_hook_reply_init(&reply);
        reply.decision = KSI_HOOK_PASS;
        if (!(message.data.event.event.keyboard.flags & KSI_KEYBOARD_HOOK_UP)) {
            printf("device %u, vk %u\n", message.data.event.event.keyboard.device_id,
                message.data.event.event.keyboard.vk_code);
            fflush(stdout);
            if (message.data.event.event.keyboard.vk_code == 0x1Bu)
                reply.decision = KSI_HOOK_BLOCK;
        }
        if (ksi_hook_reply_event(connection, &message.data.event, &reply,
                                 &error) != KSI_STATUS_OK)
            break;
    }
    ksi_disconnect(connection);
    ksi_disconnect(lease);
    return 0;
}
