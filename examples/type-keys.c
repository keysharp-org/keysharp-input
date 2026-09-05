#include <keysharp_input/client.h>
#include <stdio.h>

static int press(ksi_connection *connection, uint16_t vk, ksi_error *error)
{
    ksi_input down;
    ksi_input up;

    ksi_input_init(&down);
    down.type = KSI_INPUT_KEYBOARD;
    down.data.keyboard.vk = vk;
    up = down;
    up.data.keyboard.flags = KSI_KEY_UP;

    if (ksi_synthesize(connection, &down, 1u, 0u, error) != KSI_STATUS_OK)
        return 0;
    return ksi_synthesize(connection, &up, 1u, 0u, error) == KSI_STATUS_OK;
}

int main(void)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_permission_scopes granted = 0u;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    options.requested_scopes = KSI_SCOPE_INPUT_CONTROL;

    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "connect: %s\n", error.message);
        return 1;
    }
    if (ksi_authorize(connection, KSI_AUTH_REQUEST, KSI_SCOPE_INPUT_CONTROL,
                      &granted, &error) != KSI_STATUS_OK) {
        fprintf(stderr, "authorize: %s\n", error.message);
        ksi_disconnect(connection);
        return 1;
    }
    if (!press(connection, 'H', &error) || !press(connection, 'I', &error))
        fprintf(stderr, "synthesize: %s\n", error.message);
    ksi_disconnect(connection);
    return 0;
}
