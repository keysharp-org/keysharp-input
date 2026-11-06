#include <keysharp_input/client.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s VT_NUMBER UTF8_TEXT\n", argv[0]);
        return 1;
    }
    char *end;
    errno = 0;
    unsigned long target = strtoul(argv[1], &end, 10);
    size_t length = strlen(argv[2]);
    if (errno != 0 || end == argv[1] || *end != '\0' || target < 1u || target > 63u
        || length > KSI_MAX_TERMINAL_INPUT_BYTES) {
        fprintf(stderr, "expected VT 1..63 and at most %u UTF-8 bytes\n", KSI_MAX_TERMINAL_INPUT_BYTES);
        return 1;
    }
    ksi_connect_options connect;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_connect_options_init(&connect);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    connect.role = KSI_ROLE_AUTHORIZATION_LEASE;
    ksi_status status = ksi_connect(&connect, &connection, &info, &error);
    if (status != KSI_STATUS_OK) {
        fprintf(stderr, "connect: %s\n", error.message);
        return 1;
    }
    if ((info.available_operations & KSI_OPERATION_TERMINAL_INPUT) == 0u) {
        fprintf(stderr, "service does not support targeted terminal input\n");
        ksi_disconnect(connection);
        return 1;
    }
    status = ksi_authorize(connection, KSI_AUTH_REQUEST, KSI_SCOPE_INPUT_CONTROL, NULL, &error);
    if (status == KSI_STATUS_OK) {
        ksi_terminal_input_options options;
        ksi_terminal_input_result result;
        ksi_terminal_input_options_init(&options);
        ksi_terminal_input_result_init(&result);
        options.target_id = (uint32_t)target;
        options.flags = KSI_TERMINAL_INPUT_REQUIRE_UTF8 | KSI_TERMINAL_INPUT_TEXT;
        status = ksi_terminal_input(connection, &options, argv[2], (uint32_t)length, &result, &error);
        if (status == KSI_STATUS_OK) printf("submitted %u bytes\n", result.bytes_accepted);
        else fprintf(stderr, "terminal input: %s; no automatic retry\n", error.message);
    } else fprintf(stderr, "authorize: %s\n", error.message);
    ksi_disconnect(connection);
    return status == KSI_STATUS_OK ? 0 : 1;
}
