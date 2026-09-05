#include "keysharp_input/client.h"
#include "../src/device_codec.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define HEADER_SIZE 24u
#define RESPONSE 0x0001u
#define EVENT 0x0002u
#define HELLO 0x0001u
#define PING 0x0003u
#define SESSION_REVOKED 0x0006u
#define HOOK_EVENT 0x1002u
#define HOOK_QUARANTINED 0x1003u
#define SYNTHESIZE 0x1010u
#define FUTURE_SCOPE_REVOKED 0x00000004u
#define FUTURE_SCOPE_KEPT 0x00000008u
#define FUTURE_HOOK_TYPE 15u
#define FUTURE_OPERATION UINT64_C(0x0000000000001000)

_Static_assert(sizeof(ksi_service_info) == 56u,
    "service-info ABI size changed");
_Static_assert(offsetof(ksi_service_info, granted_scopes) == 12u,
    "service-info scope offset changed");
_Static_assert(offsetof(ksi_service_info, available_operations) == 16u,
    "service-info operation offset changed");

typedef struct server_state {
    int listener;
    int failed;
} server_state;

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u)
        | ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static uint64_t read_u64(const uint8_t *p)
{
    return (uint64_t)read_u32(p) | ((uint64_t)read_u32(p + 4u) << 32u);
}

static void write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8u);
}

static void write_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8u);
    p[2] = (uint8_t)(v >> 16u); p[3] = (uint8_t)(v >> 24u);
}

static void write_u64(uint8_t *p, uint64_t v)
{
    write_u32(p, (uint32_t)v); write_u32(p + 4u, (uint32_t)(v >> 32u));
}

static bool transfer(int fd, void *buffer, size_t size, bool writing)
{
    size_t offset = 0u;
    while (offset < size) {
        ssize_t count = writing
            ? write(fd, (const uint8_t *)buffer + offset, size - offset)
            : read(fd, (uint8_t *)buffer + offset, size - offset);
        if (count > 0) { offset += (size_t)count; continue; }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

static bool receive_frame(
    int fd, uint16_t *opcode, uint16_t *flags, uint64_t *id,
    uint8_t *payload, size_t capacity, size_t *payload_size)
{
    uint8_t header[HEADER_SIZE];
    if (!transfer(fd, header, sizeof(header), false)
        || memcmp(header, "KSIP", 4u) != 0) return false;
    *opcode = read_u16(header + 8u); *flags = read_u16(header + 10u);
    *payload_size = read_u32(header + 12u); *id = read_u64(header + 16u);
    return *payload_size <= capacity
        && transfer(fd, payload, *payload_size, false);
}

static bool send_frame(
    int fd, uint16_t opcode, uint16_t flags, uint64_t id,
    const uint8_t *payload, size_t payload_size)
{
    uint8_t header[HEADER_SIZE] = { 'K', 'S', 'I', 'P' };
    write_u16(header + 4u, 2u); write_u16(header + 6u, 0u);
    write_u16(header + 8u, opcode); write_u16(header + 10u, flags);
    write_u32(header + 12u, (uint32_t)payload_size); write_u64(header + 16u, id);
    return transfer(fd, header, sizeof(header), true)
        && transfer(fd, (void *)payload, payload_size, true);
}

static void *server_main(void *argument)
{
    server_state *state = argument;
    uint8_t payload[65512];
    uint16_t opcode, flags;
    uint64_t outer_id, nested_id, event_id = 100u;
    size_t size;
    int fd = accept(state->listener, NULL, NULL);
    if (fd < 0) { state->failed = 1; return NULL; }

    if (!receive_frame(fd, &opcode, &flags, &outer_id, payload, sizeof(payload), &size)
        || opcode != HELLO || flags != 0u || size != 16u
        || read_u16(payload) != KSI_ROLE_CALLBACK_STREAM) goto fail;
    memset(payload, 0, 24u); write_u32(payload, KSI_STATUS_OK);
    write_u32(payload + 8u, KSI_SCOPE_INPUT_CONTROL | FUTURE_SCOPE_REVOKED
        | FUTURE_SCOPE_KEPT);
    write_u64(payload + 16u, KSI_OPERATION_HOOK_KEYBOARD
        | KSI_OPERATION_SYNTHESIZE_KEYBOARD | FUTURE_OPERATION);
    if (!send_frame(fd, HELLO, RESPONSE, outer_id, payload, 24u)) goto fail;

    if (!receive_frame(fd, &opcode, &flags, &outer_id, payload, sizeof(payload), &size)
        || opcode != SYNTHESIZE || flags != 0u) goto fail;
    memset(payload, 0, 48u); write_u32(payload, KSI_HOOK_KEYBOARD);
    write_u32(payload + 8u, KSI_MESSAGE_KEY_DOWN);
    write_u32(payload + 12u, 0x41u);
    if (!send_frame(fd, HOOK_EVENT, 0u, event_id, payload, 48u)) goto fail;

    if (!receive_frame(fd, &opcode, &flags, &nested_id, payload, sizeof(payload), &size)
        || opcode != SYNTHESIZE || flags != 0u || nested_id == outer_id) goto fail;
    memset(payload, 0, 8u);
    if (!send_frame(fd, SYNTHESIZE, RESPONSE, nested_id, payload, 8u)) goto fail;

    if (!receive_frame(fd, &opcode, &flags, &nested_id, payload, sizeof(payload), &size)
        || opcode != HOOK_EVENT || flags != RESPONSE || nested_id != event_id
        || size != 16u || read_u32(payload + 8u) != KSI_HOOK_PASS) goto fail;

    memset(payload, 0, 32u); write_u32(payload, FUTURE_HOOK_TYPE);
    write_u32(payload + 4u, KSI_HOOK_QUARANTINE_TIMEOUT);
    write_u64(payload + 8u, event_id); write_u32(payload + 16u, 3u);
    write_u32(payload + 20u, 1u); write_u32(payload + 24u, 1000u);
    if (!send_frame(fd, HOOK_QUARANTINED, EVENT, 0u, payload, 32u)) goto fail;
    memset(payload, 0, 8u);
    write_u32(payload, KSI_SCOPE_INPUT_CONTROL | FUTURE_SCOPE_REVOKED);
    if (!send_frame(fd, SESSION_REVOKED, EVENT, 0u, payload, 8u)) goto fail;
    memset(payload, 0, 8u);
    if (!send_frame(fd, SYNTHESIZE, RESPONSE, outer_id, payload, 8u)
        || !receive_frame(fd, &opcode, &flags, &nested_id,
            payload, sizeof(payload), &size)
        || opcode != PING || flags != 0u || nested_id != 0u || size != 0u)
        goto fail;

    close(fd); return NULL;
fail:
    state->failed = 1; close(fd); return NULL;
}

static ksi_status nested_handler(
    ksi_connection *connection, const ksi_hook_event *event,
    ksi_hook_reply *reply, void *context, ksi_error *error)
{
    unsigned int *calls = context;
    (*calls)++;
    if (event->hook_type != KSI_HOOK_KEYBOARD) return KSI_STATUS_INTERNAL;
    ksi_hook_reply_init(reply);
    return ksi_synthesize(connection, NULL, 0u, KSI_SYNTH_BYPASS_HOOK, error);
}

static void *observer_server(void *argument)
{
    server_state *state = argument;
    uint8_t payload[4096];
    uint16_t opcode, flags;
    uint64_t id;
    size_t size;
    int fd = accept(state->listener, NULL, NULL);
    if (fd < 0) { state->failed = 1; return NULL; }
    if (!receive_frame(fd, &opcode, &flags, &id, payload, sizeof(payload), &size)
        || opcode != HELLO || read_u16(payload) != KSI_ROLE_OBSERVER_STREAM) goto fail;
    memset(payload, 0, 24u);
    write_u32(payload + 8u, KSI_SCOPE_INPUT_MONITORING);
    write_u64(payload + 16u, KSI_OPERATION_OBSERVE_KEYBOARD | KSI_OPERATION_QUERY_DEVICES);
    if (!send_frame(fd, HELLO, RESPONSE, id, payload, 24u)) goto fail;
    if (!receive_frame(fd, &opcode, &flags, &id, payload, sizeof(payload), &size)
        || opcode != KSI_OPCODE_SUBSCRIBE_HOOK || read_u32(payload) != KSI_HOOK_KEYBOARD) goto fail;
    memset(payload, 0, 72u);
    write_u32(payload, KSI_OBSERVER_INPUT); write_u64(payload + 8u, 2u);
    write_u32(payload + 24u, KSI_HOOK_KEYBOARD);
    write_u32(payload + 32u, KSI_MESSAGE_KEY_DOWN); write_u32(payload + 36u, 'A');
    write_u32(payload + 64u, 7u);
    if (!send_frame(fd, KSI_OPCODE_OBSERVER_EVENT, EVENT, 0u, payload, 72u)) goto fail;
    memset(payload, 0, 16u); write_u32(payload + 8u, KSI_OPERATION_OBSERVE_KEYBOARD);
    if (!send_frame(fd, KSI_OPCODE_SUBSCRIBE_HOOK, RESPONSE, id, payload, 16u)) goto fail;
    if (!receive_frame(fd, &opcode, &flags, &id, payload, sizeof(payload), &size)
        || opcode != KSI_OPCODE_DEVICES_LIST || size != KSI_DEVICE_LIST_REQUEST_SIZE) goto fail;
    ksi_device_info device = { .struct_size = sizeof(device), .device_id = 7u,
        .name = "Observed keyboard", .path = "/dev/input/event2", .vendor = 0x1234u,
        .capabilities = KSI_DEVICE_KEYBOARD };
    memset(payload, 0, KSI_DEVICE_LIST_PREFIX_SIZE);
    write_u64(payload + 8u, 2u); write_u32(payload + 20u, 1u);
    ksi_device_encode(payload + KSI_DEVICE_LIST_PREFIX_SIZE, &device);
    if (!send_frame(fd, KSI_OPCODE_DEVICES_LIST, RESPONSE, id, payload,
            KSI_DEVICE_LIST_PREFIX_SIZE + KSI_DEVICE_INFO_WIRE_SIZE)) goto fail;
    memset(payload, 0, KSI_OBSERVER_PREFIX_SIZE);
    write_u32(payload, KSI_OBSERVER_DEVICE_REMOVED); write_u64(payload + 8u, 3u);
    ksi_device_encode(payload + KSI_OBSERVER_PREFIX_SIZE, &device);
    if (!send_frame(fd, KSI_OPCODE_OBSERVER_EVENT, EVENT, 0u, payload,
            KSI_OBSERVER_PREFIX_SIZE + KSI_DEVICE_INFO_WIRE_SIZE)) goto fail;
    memset(payload, 0, KSI_OBSERVER_PREFIX_SIZE + KSI_RAW_INPUT_WIRE_SIZE);
    write_u32(payload, KSI_OBSERVER_RAW_INPUT);
    write_u32(payload + 24u, 12u); write_u64(payload + 32u, 123456u);
    write_u16(payload + 40u, 3u); write_u16(payload + 42u, 53u);
    write_u32(payload + 44u, (uint32_t)-50); write_u32(payload + 48u, KSI_RAW_INPUT_MONOTONIC_TIME);
    if (!send_frame(fd, KSI_OPCODE_OBSERVER_EVENT, EVENT, 0u, payload,
            KSI_OBSERVER_PREFIX_SIZE + KSI_RAW_INPUT_WIRE_SIZE)) goto fail;
    memset(payload, 0, KSI_OBSERVER_PREFIX_SIZE);
    write_u32(payload, KSI_OBSERVER_OVERFLOW); write_u64(payload + 8u, 3u); write_u64(payload + 16u, 9u);
    if (!send_frame(fd, KSI_OPCODE_OBSERVER_EVENT, EVENT, 0u, payload, KSI_OBSERVER_PREFIX_SIZE)) goto fail;
    memset(payload, 0, 8u); write_u32(payload, KSI_SCOPE_INPUT_MONITORING);
    if (!send_frame(fd, SESSION_REVOKED, EVENT, 0u, payload, 8u)) goto fail;
    /* No observer event should generate a hook-decision frame. */
    if (read(fd, payload, 1u) != 0) goto fail;
    close(fd); return NULL;
fail:
    state->failed = 1; close(fd); return NULL;
}

static bool visit_device(const ksi_device_info *device, void *context)
{
    unsigned int *count = context;
    if (device->device_id == 7u && device->vendor == 0x1234u
        && strcmp(device->name, "Observed keyboard") == 0) (*count)++;
    return true;
}

static int run_client_test(bool observer)
{
    char directory[] = "/tmp/keysharp-input-client-XXXXXX";
    char socket_path[108];
    struct sockaddr_un address;
    server_state server = { .listener = -1 };
    pthread_t thread;
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;
    ksi_hook_message message;
    unsigned int callback_calls = 0u;
    int result = 1;

    ksi_connect_options_init(&options);
    if (options.timeout_ms != KSI_DEFAULT_REQUEST_TIMEOUT_MS
        || options.timeout_ms != 130000u) return 1;
    if (mkdtemp(directory) == NULL) return 1;
    (void)snprintf(socket_path, sizeof(socket_path), "%s/socket", directory);
    server.listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server.listener < 0) goto done;
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
    if (bind(server.listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server.listener, 1) != 0
        || pthread_create(&thread, NULL, observer ? observer_server : server_main, &server) != 0) goto done;

    options.socket_path = socket_path;
    options.role = observer ? KSI_ROLE_OBSERVER_STREAM : KSI_ROLE_CALLBACK_STREAM;
    options.requested_scopes = observer ? KSI_SCOPE_INPUT_MONITORING : KSI_SCOPE_INPUT_CONTROL;
    ksi_service_info_init(&info); ksi_error_init(&error);
    if (observer) {
        ksi_observer_message observation;
        ksi_operations active = 0u;
        unsigned int device_count = 0u;
        ksi_observer_message_init(&observation);
        if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK
            || ksi_hook_subscribe(connection, KSI_HOOK_KEYBOARD, &active, &error) != KSI_STATUS_OK
            || active != KSI_OPERATION_OBSERVE_KEYBOARD
            || ksi_observer_next(connection, 1000u, &observation, &error) != KSI_STATUS_OK
            || observation.kind != KSI_OBSERVER_INPUT || observation.data.input.request_id != 0u
            || observation.data.input.event.keyboard.device_id != 7u
            || ksi_devices_list(connection, visit_device, &device_count, NULL, &error) != KSI_STATUS_OK
            || device_count != 1u
            || ksi_observer_next(connection, 1000u, &observation, &error) != KSI_STATUS_OK
            || observation.kind != KSI_OBSERVER_DEVICE_REMOVED || observation.device_generation != 3u
            || ksi_observer_next(connection, 1000u, &observation, &error) != KSI_STATUS_OK
            || observation.kind != KSI_OBSERVER_RAW_INPUT || observation.data.raw_input.device_id != 12u
            || observation.data.raw_input.type != 3u || observation.data.raw_input.code != 53u
            || observation.data.raw_input.value != -50 || observation.data.raw_input.time_ms != 123456u
            || ksi_observer_next(connection, 1000u, &observation, &error) != KSI_STATUS_OK
            || observation.kind != KSI_OBSERVER_OVERFLOW || observation.dropped_events != 9u
            || ksi_observer_next(connection, 1000u, &observation, &error) != KSI_STATUS_OK
            || observation.kind != KSI_OBSERVER_SESSION_REVOKED
            || ksi_connection_granted_scopes(connection) != 0u) goto joined;
        result = 0;
        goto joined;
    }
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK
        || ksi_set_nested_hook_handler(connection, nested_handler,
            &callback_calls, &error) != KSI_STATUS_OK
        || ksi_synthesize(connection, NULL, 0u,
            KSI_SYNTH_BYPASS_HOOK, &error) != KSI_STATUS_OK
        || callback_calls != 1u
        || ksi_connection_available_operations(connection)
            != (KSI_OPERATION_HOOK_KEYBOARD | KSI_OPERATION_SYNTHESIZE_KEYBOARD
                | FUTURE_OPERATION)
        || ksi_connection_granted_scopes(connection) != 0u) goto joined;
    ksi_hook_message_init(&message);
    if (ksi_hook_next(connection, 0u, &message, &error) != KSI_STATUS_OK
        || message.kind != KSI_HOOK_MESSAGE_QUARANTINED
        || message.data.quarantined.hook_type
            != FUTURE_HOOK_TYPE) goto joined;
    ksi_hook_message_init(&message);
    if (ksi_hook_next(connection, 0u, &message, &error) != KSI_STATUS_OK
        || message.kind != KSI_HOOK_MESSAGE_SESSION_REVOKED
        || message.data.revoked_scopes
            != (KSI_SCOPE_INPUT_CONTROL | FUTURE_SCOPE_REVOKED)) goto joined;
    ksi_hook_message_init(&message);
    if (ksi_hook_next(connection, 1u, &message, &error) != KSI_STATUS_TIMEOUT)
        goto joined;
    result = 0;
joined:
    ksi_disconnect(connection); pthread_join(thread, NULL);
    if (server.failed) result = 1;
done:
    if (server.listener >= 0) close(server.listener);
    unlink(socket_path); rmdir(directory);
    return result;
}

int main(void)
{
    return run_client_test(false) || run_client_test(true);
}
