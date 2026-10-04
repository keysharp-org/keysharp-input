#include "keysharp_input/client.h"
#include "device_codec.h"

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

_Static_assert(sizeof(ksi_service_info) == 64u, "service-info layout");
_Static_assert(sizeof(ksi_connect_options) == 72u, "connect-options layout");
_Static_assert(sizeof(ksi_key_state) == 224u, "keyboard-state layout");
_Static_assert(sizeof(ksi_lease_message) == 288u, "lease-message layout");
_Static_assert(offsetof(ksi_lease_message, state) == 32u, "lease keyboard-state offset");

#define LE32(value) \
    (uint8_t)((uint32_t)(value)), \
    (uint8_t)((uint32_t)(value) >> 8u), \
    (uint8_t)((uint32_t)(value) >> 16u), \
    (uint8_t)((uint32_t)(value) >> 24u)

#define HOOK_REQUEST_ID UINT64_C(17)

ksi_connection *ksi_client_test_adopt_descriptor(int descriptor);
void ksi_client_test_set_role(ksi_connection *connection, uint32_t role);
void ksi_client_test_set_timeout(ksi_connection *connection, uint32_t timeout_ms);
void ksi_client_test_set_outstanding_hook_request(
    ksi_connection *connection, uint64_t request_id);

typedef ksi_status (*client_call)(ksi_connection *connection,
                                  ksi_error *error);

static void transfer(int descriptor, void *data, size_t length, bool write_data)
{
    uint8_t *bytes = data;
    size_t offset = 0u;

    while (offset < length) {
        ssize_t count = write_data
            ? write(descriptor, bytes + offset, length - offset)
            : read(descriptor, bytes + offset, length - offset);
        assert(count > 0);
        offset += (size_t)count;
    }
}

static void write_success(int descriptor, uint16_t opcode,
                          uint32_t payload_length)
{
    uint8_t header[KSI_FRAME_HEADER_SIZE] = { 0 };
    uint8_t payload[KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE]
        = { 0 };

    assert(payload_length >= KSI_STATUS_PAYLOAD_SIZE
           && payload_length <= sizeof(payload));
    memcpy(header, KSI_FRAME_MAGIC, 4u);
    ksi_device_write(header + 4u, KSI_PROTOCOL_MAJOR, 2u);
    ksi_device_write(header + 6u, KSI_PROTOCOL_MINOR, 2u);
    ksi_device_write(header + 8u, opcode, 2u);
    ksi_device_write(header + 10u, KSI_FRAME_FLAG_RESPONSE, 2u);
    ksi_device_write(header + 12u, payload_length, 4u);
    ksi_device_write(header + 16u, 1u, 4u);
    transfer(descriptor, header, sizeof(header), true);
    transfer(descriptor, payload, payload_length, true);
}

static ksi_status call_authorize(ksi_connection *connection, ksi_error *error)
{
    ksi_permission_scopes granted = 0u;
    return ksi_authorize(connection, KSI_AUTH_REQUEST,
                         KSI_SCOPE_INPUT_CONTROL, &granted, error);
}

static ksi_status call_ping(ksi_connection *connection, ksi_error *error)
{
    return ksi_ping(connection, error);
}

static ksi_status call_hook_reply(ksi_connection *connection, ksi_error *error)
{
    ksi_hook_event event;
    ksi_hook_reply reply;

    ksi_hook_event_init(&event);
    ksi_hook_reply_init(&reply);
    event.request_id = HOOK_REQUEST_ID;
    ksi_client_test_set_outstanding_hook_request(connection, HOOK_REQUEST_ID);
    return ksi_hook_reply_event(connection, &event, &reply, error);
}

static ksi_status call_block_input(ksi_connection *connection, ksi_error *error)
{
    uint32_t effective = 0u;
    return ksi_set_block_input(connection, 3u, &effective, error);
}

#define OUTPUT_CALL(name, type, init, invoke) \
    static ksi_status call_##name(ksi_connection *connection, \
                                  ksi_error *error) \
    { \
        type value; \
        init(&value); \
        return invoke(connection, &value, error); \
    }

OUTPUT_CALL(pointer_position, ksi_pointer_position,
            ksi_pointer_position_init, ksi_get_pointer_position)
OUTPUT_CALL(key_state, ksi_key_state, ksi_key_state_init, ksi_get_key_state)
OUTPUT_CALL(pointer_buttons, ksi_pointer_buttons,
            ksi_pointer_buttons_init, ksi_get_pointer_buttons)
OUTPUT_CALL(idle_time, ksi_idle_time, ksi_idle_time_init, ksi_get_idle_time)
OUTPUT_CALL(modifier_state, ksi_modifier_state,
            ksi_modifier_state_init, ksi_get_modifier_state)

#undef OUTPUT_CALL

static ksi_status call_device_key_state(ksi_connection *connection, ksi_error *error)
{
    ksi_key_state state;
    ksi_key_state_init(&state);
    return ksi_get_device_key_state(connection, 19u, &state, error);
}

typedef struct round_trip_case {
    uint16_t opcode;
    uint16_t flags;
    uint64_t request_id;
    client_call call;
    const uint8_t *payload;
    uint32_t payload_length;
    uint32_t response_length;
} round_trip_case;

static const uint8_t authorize_payload[KSI_AUTHORIZE_PAYLOAD_SIZE] = {
    LE32(KSI_AUTH_REQUEST), LE32(KSI_SCOPE_INPUT_CONTROL),
};
static const uint8_t block_payload[KSI_BLOCK_INPUT_PAYLOAD_SIZE] = {
    LE32(3u), LE32(0u),
};
static const uint8_t hook_reply_payload[KSI_HOOK_DECISION_PREFIX_SIZE] = { 0 };
static const uint8_t device_state_payload[] = { LE32(19u) };

static const round_trip_case cases[] = {
    { KSI_OPCODE_AUTHORIZE, 0u, 1u, call_authorize, authorize_payload,
      sizeof(authorize_payload), KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE },
    { KSI_OPCODE_PING, 0u, 1u, call_ping, NULL, 0u,
      KSI_STATUS_PAYLOAD_SIZE },
    { KSI_OPCODE_HOOK_EVENT, KSI_FRAME_FLAG_RESPONSE, HOOK_REQUEST_ID,
      call_hook_reply, hook_reply_payload, sizeof(hook_reply_payload), 0u },
    { KSI_OPCODE_SET_BLOCK_INPUT, 0u, 1u, call_block_input, block_payload,
      sizeof(block_payload), KSI_BLOCK_INPUT_RESULT_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_POINTER_POSITION, 0u, 1u, call_pointer_position,
      NULL, 0u, KSI_STATUS_PAYLOAD_SIZE + KSI_POINTER_POSITION_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_KEY_STATE, 0u, 1u, call_key_state, NULL, 0u,
      KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_KEY_STATE, 0u, 1u, call_device_key_state, device_state_payload, sizeof(device_state_payload),
      KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_POINTER_BUTTONS, 0u, 1u, call_pointer_buttons,
      NULL, 0u, KSI_STATUS_PAYLOAD_SIZE + KSI_POINTER_BUTTONS_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_IDLE_TIME, 0u, 1u, call_idle_time, NULL, 0u,
      KSI_STATUS_PAYLOAD_SIZE + KSI_IDLE_TIME_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_MODIFIER_STATE, 0u, 1u, call_modifier_state,
      NULL, 0u, KSI_STATUS_PAYLOAD_SIZE + KSI_MODIFIER_STATE_PAYLOAD_SIZE },
};

_Static_assert(sizeof(cases) / sizeof(cases[0]) == 10u,
               "every previously untested request API needs a round trip");

static void check_case(const round_trip_case *test)
{
    int sockets[2];
    uint8_t header[KSI_FRAME_HEADER_SIZE];
    uint8_t payload[KSI_HOOK_DECISION_PREFIX_SIZE];
    ksi_error error;

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    ksi_connection *connection = ksi_client_test_adopt_descriptor(sockets[0]);
    assert(connection != NULL);
    if (test->response_length != 0u)
        write_success(sockets[1], test->opcode, test->response_length);

    ksi_error_init(&error);
    assert(test->call(connection, &error) == KSI_STATUS_OK);
    transfer(sockets[1], header, sizeof(header), false);
    assert(memcmp(header, KSI_FRAME_MAGIC, 4u) == 0
           && ksi_device_read(header + 4u, 2u) == KSI_PROTOCOL_MAJOR
           && ksi_device_read(header + 6u, 2u) == KSI_PROTOCOL_MINOR
           && ksi_device_read(header + 8u, 2u) == test->opcode
           && ksi_device_read(header + 10u, 2u) == test->flags
           && ksi_device_read(header + 12u, 4u) == test->payload_length
           && ksi_device_read(header + 16u, 4u) == test->request_id
           && ksi_device_read(header + 20u, 4u) == 0u);
    if (test->payload_length != 0u) {
        assert(test->payload_length <= sizeof(payload));
        transfer(sockets[1], payload, test->payload_length, false);
        assert(memcmp(payload, test->payload, test->payload_length) == 0);
    }
    ksi_disconnect(connection);
    assert(close(sockets[1]) == 0);
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    for (size_t i = 0u; i < 8u; i++) bytes[i] = (uint8_t)(value >> (8u * i));
}

static void write_event_header(uint8_t *header, uint16_t opcode, uint32_t size)
{
    memset(header, 0, KSI_FRAME_HEADER_SIZE);
    memcpy(header, KSI_FRAME_MAGIC, 4u);
    ksi_device_write(header + 4u, KSI_PROTOCOL_MAJOR, 2u);
    ksi_device_write(header + 8u, opcode, 2u);
    ksi_device_write(header + 10u, KSI_FRAME_FLAG_EVENT, 2u);
    ksi_device_write(header + 12u, size, 4u);
}

static void check_pollable_drain(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    ksi_connection *connection = ksi_client_test_adopt_descriptor(sockets[0]);
    assert(connection != NULL);
    ksi_error error; ksi_error_init(&error);
    ksi_lease_message message; ksi_lease_message_init(&message);
    struct pollfd descriptor = { .fd = ksi_connection_fd(connection), .events = POLLIN };
    assert(descriptor.fd >= 0 && poll(&descriptor, 1u, 0) == 0);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_TIMEOUT);
    uint8_t header[KSI_FRAME_HEADER_SIZE], payload[8u] = { 0 };
    write_event_header(header, KSI_OPCODE_SESSION_GRANTED, sizeof(payload));
    ksi_device_write(payload, KSI_SCOPE_INPUT_CONTROL, 4u);
    transfer(sockets[1], header, 7u, true);
    assert(poll(&descriptor, 1u, 0) == 1);
    assert(ksi_lease_next(connection, 1u, &message, &error) == KSI_STATUS_TIMEOUT);
    assert(poll(&descriptor, 1u, 0) == 0);
    transfer(sockets[1], header + 7u, sizeof(header) - 7u, true);
    transfer(sockets[1], payload, 3u, true);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_TIMEOUT);
    transfer(sockets[1], payload + 3u, sizeof(payload) - 3u, true);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(message.kind == KSI_LEASE_GRANTED && message.granted_scopes == KSI_SCOPE_INPUT_CONTROL);
    assert(poll(&descriptor, 1u, 0) == 0);
    // A synchronous reply can consume events whose kernel bytes no longer exist.
    transfer(sockets[1], header, sizeof(header), true);
    transfer(sockets[1], payload, sizeof(payload), true);
    write_success(sockets[1], KSI_OPCODE_PING, KSI_STATUS_PAYLOAD_SIZE);
    assert(ksi_ping(connection, &error) == KSI_STATUS_OK);
    assert(poll(&descriptor, 1u, 0) == 1);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(poll(&descriptor, 1u, 0) == 0);
    ksi_client_test_set_role(connection, KSI_ROLE_AUTHORIZATION_LEASE);
    uint8_t state_payload[KSI_KEY_STATE_EVENT_PAYLOAD_SIZE] = { 0 };
    ksi_device_write(state_payload, KSI_LEASE_KEYBOARD_SNAPSHOT, 4u);
    ksi_device_write(state_payload + 4u, 0x20u, 4u);
    write_u64(state_payload + 8u, 17u);
    ksi_device_write(state_payload + 16u, 0x10u, 4u);
    state_payload[20u] = 1u;
    state_payload[24u + 5u] = 4u;
    write_event_header(header, KSI_OPCODE_KEY_STATE_EVENT, sizeof(state_payload));
    transfer(sockets[1], header, sizeof(header), true);
    transfer(sockets[1], state_payload, sizeof(state_payload), true);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(message.kind == KSI_LEASE_KEYBOARD_SNAPSHOT && message.sequence == 17u);
    assert(message.physical_modifiers_lr == 0x20u && message.state.modifiers_lr == 0x10u);
    assert(message.state.caps_lock == 1u && message.state.logical_keys[5u] == 4u);
    ksi_device_write(state_payload, KSI_LEASE_KEYBOARD_DELTA, 4u);
    write_u64(state_payload + 8u, 19u);
    transfer(sockets[1], header, sizeof(header), true);
    transfer(sockets[1], state_payload, sizeof(state_payload), true);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK && message.sequence == 19u);
    ksi_device_write(state_payload, KSI_LEASE_KEYBOARD_SNAPSHOT, 4u);
    transfer(sockets[1], header, sizeof(header), true);
    transfer(sockets[1], state_payload, sizeof(state_payload), true);
    uint8_t response_header[KSI_FRAME_HEADER_SIZE];
    write_event_header(response_header, KSI_OPCODE_KEY_STATE_SUBSCRIBE, KSI_STATUS_PAYLOAD_SIZE);
    ksi_device_write(response_header + 10u, KSI_FRAME_FLAG_RESPONSE, 2u);
    write_u64(response_header + 16u, 2u);
    uint8_t status_payload[KSI_STATUS_PAYLOAD_SIZE] = { 0 };
    transfer(sockets[1], response_header, sizeof(response_header), true);
    transfer(sockets[1], status_payload, sizeof(status_payload), true);
    assert(ksi_key_state_subscribe(connection, &error) == KSI_STATUS_OK);
    assert(poll(&descriptor, 1u, 0) == 1);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(message.kind == KSI_LEASE_KEYBOARD_SNAPSHOT && message.sequence == 19u);
    for (uint64_t sequence = 20u; sequence <= 51u; sequence++) {
        ksi_device_write(state_payload, KSI_LEASE_KEYBOARD_DELTA, 4u);
        write_u64(state_payload + 8u, sequence);
        transfer(sockets[1], header, sizeof(header), true);
        transfer(sockets[1], state_payload, sizeof(state_payload), true);
    }
    write_event_header(response_header, KSI_OPCODE_AUTHORIZE, KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE);
    ksi_device_write(response_header + 10u, KSI_FRAME_FLAG_RESPONSE, 2u);
    write_u64(response_header + 16u, 3u);
    uint8_t authorize_result[KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE] = { 0 };
    ksi_device_write(authorize_result + 8u, KSI_SCOPE_INPUT_MONITORING, 4u);
    transfer(sockets[1], response_header, sizeof(response_header), true);
    transfer(sockets[1], authorize_result, sizeof(authorize_result), true);
    ksi_permission_scopes granted;
    assert(ksi_authorize(connection, KSI_AUTH_CHECK, KSI_SCOPE_INPUT_MONITORING, &granted, &error) == KSI_STATUS_OK);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(message.kind == KSI_LEASE_KEYBOARD_SNAPSHOT && message.sequence == 51u);
    assert(poll(&descriptor, 1u, 0) == 0);
    // Drain pending data before reporting the peer's shutdown.
    write_event_header(header, KSI_OPCODE_SESSION_GRANTED, sizeof(payload));
    transfer(sockets[1], header, sizeof(header), true);
    transfer(sockets[1], payload, sizeof(payload), true);
    close(sockets[1]);
    assert(poll(&descriptor, 1u, 0) == 1);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
    assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_UNAVAILABLE);
    assert(ksi_ping(connection, &error) == KSI_STATUS_UNAVAILABLE);
    ksi_disconnect(connection);
}

static uint64_t test_milliseconds(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void *write_state_burst(void *context)
{
    int fd = *(int *)context;
    uint8_t header[KSI_FRAME_HEADER_SIZE], state[KSI_KEY_STATE_EVENT_PAYLOAD_SIZE] = { 0 };
    write_event_header(header, KSI_OPCODE_KEY_STATE_EVENT, sizeof(state));
    ksi_device_write(state, KSI_LEASE_KEYBOARD_DELTA, 4u);
    for (uint64_t sequence = 1u; sequence <= 10u; sequence++) {
        write_u64(state + 8u, sequence);
        if (send(fd, header, sizeof(header), MSG_NOSIGNAL) != (ssize_t)sizeof(header)
            || send(fd, state, sizeof(state), MSG_NOSIGNAL) != (ssize_t)sizeof(state)) break;
        /* The fixture publishes often enough to keep resetting a relative timeout. */
        struct timespec interval = { .tv_nsec = 30000000L };
        while (nanosleep(&interval, &interval) != 0) assert(errno == EINTR);
    }
    return NULL;
}

static void check_response_deadline(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    ksi_connection *connection = ksi_client_test_adopt_descriptor(sockets[0]);
    assert(connection != NULL);
    ksi_client_test_set_timeout(connection, 80u);
    pthread_t producer;
    assert(pthread_create(&producer, NULL, write_state_burst, &sockets[1]) == 0);
    ksi_error error; ksi_error_init(&error);
    uint64_t before = test_milliseconds();
    assert(ksi_ping(connection, &error) == KSI_STATUS_TIMEOUT);
    assert(test_milliseconds() - before < 250u);
    assert(pthread_join(producer, NULL) == 0);
    ksi_lease_message message; ksi_lease_message_init(&message);
    ksi_status status;
    while ((status = ksi_lease_next(connection, 0u, &message, &error)) == KSI_STATUS_OK) {}
    assert(status == KSI_STATUS_UNAVAILABLE);
    struct pollfd ready = { .fd = ksi_connection_fd(connection), .events = POLLIN };
    assert(poll(&ready, 1u, 0) == 1);
    assert(ksi_ping(connection, &error) == KSI_STATUS_UNAVAILABLE);
    ksi_disconnect(connection); close(sockets[1]);
}

static void check_terminal_readiness(void)
{
    for (unsigned malformed = 0u; malformed < 2u; malformed++) {
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        ksi_connection *connection = ksi_client_test_adopt_descriptor(sockets[0]);
        assert(connection != NULL);
        uint8_t header[KSI_FRAME_HEADER_SIZE], grant[8u] = { 0 };
        write_event_header(header, KSI_OPCODE_SESSION_GRANTED, sizeof(grant));
        ksi_device_write(grant, KSI_SCOPE_INPUT_CONTROL, 4u);
        transfer(sockets[1], header, sizeof(header), true);
        transfer(sockets[1], grant, sizeof(grant), true);
        write_event_header(header, KSI_OPCODE_SESSION_GRANTED, sizeof(grant));
        if (malformed == 0u) header[4u] = KSI_PROTOCOL_MAJOR - 1u;
        else ksi_device_write(header + 10u, 0xffffu, 2u);
        transfer(sockets[1], header, sizeof(header), true);
        ksi_error error; ksi_error_init(&error);
        ksi_status expected = malformed == 0u ? KSI_STATUS_UNSUPPORTED : KSI_STATUS_INTERNAL;
        assert(ksi_ping(connection, &error) == expected);
        ksi_lease_message message; ksi_lease_message_init(&message);
        assert(ksi_lease_next(connection, 0u, &message, &error) == KSI_STATUS_OK);
        struct pollfd ready = { .fd = ksi_connection_fd(connection), .events = POLLIN };
        assert(poll(&ready, 1u, 0) == 1);
        assert(ksi_lease_next(connection, 0u, &message, &error) == expected);
        assert(poll(&ready, 1u, 0) == 1);
        ksi_disconnect(connection); close(sockets[1]);
    }
    for (unsigned malformed = 0u; malformed < 2u; malformed++) {
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        ksi_connection *connection = ksi_client_test_adopt_descriptor(sockets[0]);
        assert(connection != NULL);
        uint8_t header[KSI_FRAME_HEADER_SIZE], payload[KSI_BLOCK_INPUT_RESULT_PAYLOAD_SIZE] = { 0 };
        uint32_t size = malformed == 0u ? KSI_STATUS_PAYLOAD_SIZE + 4u : sizeof(payload);
        write_event_header(header, malformed == 0u ? KSI_OPCODE_PING : KSI_OPCODE_SET_BLOCK_INPUT, size);
        ksi_device_write(header + 10u, KSI_FRAME_FLAG_RESPONSE, 2u);
        write_u64(header + 16u, 1u);
        if (malformed != 0u) payload[12u] = 1u;
        transfer(sockets[1], header, sizeof(header), true);
        transfer(sockets[1], payload, size, true);
        ksi_error error; ksi_error_init(&error);
        assert((malformed == 0u ? call_ping(connection, &error) : call_block_input(connection, &error)) == KSI_STATUS_INTERNAL);
        struct pollfd ready = { .fd = ksi_connection_fd(connection), .events = POLLIN };
        assert(poll(&ready, 1u, 0) == 1);
        ksi_disconnect(connection); close(sockets[1]);
    }
}

int main(void)
{
    alarm(5u);
    check_response_deadline();
    check_terminal_readiness();
    check_pollable_drain();
    for (size_t index = 0u; index < sizeof(cases) / sizeof(cases[0]); index++)
        check_case(&cases[index]);
    return 0;
}

#undef HOOK_REQUEST_ID
#undef LE32
