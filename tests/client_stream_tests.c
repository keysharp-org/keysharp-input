#include "keysharp_input/client.h"
#include "device_codec.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LE32(value) \
    (uint8_t)((uint32_t)(value)), \
    (uint8_t)((uint32_t)(value) >> 8u), \
    (uint8_t)((uint32_t)(value) >> 16u), \
    (uint8_t)((uint32_t)(value) >> 24u)

#define HOOK_REQUEST_ID UINT64_C(17)

ksi_connection *ksi_client_test_adopt_descriptor(int descriptor);
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
    { KSI_OPCODE_GET_POINTER_BUTTONS, 0u, 1u, call_pointer_buttons,
      NULL, 0u, KSI_STATUS_PAYLOAD_SIZE + KSI_POINTER_BUTTONS_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_IDLE_TIME, 0u, 1u, call_idle_time, NULL, 0u,
      KSI_STATUS_PAYLOAD_SIZE + KSI_IDLE_TIME_PAYLOAD_SIZE },
    { KSI_OPCODE_GET_MODIFIER_STATE, 0u, 1u, call_modifier_state,
      NULL, 0u, KSI_STATUS_PAYLOAD_SIZE + KSI_MODIFIER_STATE_PAYLOAD_SIZE },
};

_Static_assert(sizeof(cases) / sizeof(cases[0]) == 9u,
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

int main(void)
{
    for (size_t index = 0u; index < sizeof(cases) / sizeof(cases[0]); index++)
        check_case(&cases[index]);
    return 0;
}

#undef HOOK_REQUEST_ID
#undef LE32
