#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool g_verbose = false;

/* White-box coverage for the daemon's private admission and operation gates. */
#include "../src/daemon.c"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

static bool dispatch_request(
    ksi_daemon_state *state,
    ksi_client *client,
    uint16_t opcode,
    uint64_t request_id,
    const uint8_t *payload,
    size_t payload_size)
{
    ksi_message_header header = {
        .major = KSI_PROTOCOL_MAJOR,
        .minor = KSI_PROTOCOL_MINOR,
        .opcode = opcode,
        .flags = 0u,
        .payload_length = (uint32_t)payload_size,
        .request_id = request_id,
    };

    if (client->rx_buffer == NULL || client->rx_used != 0u
        || payload_size > KSI_MAX_PAYLOAD_SIZE) {
        return false;
    }
    ksi_frame_header_encode(client->rx_buffer, &header);
    if (payload_size != 0u) {
        memcpy(client->rx_buffer + KSI_FRAME_HEADER_SIZE,
            payload, payload_size);
    }
    client->rx_used = KSI_FRAME_HEADER_SIZE + payload_size;
    return process_client_buffer_direct(state, client)
        && client->rx_used == 0u;
}

static bool read_status_response(
    int fd,
    uint16_t expected_opcode,
    uint64_t expected_request_id,
    size_t expected_payload_size,
    uint32_t expected_status,
    uint32_t expected_detail,
    uint8_t *response_payload)
{
    uint8_t response[KSI_FRAME_HEADER_SIZE + KSI_HELLO_RESULT_PAYLOAD_SIZE];
    ksi_message_header header;
    ksi_status_payload status;
    size_t response_size = 0u;
    struct pollfd wait = { .fd = fd, .events = POLLIN };

    CHECK(poll(&wait, 1u, 1000) == 1);
    CHECK(ksi_ipc_read_framed_message(
        fd, response, sizeof(response), &response_size) == 1);
    CHECK(response_size == KSI_FRAME_HEADER_SIZE + expected_payload_size);
    CHECK(ksi_frame_header_decode(response, &header));
    CHECK(header.major == KSI_PROTOCOL_MAJOR);
    CHECK(header.minor == KSI_PROTOCOL_MINOR);
    CHECK(header.opcode == expected_opcode);
    CHECK(header.flags == KSI_FRAME_FLAG_RESPONSE);
    CHECK(header.request_id == expected_request_id);
    CHECK(header.payload_length == expected_payload_size);
    ksi_status_decode(response + KSI_FRAME_HEADER_SIZE, &status);
    CHECK(status.status == expected_status);
    CHECK(status.detail == expected_detail);
    if (response_payload != NULL) {
        memcpy(response_payload, response + KSI_FRAME_HEADER_SIZE,
            expected_payload_size);
    }
    return true;
}

static bool test_daemon_admission_and_operation_gates(void)
{
    ksi_daemon_state state = {
        .available_operations = KSI_OPERATION_ALL,
    };
    ksi_client client = {
        .fd = -1,
        .state = KSI_CLIENT_STATE_READY,
        .uid = getuid(),
    };
    uint8_t *rx_buffer = calloc(1u, KSI_MAX_MESSAGE_SIZE);
    uint8_t hello[KSI_HELLO_PAYLOAD_SIZE] = { 0 };
    uint8_t authorize[KSI_AUTHORIZE_PAYLOAD_SIZE] = { 0 };
    uint8_t hook[KSI_HOOK_SUBSCRIPTION_PAYLOAD_SIZE] = { 0 };
    uint8_t block[KSI_BLOCK_INPUT_PAYLOAD_SIZE] = { 0 };
    uint8_t synthesize[KSI_SYNTHESIZE_PREFIX_SIZE + KSI_INPUT_WIRE_SIZE] = { 0 };
    uint8_t hello_result[KSI_HELLO_RESULT_PAYLOAD_SIZE];
    int sockets[2];

    CHECK(rx_buffer != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    client.fd = sockets[0];
    client.rx_buffer = rx_buffer;
    client.hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(client.hook_send_ref != NULL);

    ksi_wire_write_u16(hello, KSI_ROLE_RPC);
    ksi_wire_write_u16(hello + 2u, KSI_AUTH_CHECK);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_HELLO, 1u,
        hello, sizeof(hello)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_HELLO, 1u,
        KSI_HELLO_RESULT_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE,
        hello_result));
    CHECK(client.hello_complete);
    CHECK(client.connection_role == KSI_ROLE_RPC);
    CHECK(ksi_wire_read_u32(hello_result + 8u) == 0u);
    CHECK(ksi_wire_read_u64(hello_result + 16u) == KSI_OPERATION_ALL);

    client.identity_attempted = true;
    client.has_identity = true;
    ksi_wire_write_u16(authorize, KSI_AUTH_CHECK);
    ksi_wire_write_u32(authorize + 4u, KSI_SCOPE_INPUT_MONITORING);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_AUTHORIZE, 2u,
        authorize, sizeof(authorize)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_AUTHORIZE, 2u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_DENIED, KSI_DETAIL_NONE, NULL));
    CHECK(!client.pending_authorization);
    CHECK(client.state == KSI_CLIENT_STATE_READY);

    ksi_wire_write_u32(hook, KSI_HOOK_KEYBOARD);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SUBSCRIBE_HOOK, 3u,
        hook, sizeof(hook)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SUBSCRIBE_HOOK, 3u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_DENIED,
        KSI_DETAIL_WRONG_ROLE, NULL));

    ksi_wire_write_u32(block, KSI_BLOCK_KEYBOARD);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SET_BLOCK_INPUT, 4u,
        block, sizeof(block)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SET_BLOCK_INPUT, 4u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_DENIED, KSI_DETAIL_NONE, NULL));

    client.granted_scopes = KSI_SCOPE_INPUT_CONTROL;
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SET_BLOCK_INPUT, 5u,
        block, sizeof(block)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SET_BLOCK_INPUT, 5u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE,
        NULL));

    /* Synthesis ready but the absolute-pointer device missing. A relative
     * batch clears the operation gate (and then fails on the uninitialized
     * output queue); an absolute MouseMove is refused up front instead of being
     * accepted and dropped inside the backend; granting the internal bit lets
     * the same absolute batch through the gate again. */
    state.ready_operations = KSI_OPERATION_SYNTHESIZE_KEYBOARD
        | KSI_OPERATION_SYNTHESIZE_MOUSE;
    ksi_wire_write_u32(synthesize, 1u);
    ksi_wire_write_u32(synthesize + 4u, (uint32_t)KSI_SYNTH_BYPASS_HOOK);
    ksi_wire_write_u32(synthesize + KSI_SYNTHESIZE_PREFIX_SIZE,
        (uint32_t)KSI_INPUT_MOUSE);
    ksi_wire_write_u32(synthesize + KSI_SYNTHESIZE_PREFIX_SIZE + 20u,
        (uint32_t)KSI_MOUSE_MOVE);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SYNTHESIZE_INPUT, 6u,
        synthesize, sizeof(synthesize)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SYNTHESIZE_INPUT, 6u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_RESOURCE_EXHAUSTED,
        KSI_DETAIL_NONE, NULL));

    ksi_wire_write_u32(synthesize + KSI_SYNTHESIZE_PREFIX_SIZE + 20u,
        (uint32_t)KSI_MOUSE_MOVE | (uint32_t)KSI_MOUSE_ABSOLUTE);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SYNTHESIZE_INPUT, 7u,
        synthesize, sizeof(synthesize)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SYNTHESIZE_INPUT, 7u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE,
        NULL));

    state.ready_operations |= KSI_INTERNAL_OPERATION_SYNTHESIZE_MOUSE_ABSOLUTE;
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_SYNTHESIZE_INPUT, 8u,
        synthesize, sizeof(synthesize)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SYNTHESIZE_INPUT, 8u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_RESOURCE_EXHAUSTED,
        KSI_DETAIL_NONE, NULL));

    hook_send_ref_invalidate(client.hook_send_ref);
    hook_send_ref_release(client.hook_send_ref);
    close(sockets[1]);
    free(rx_buffer);
    return true;
}

int main(void)
{
    if (!test_daemon_admission_and_operation_gates()) {
        return 1;
    }
    puts("PASS daemon admission and operation gates");
    return 0;
}
