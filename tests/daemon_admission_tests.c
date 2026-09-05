#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include "keysharp_permissions/permissions.h"

static int delayed_permission_check(const ksp_store *store, uid_t uid,
    const char *hash, uint32_t scopes, uint32_t *allowed, uint64_t *generation);

bool g_verbose = false;

/* White-box coverage for the daemon's private admission and operation gates. */
#define ksp_store_check_at_generation delayed_permission_check
#include "../src/daemon.c"
#undef ksp_store_check_at_generation

static atomic_bool delay_permission_io;
static pthread_mutex_t permission_barrier = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t permission_condition = PTHREAD_COND_INITIALIZER;
static bool permission_worker_entered;
static bool release_permission_worker;

static int delayed_permission_check(const ksp_store *store, uid_t uid,
    const char *hash, uint32_t scopes, uint32_t *allowed, uint64_t *generation)
{
    if (!atomic_load(&delay_permission_io))
        return ksp_store_check_at_generation(store, uid, hash, scopes, allowed, generation);
    pthread_mutex_lock(&permission_barrier);
    permission_worker_entered = true;
    pthread_cond_broadcast(&permission_condition);
    while (!release_permission_worker) pthread_cond_wait(&permission_condition, &permission_barrier);
    pthread_mutex_unlock(&permission_barrier);
    *allowed = KSI_SCOPE_INPUT_MONITORING;
    *generation = 3u;
    return 0;
}

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

static bool test_observer_admission_and_backpressure(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    int sockets[2];
    uint8_t subscription[KSI_HOOK_SUBSCRIPTION_PAYLOAD_SIZE] = { 0 };
    CHECK(state != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    state->client_count = 1u;
    ksi_client *client = &state->clients[0];
    client->fd = sockets[0];
    client->hook_send_ref = hook_send_ref_create(sockets[0]);
    client->rx_buffer = calloc(1u, KSI_MAX_MESSAGE_SIZE);
    client->hello_complete = true;
    client->connection_role = KSI_ROLE_OBSERVER_STREAM;
    client->connection_id = 1u;
    client->granted_scopes = KSI_SCOPE_INPUT_MONITORING;
    CHECK(client->hook_send_ref != NULL && client->rx_buffer != NULL);
    ksi_wire_write_u32(subscription, KSI_HOOK_KEYBOARD);
    CHECK(dispatch_request(state, client, KSI_OPCODE_SUBSCRIBE_HOOK, 1u,
        subscription, sizeof(subscription)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_SUBSCRIBE_HOOK, 1u,
        KSI_HOOK_SUBSCRIPTION_RESULT_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));
    CHECK(client->observer_subscriptions == KSI_OPERATION_HOOK_KEYBOARD);
    CHECK(client->hook_subscriptions == 0u && !state->interception_active);
    ksi_keyboard_hook_event event = { .message = KSI_MESSAGE_KEY_DOWN, .vk_code = 'A' };
    for (size_t i = 0u; i < KSI_OBSERVER_QUEUE_CAPACITY + 3u; i++)
        daemon_observe_input(state, KSI_HOOK_KEYBOARD, &event, sizeof(event));
    CHECK(client->observer_count == KSI_OBSERVER_QUEUE_CAPACITY && client->observer_dropped == 3u);
    CHECK(client->hook_subscriptions == 0u);
    client->observer_head = 1u;
    client->observer_count--;
    daemon_observe_input(state, KSI_HOOK_KEYBOARD, &event, sizeof(event));
    CHECK(ksi_wire_read_u32(client->observer_queue[0].payload) == KSI_OBSERVER_OVERFLOW);
    CHECK(ksi_wire_read_u64(client->observer_queue[0].payload + 16u) == 3u);
    CHECK(client->observer_dropped == 1u);

    ksi_prompt_task task = { .state = state, .send_ref = client->hook_send_ref,
        .input_generation = 1u, .identity.uid = getuid(), .deadline_ms = UINT64_MAX };
    atomic_store(&state->active_input_generation, 1u);
    CHECK(!prompt_cancelled(&task));
    atomic_store(&state->active_input_generation, 2u);
    CHECK(prompt_cancelled(&task));
    client->pending_authorization = true;
    client->pending_authorization_opcode = KSI_OPCODE_AUTHORIZE;
    client->pending_request_id = 19u;
    client->pending_requested_scopes = KSI_SCOPE_INPUT_CONTROL;
    ksi_daemon_command completed_prompt = {
        .type = KSI_DAEMON_COMMAND_CLIENT_PROMPT_DONE,
        .client_fd = client->fd, .connection_id = client->connection_id,
        .data.prompt_done = { .decision = KSP_POLKIT_GRANTED,
            .allowed_scopes = KSI_SCOPE_INPUT_CONTROL, .input_generation = 1u },
    };
    process_client_prompt_done(state, &completed_prompt);
    CHECK(read_status_response(sockets[1], KSI_OPCODE_AUTHORIZE, 19u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_DENIED, KSI_DETAIL_NONE, NULL));
    CHECK(client->granted_scopes == KSI_SCOPE_INPUT_MONITORING && !client->pending_authorization);
    task.input_generation = 2u;
    hook_send_ref_invalidate(client->hook_send_ref);
    CHECK(prompt_cancelled(&task));
    hook_send_ref_release(client->hook_send_ref);
    free(client->rx_buffer);
    free(client->observer_queue);
    ksi_linux_devices_set_observer_callback(NULL, NULL, NULL);
    ksi_linux_devices_set_raw_observer_callback(NULL, NULL);
    close(sockets[1]);
    free(state);
    return true;
}

static bool test_nonblocking_observer_transport(void)
{
    int sockets[2];
    int capacity = 1024;
    uint8_t payload[1024] = { 0 };
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0);
    ksi_hook_send_ref *ref = hook_send_ref_create(sockets[0]);
    CHECK(ref != NULL);
    int result = 1;
    for (size_t i = 0; i < 1024u && result == 1; i++)
        result = hook_send_ref_try_send(ref, KSI_OPCODE_OBSERVER_EVENT,
            KSI_FRAME_FLAG_EVENT, 0u, payload, sizeof(payload));
    CHECK(result == 0 || result == -1);
    hook_send_ref_invalidate(ref);
    hook_send_ref_release(ref);
    close(sockets[1]);
    return true;
}

static bool test_permission_fence_preserves_key_release(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    atomic_store(&state->active_input_generation, 1u);
    const ksi_hook_event_payload up = { .hook_type = KSI_HOOK_KEYBOARD,
        .event.keyboard = { .message = KSI_MESSAGE_KEY_UP, .vk_code = 'A' } };
    CHECK(output_queue_push_replay(&state->output_queue, KSI_HOOK_KEYBOARD, &up, 1u));
    CHECK(fence_permission_output(state));
    CHECK(current_input_generation(state) == 2u);
    ksi_output_action action;
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_RELEASE_ALL && action.input_generation == 0u);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_permission_io_does_not_block_input_admission(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    ksi_daemon_command_queue commands;
    int rpc[2], observer[2];
    CHECK(state != NULL && command_queue_init(&commands) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, rpc) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, observer) == 0);
    CHECK(ksi_worker_pool_init(&g_permission_worker_pool) == 0);
    state->commands = &commands;
    state->permissions = (ksp_store *)&commands;
    state->client_count = 2u;
    for (size_t i = 0u; i < 2u; i++) {
        ksi_client *client = &state->clients[i];
        client->fd = i == 0u ? rpc[0] : observer[0];
        client->uid = getuid();
        client->connection_id = i + 1u;
        client->hook_send_ref = hook_send_ref_create(client->fd);
        client->rx_buffer = calloc(1u, KSI_MAX_MESSAGE_SIZE);
        client->hello_complete = true;
        client->state = KSI_CLIENT_STATE_READY;
        CHECK(client->hook_send_ref != NULL && client->rx_buffer != NULL);
    }
    ksi_client *requester = &state->clients[0];
    requester->connection_role = KSI_ROLE_RPC;
    requester->identity_attempted = requester->has_identity = true;
    CHECK(ksp_identity_capture(getpid(), getuid(), &requester->identity) == 0);
    requester->pid = requester->identity.pid;
    requester->start_time = requester->identity.start_time;
    requester->identity_checked_ms = monotonic_ms();
    (void)snprintf(requester->exe_hash, sizeof(requester->exe_hash), "%s", requester->identity.hash);
    ksi_client *reader = &state->clients[1];
    reader->connection_role = KSI_ROLE_OBSERVER_STREAM;
    reader->granted_scopes = KSI_SCOPE_INPUT_MONITORING;
    reader->observer_subscriptions = KSI_OPERATION_HOOK_KEYBOARD;
    reader->observer_queue = calloc(KSI_OBSERVER_QUEUE_CAPACITY, sizeof(ksi_observer_frame));
    CHECK(reader->observer_queue != NULL);

    atomic_store(&delay_permission_io, true);
    permission_worker_entered = release_permission_worker = false;
    uint8_t authorize[KSI_AUTHORIZE_PAYLOAD_SIZE] = {0};
    ksi_wire_write_u32(authorize + 4u, KSI_SCOPE_INPUT_MONITORING);
    CHECK(dispatch_request(state, requester, KSI_OPCODE_AUTHORIZE, 8u, authorize, sizeof(authorize)));
    CHECK(requester->pending_authorization && requester->permission_task != NULL);
    struct timespec until;
    CHECK(clock_gettime(CLOCK_REALTIME, &until) == 0);
    until.tv_sec++;
    pthread_mutex_lock(&permission_barrier);
    while (!permission_worker_entered) {
        if (pthread_cond_timedwait(&permission_condition, &permission_barrier, &until) != 0) break;
    }
    bool entered = permission_worker_entered;
    pthread_mutex_unlock(&permission_barrier);
    CHECK(entered);

    /* The real input callback and another connection's dispatcher keep running
     * while the store operation is held behind an explicit worker barrier. */
    ksi_keyboard_hook_event event = { .message = KSI_MESSAGE_KEY_DOWN, .vk_code = 'A' };
    daemon_observe_input(state, KSI_HOOK_KEYBOARD, &event, sizeof(event));
    CHECK(reader->observer_count == 1u);
    CHECK(dispatch_request(state, reader, KSI_OPCODE_PING, 9u, NULL, 0u));
    CHECK(read_status_response(observer[1], KSI_OPCODE_PING, 9u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));
    CHECK(requester->pending_authorization && requester->granted_scopes == 0u);

    pthread_mutex_lock(&permission_barrier);
    release_permission_worker = true;
    pthread_cond_broadcast(&permission_condition);
    pthread_mutex_unlock(&permission_barrier);
    struct pollfd completed = { .fd = ksi_pipe_ring_wake_fd(&commands.ring), .events = POLLIN };
    CHECK(poll(&completed, 1u, 1000) == 1);
    process_daemon_commands(state);
    CHECK(read_status_response(rpc[1], KSI_OPCODE_AUTHORIZE, 8u,
        KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));
    CHECK(!requester->pending_authorization && requester->permission_task == NULL);
    CHECK(requester->granted_scopes == KSI_SCOPE_INPUT_MONITORING);
    ksi_worker_pool_request_stop(&g_permission_worker_pool);
    CHECK(ksi_worker_pool_join_before(&g_permission_worker_pool, monotonic_ms() + 1000u));
    ksi_worker_pool_destroy(&g_permission_worker_pool);
    atomic_store(&delay_permission_io, false);
    while (state->client_count != 0u) remove_client(state, state->client_count - 1u);
    close(rpc[1]); close(observer[1]);
    command_queue_destroy(&commands);
    free(state);
    return true;
}

int main(void)
{
    if (!test_daemon_admission_and_operation_gates()
        || !test_observer_admission_and_backpressure()
        || !test_nonblocking_observer_transport()
        || !test_permission_fence_preserves_key_release()
        || !test_permission_io_does_not_block_input_admission()) {
        return 1;
    }
    puts("PASS daemon admission and operation gates");
    return 0;
}
