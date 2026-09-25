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

void recorded_apply_end_grab(uint64_t next, const uint8_t *held);

/* White-box coverage for the daemon's private admission and operation gates. */
#define ksp_store_check_at_generation delayed_permission_check
#define ksi_linux_forward_apply_end_grab recorded_apply_end_grab
#include "../src/daemon.c"
#undef ksp_store_check_at_generation
#undef ksi_linux_forward_apply_end_grab

void ksi_linux_forward_apply_end_grab(uint64_t next, const uint8_t *held);
static uint64_t applied_end_grab;
void recorded_apply_end_grab(uint64_t next, const uint8_t *held)
{
    applied_end_grab = next;
    ksi_linux_forward_apply_end_grab(next, held);
}

#include <libevdev/libevdev.h>

/* Forwarding and synthesis run for real against a pipe standing for the sink;
 * a source here is a plain keyboard, which needs no clone. */
static int fake_keyboard_source(int fd, struct libevdev **out)
{
    struct libevdev *device = libevdev_new();

    (void)fd;
    if (device == NULL) return -ENOMEM;
    libevdev_set_name(device, "Physical Keyboard");
    for (unsigned int code = KEY_ESC; code <= KEY_D; code++)
        (void)libevdev_enable_event_code(device, EV_KEY, code, NULL);
    (void)libevdev_enable_event_code(device, EV_KEY, KEY_LEFTSHIFT, NULL);
    *out = device;
    return 0;
}

#define libevdev_new_from_fd fake_keyboard_source
#include "../src/platform/linux_forward.c"
#undef libevdev_new_from_fd
#include "../src/platform/linux_synth.c"

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
    uint8_t response[KSI_FRAME_HEADER_SIZE + KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE
        + KSI_HELLO_RESULT_PAYLOAD_SIZE];
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

    /* Gamepad discovery and state are ungated. This client holds only Input
     * Control, so the monitoring-gated device list is refused while the gamepad
     * calls answer. No device is tracked in this harness, so the listing is
     * empty and the state read reports the id as unknown. */
    uint8_t device_list[KSI_DEVICE_LIST_REQUEST_SIZE] = { 0 };
    uint8_t gamepad_request[KSI_GAMEPAD_STATE_REQUEST_SIZE] = { 0 };
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_DEVICES_LIST, 9u,
        device_list, sizeof(device_list)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_DEVICES_LIST, 9u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_DENIED, KSI_DETAIL_NONE, NULL));

    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GAMEPADS_LIST, 10u,
        device_list, sizeof(device_list)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GAMEPADS_LIST, 10u,
        KSI_DEVICE_LIST_PREFIX_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));

    ksi_wire_write_u32(gamepad_request, 1u);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_GAMEPAD_STATE, 11u,
        gamepad_request, sizeof(gamepad_request)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_GAMEPAD_STATE, 11u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_NOT_FOUND, KSI_DETAIL_NONE, NULL));

    /* A key-state request selects a device only with a whole device id. */
    uint8_t device_key_state[KSI_KEY_STATE_REQUEST_SIZE + 1u] = { 0 };
    client.granted_scopes |= KSI_SCOPE_INPUT_MONITORING;
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_KEY_STATE, 12u,
        device_key_state, KSI_KEY_STATE_REQUEST_SIZE - 1u));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_KEY_STATE, 12u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_PAYLOAD_SIZE, NULL));
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_KEY_STATE, 13u,
        device_key_state, sizeof(device_key_state)));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_KEY_STATE, 13u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_PAYLOAD_SIZE, NULL));
    ksi_wire_write_u32(device_key_state, 999u);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_KEY_STATE, 14u,
        device_key_state, KSI_KEY_STATE_REQUEST_SIZE));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_KEY_STATE, 14u,
        KSI_STATUS_PAYLOAD_SIZE, KSI_STATUS_NOT_FOUND, KSI_DETAIL_NONE, NULL));
    /* The seat answers even with no device to read. */
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_KEY_STATE, 15u, NULL, 0u));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_KEY_STATE, 15u,
        KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));
    ksi_wire_write_u32(device_key_state, 0u);
    CHECK(dispatch_request(&state, &client, KSI_OPCODE_GET_KEY_STATE, 16u,
        device_key_state, KSI_KEY_STATE_REQUEST_SIZE));
    CHECK(read_status_response(sockets[1], KSI_OPCODE_GET_KEY_STATE, 16u,
        KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE, KSI_STATUS_OK, KSI_DETAIL_NONE, NULL));

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
    const ksi_forward_packet replay = { .target = 9u, .count = 1u,
        .events = {{ .type = EV_KEY, .code = KEY_A, .value = 0 }} };
    CHECK(output_queue_push_replay(&state->output_queue, &replay, 1u));
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
    CHECK(output_queue_init(&state->output_queue, state) == 0);
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
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_physical_and_generated_egress(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    atomic_store(&state->active_input_generation, 1u);
    const ksi_mouse_hook_event mouse = { .message = KSI_MESSAGE_MOUSE_MOVE, .x = 320, .device_id = 3u };
    const ksi_forward_packet replay = { .target = 17u, .count = 1u,
        .events = {{ .type = EV_REL, .code = REL_X, .value = 320 }} };
    /* No lane runs in this fixture, so every event finds its lane full. */
    state->keyboard_lane.state = state->mouse_lane.state = state;
    daemon_handle_hook_event(state, KSI_HOOK_MOUSE, &mouse, sizeof(mouse), &replay);
    ksi_output_action action;
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_REPLAY && action.packet.target == 17u);
    CHECK(action.packet.events[0].value == 320 && action.synth_inputs == NULL);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    state->client_count = 1u;
    state->clients[0].block_input_mask = KSI_BLOCK_KEYBOARD;
    const ksi_keyboard_hook_event key_up = { .message = KSI_MESSAGE_KEY_UP,
        .vk_code = 'A', .scan_code = KEY_A, .flags = KSI_KEYBOARD_HOOK_UP };
    const ksi_forward_packet release = { .target = 19u, .count = 2u,
        .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 0x70004 },
            { .type = EV_KEY, .code = KEY_A, .value = 0 }} };
    /* A key transition cannot overtake input still in its lane, so it fails
     * open instead of bypassing. */
    daemon_handle_hook_event(
        state, KSI_HOOK_KEYBOARD, &key_up, sizeof(key_up), &release);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_SOURCE_STATE);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    CHECK(atomic_exchange(&g_fail_open_requested, 0) == 1);

    const ksi_input generated = { .type = KSI_INPUT_MOUSE,
        .data.mouse = { .dx = 20, .flags = KSI_MOUSE_MOVE } };
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 5u };
    output_queue_sync_owners(state);
    CHECK(output_queue_push_synth(&state->output_queue, &generated, 1u, 0u, 1u, 5u));
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_SYNTH && action.synth_owner.connection_id == 5u);
    CHECK(action.synth_inputs[0].data.mouse.dx == 20);
    free(action.synth_inputs);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_synth_recreation_resets_logical_queue_state(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    uint8_t keys[KSI_KEY_STATE_BITMAP_BYTES] = {0};
    const ksi_input down = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    atomic_store(&state->active_input_generation, 1u);
    state->client_count = 1u;
    state->clients[0].connection_id = 7u;
    output_queue_sync_owners(state);
    CHECK(output_queue_push_synth(
        &state->output_queue, &down, 1u, 0u, 1u, 7u));
    ksi_linux_synth_add_logical_key_state(keys, sizeof(keys));
    CHECK((keys[KEY_B / 8u] & (uint8_t)(1u << (KEY_B % 8u))) != 0u);
    CHECK(output_queue_push_recreate_synth(&state->output_queue));
    memset(keys, 0, sizeof(keys));
    ksi_linux_synth_add_logical_key_state(keys, sizeof(keys));
    CHECK((keys[KEY_B / 8u] & (uint8_t)(1u << (KEY_B % 8u))) == 0u);

    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool key_logically_down(uint16_t code)
{
    uint8_t keys[KSI_KEY_STATE_BITMAP_BYTES] = {0};

    ksi_linux_synth_add_logical_key_state(keys, sizeof(keys));
    return (keys[code / 8u] & (uint8_t)(1u << (code % 8u))) != 0u;
}

/* An accepted connection owns output at once; only a passed key-up ends a Send
 * hold of its key; source state may use the reserve; an ungrabbed release skips
 * the lanes; and END_GRAB survives a seat fence. */
static bool test_output_admission_rules(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_ipc_peer_credentials credentials = { .pid = getpid(), .uid = getuid(), .gid = getgid() };
    const ksi_input shift = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_LEFTSHIFT, .flags = KSI_KEY_SCANCODE } };
    ksi_forward_packet packet = { .count = 2u, .flags = KSI_FORWARD_SUPPRESSED,
        .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 0x700e1 },
            { .type = EV_KEY, .code = KEY_LEFTSHIFT, .value = 0 }} };
    uint8_t kept[KSI_KEY_STATE_BITMAP_BYTES];
    ksi_output_action action;
    int sockets[2];

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    atomic_store(&state->active_input_generation, 1u);
    add_client(state, sockets[0], &credentials);
    CHECK(state->client_count == 1u);
    CHECK(output_queue_push_synth(&state->output_queue, &shift, 1u, 0u, 1u,
        state->clients[0].connection_id));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH);
    free(action.synth_inputs);
    CHECK(!output_queue_pop(&state->output_queue, &action) && key_logically_down(KEY_LEFTSHIFT));

    CHECK(output_queue_push_replay(&state->output_queue, &packet, 1u) && key_logically_down(KEY_LEFTSHIFT));
    packet.flags = 0u;
    CHECK(output_queue_push_replay(&state->output_queue, &packet, 1u) && !key_logically_down(KEY_LEFTSHIFT));
    while (output_queue_pop(&state->output_queue, &action)) {}

    packet.events[1].value = 1;
    while (output_queue_push_replay(&state->output_queue, &packet, 1u)) {}
    CHECK(output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE, &packet, 1u));
    while (output_queue_pop(&state->output_queue, &action)) {}

    packet = (ksi_forward_packet){ .target = 21u, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED,
        .events = {{ .type = EV_KEY, .code = KEY_A, .value = 0 }} };
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &packet));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SOURCE_STATE);
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY
        && action.packet.target == 21u);

    CHECK(output_queue_push_end_grab(&state->output_queue, 21u, kept) == 21u);
    output_queue_discard_stale(&state->output_queue, advance_input_generation(state));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_END_GRAB
        && action.input_generation == 0u && action.next_target == 21u);
    CHECK(atomic_load(&g_fail_open_requested) == 0);

    /* A queue too full to order the end moves written output at once. */
    packet.target = 22u;
    packet.events[0] = (ksi_forward_event){ .type = EV_REL, .code = REL_X, .value = 1 };
    packet.count = 1u;
    while (output_queue_push_replay(&state->output_queue, &packet, current_input_generation(state))) {}
    while (output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE,
        &(ksi_forward_packet){ .target = 22u, .count = 1u,
            .events = {{ .type = EV_KEY, .code = KEY_A, .value = 0 }} }, current_input_generation(state))) {}
    applied_end_grab = 0u;
    CHECK(output_queue_push_end_grab(&state->output_queue, 22u, kept) == 22u && applied_end_grab == 22u);
    while (output_queue_pop(&state->output_queue, &action)) CHECK(action.type != KSI_OUTPUT_ACTION_END_GRAB);

    remove_client(state, 0u);
    close(sockets[1]);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A lane keeps its last slots for events that must keep their order: key
 * transitions and a report's end. Other fragments pass a nearly full lane
 * without their hooks; an ordered one that cannot enter fails open. */
static bool test_lane_order_reserve(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    ksi_forward_packet packet = { .target = 23u, .count = 1u,
        .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 30 }} };
    ksi_output_action action;
    ksi_lane_event *event;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(ksi_pipe_ring_init(&state->keyboard_lane.action_queue.ring, sizeof(ksi_lane_event *),
        KSI_LANE_TRANSITION_RESERVE + 2u) == 0);
    atomic_store(&state->active_input_generation, 1u);
    state->keyboard_lane.state = state;

    for (int i = 0; i < 3; i++) CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &packet));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY
        && action.packet.events[0].type == EV_MSC);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    packet.count = 2u;
    packet.events[1] = (ksi_forward_event){ .type = EV_KEY, .code = KEY_A, .value = 0 };
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &packet));
    packet.count = 1u;
    packet.events[0] = (ksi_forward_event){ .type = EV_SYN, .code = SYN_REPORT };
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &packet));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SOURCE_STATE);
    CHECK(!output_queue_pop(&state->output_queue, &action) && atomic_load(&g_fail_open_requested) == 0);

    while (ksi_pipe_ring_pop(&state->keyboard_lane.action_queue.ring, &event)) lane_event_dispose(event);
    ksi_pipe_ring_close(&state->keyboard_lane.action_queue.ring);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A quarantined hook's holds end, and its later Modify output is refused. */
static bool test_quarantine_revokes_hook_output(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_synth_owner owner = { .connection_id = 6u, .hook_type = KSI_HOOK_KEYBOARD };
    const ksi_input b = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    ksi_output_action action;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    state->client_count = 1u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 6u, .uid = getuid(),
        .hook_subscriptions = KSI_OPERATION_HOOK_KEYBOARD };
    output_queue_sync_owners(state);
    CHECK(output_queue_push_owned_synth(&state->output_queue, &b, 1u, 0u, 0u, &owner, NULL, 0u));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH);
    free(action.synth_inputs);

    record_client_hook_failure(state, 0u, KSI_HOOK_KEYBOARD, 1u, 0u, 0u, KSI_HOOK_QUARANTINE_TIMEOUT);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && memcmp(&action.synth_owner, &owner, sizeof(owner)) == 0);
    CHECK(!output_queue_push_owned_synth(&state->output_queue, &b, 1u, 0u, 0u, &owner, NULL, 0u));
    CHECK(!output_queue_pop(&state->output_queue, &action));

    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A disconnect ends exactly the client's own holds, and output the client had
 * sent still plays but holds nothing; the last disconnect ends every
 * synthetic hold. */
static bool test_disconnect_releases_client_output(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_input b = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    ksi_output_action action;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    state->client_count = 2u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 7u };
    state->clients[1] = (ksi_client){ .fd = -1, .connection_id = 8u };
    remove_client(state, 0u);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && action.synth_owner.connection_id == 7u && action.synth_owner.target == 0u
        && action.synth_owner.hook_type == 0u && action.synth_owner.source_code == 0u);
    CHECK(output_queue_push_synth(&state->output_queue, &b, 1u, 0u, 0u, 7u));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH);
    free(action.synth_inputs);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && action.synth_owner.connection_id == 7u);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    /* Physical holds on clones end with their forwarded releases. */
    remove_client(state, 0u);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && action.synth_owner.connection_id == 8u);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_GENERIC);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    CHECK(atomic_load(&g_fail_open_requested) == 0);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* Unsubscribing revokes a hook before its holds are released, so a Modify
 * decided under it afterwards is refused and its event passes instead. */
static bool test_unsubscribe_revokes_hook_output(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    uint8_t hook[KSI_HOOK_SUBSCRIPTION_PAYLOAD_SIZE] = { 0 };
    const ksi_input b = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    const ksi_synth_owner owner = { .connection_id = 6u, .hook_type = KSI_HOOK_KEYBOARD };
    ksi_output_action action;
    int sockets[2];

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    state->ready_operations = KSI_OPERATION_ALL;
    state->client_count = 1u;
    ksi_client *client = &state->clients[0];
    *client = (ksi_client){ .fd = sockets[0], .connection_id = 6u, .uid = getuid(),
        .state = KSI_CLIENT_STATE_READY, .hello_complete = true,
        .connection_role = KSI_ROLE_CALLBACK_STREAM, .granted_scopes = KSI_SCOPE_INPUT_MONITORING,
        .rx_buffer = calloc(1u, KSI_MAX_MESSAGE_SIZE), .hook_send_ref = hook_send_ref_create(sockets[0]) };
    CHECK(client->rx_buffer != NULL && client->hook_send_ref != NULL);

    ksi_wire_write_u32(hook, KSI_HOOK_KEYBOARD);
    CHECK(dispatch_request(state, client, KSI_OPCODE_SUBSCRIBE_HOOK, 1u, hook, sizeof(hook)));
    CHECK(client->hook_subscriptions == KSI_OPERATION_HOOK_KEYBOARD);
    CHECK(output_queue_push_owned_synth(&state->output_queue, &b, 1u, 0u, 0u, &owner, NULL, 0u));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH);
    free(action.synth_inputs);

    CHECK(dispatch_request(state, client, KSI_OPCODE_UNSUBSCRIBE_HOOK, 2u, hook, sizeof(hook)));
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && memcmp(&action.synth_owner, &owner, sizeof(owner)) == 0);
    CHECK(!output_queue_push_owned_synth(&state->output_queue, &b, 1u, 0u, 0u, &owner, NULL, 0u));
    CHECK(!output_queue_pop(&state->output_queue, &action));

    remove_client(state, 0u);
    close(sockets[0]);
    close(sockets[1]);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A Modify of a physical key is owned by its responder, hook class and key. A
 * key-down not passed never reaches the outputs; a key-up does, after the
 * decision. A refused Modify passes once; a former seat's output drops quietly. */
static bool test_lane_decision_output(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    ksi_lane_decision *decision = calloc(1u, sizeof(*decision));
    ksi_output_action action;

    CHECK(state != NULL && decision != NULL);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    atomic_store(&state->active_input_generation, 1u);
    state->keyboard_lane.state = state;
    state->client_count = 1u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 4u,
        .hook_subscriptions = KSI_OPERATION_HOOK_KEYBOARD };
    output_queue_sync_owners(state);

    ksi_lane_event event = { .hook_type = KSI_HOOK_KEYBOARD, .input_generation = 1u,
        .physical_input = true, .egress = { .type = KSI_LANE_EGRESS_REPLAY,
            .replay = { .target = 19u, .count = 2u,
                .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 0x70004 },
                    { .type = EV_KEY, .code = KEY_A, .value = 0 }} } } };
    *decision = (ksi_lane_decision){ .decision = KSI_HOOK_MODIFY,
        .responder_connection_id = 4u, .input_count = 1u };
    decision->inputs[0] = (ksi_input){ .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    const ksi_synth_owner remap = { .target = 19u, .connection_id = 4u,
        .hook_type = KSI_HOOK_KEYBOARD, .source_type = EV_KEY, .source_code = KEY_A };

    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_MODIFY, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH
        && memcmp(&action.synth_owner, &remap, sizeof(remap)) == 0);
    free(action.synth_inputs);
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY
        && action.packet.events[1].value == 0 && (action.packet.flags & KSI_FORWARD_SUPPRESSED) != 0u);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_BLOCK, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY
        && (action.packet.flags & KSI_FORWARD_SUPPRESSED) != 0u);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    ksi_lane_event blocked = event;
    blocked.egress.type = KSI_LANE_EGRESS_NONE;
    CHECK(lane_emit_output(&state->keyboard_lane, &blocked, KSI_HOOK_PASS, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY
        && (action.packet.flags & KSI_FORWARD_SUPPRESSED) != 0u);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    event.egress.replay.events[1].value = 1;
    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_BLOCK, decision));
    CHECK(!output_queue_pop(&state->output_queue, &action));
    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_MODIFY, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH);
    free(action.synth_inputs);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    event.egress.replay.events[1].value = 0;

    state->clients[0].hook_subscriptions = 0u;
    output_queue_sync_owners(state);
    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_MODIFY, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    atomic_store(&state->active_input_generation, 2u);
    CHECK(lane_emit_output(&state->keyboard_lane, &event, KSI_HOOK_BLOCK, decision));
    CHECK(!output_queue_pop(&state->output_queue, &action));
    CHECK(atomic_load(&g_fail_open_requested) == 0);

    output_queue_close(&state->output_queue);
    free(decision);
    free(state);
    return true;
}

/* Raw report fragments collect no hook subscriber, input read while no seat
 * owner is active reaches nobody, and an ungrabbed source's release still
 * ends its clone hold. */
static bool test_raw_fragments_and_seat_gate(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_forward_packet scan = { .target = 24u, .count = 1u,
        .events = {{ .type = EV_MSC, .code = MSC_SCAN, .value = 30 }} };
    const ksi_keyboard_hook_event key = { .message = KSI_MESSAGE_KEY_DOWN, .vk_code = 'A', .scan_code = KEY_A };
    const ksi_forward_packet press = { .target = 24u, .count = 1u,
        .events = {{ .type = EV_KEY, .code = KEY_A, .value = 1 }} };
    ksi_output_action action;
    ksi_lane_event *event;
    int sockets[2];

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(ksi_pipe_ring_init(&state->keyboard_lane.action_queue.ring, sizeof(ksi_lane_event *),
        KSI_LANE_TRANSITION_RESERVE + 2u) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    atomic_store(&state->active_input_generation, 1u);
    state->keyboard_lane.state = state;
    state->client_count = 1u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 3u, .uid = getuid(),
        .hook_subscriptions = KSI_OPERATION_HOOK_KEYBOARD, .hook_send_ref = hook_send_ref_create(sockets[0]) };
    CHECK(state->clients[0].hook_send_ref != NULL);

    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &scan));
    CHECK(ksi_pipe_ring_pop(&state->keyboard_lane.action_queue.ring, &event) && event->subscriber_count == 0u);
    lane_event_dispose(event);
    daemon_handle_hook_event(state, KSI_HOOK_KEYBOARD, &key, sizeof(key), &press);
    CHECK(ksi_pipe_ring_pop(&state->keyboard_lane.action_queue.ring, &event) && event->subscriber_count == 1u);
    lane_event_dispose(event);
    while (output_queue_pop(&state->output_queue, &action)) {}

    state->input_owner_enforced = true;
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &scan));
    CHECK(!ksi_pipe_ring_pop(&state->keyboard_lane.action_queue.ring, &event));
    CHECK(!output_queue_pop(&state->output_queue, &action));
    const ksi_forward_packet release = { .target = 24u, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED,
        .events = {{ .type = EV_KEY, .code = KEY_A, .value = 0 }} };
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &release));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SOURCE_STATE);
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_REPLAY);

    hook_send_ref_invalidate(state->clients[0].hook_send_ref);
    hook_send_ref_release(state->clients[0].hook_send_ref);
    close(sockets[0]);
    close(sockets[1]);
    ksi_pipe_ring_close(&state->keyboard_lane.action_queue.ring);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* The panic chord fails open only while something intercepts input. */
static bool test_panic_fails_open(void)
{
    ksi_daemon_state state = { 0 };

    atomic_store(&g_fail_open_requested, 0);
    daemon_handle_panic(&state);
    CHECK(atomic_load(&g_fail_open_requested) == 0);
    state.interception_active = true;
    daemon_handle_panic(&state);
    CHECK(atomic_exchange(&g_fail_open_requested, 0) == 1);
    return true;
}

/* A hook class that ends releases its Modify holds, those made on synthetic
 * input included. */
static bool test_hook_class_end_releases_holds(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_platform_backend backend = { 0 };
    const ksi_synth_owner owner = { .hook_type = KSI_HOOK_KEYBOARD };
    ksi_output_action action;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    state->backend = &backend;
    state->owned_hook_mask = KSI_OPERATION_HOOK_KEYBOARD;
    CHECK(update_grab_state(state) == 0 && state->owned_hook_mask == 0u);
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER
        && memcmp(&action.synth_owner, &owner, sizeof(owner)) == 0);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A closed connection's holds end after the synthetic input it had already
 * queued for the hooks, and a fail-open that cancels that input keeps the
 * point where they end. */
static bool test_closed_connection_release_order(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_input b = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    ksi_output_action action;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(synthetic_hook_queue_init(&state->synthetic_hook_queue) == 0);
    state->client_count = 2u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 7u };
    state->clients[1] = (ksi_client){ .fd = -1, .connection_id = 8u };
    output_queue_sync_owners(state);
    CHECK(synthetic_hook_queue_push(&state->synthetic_hook_queue, &b, 1u, 1u, 0u, NULL, 0u, 7u));
    remove_client(state, 0u);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    CHECK(process_synthetic_hook_queue_one(state) && key_logically_down(KEY_B));
    CHECK(process_synthetic_hook_queue_one(state) && !key_logically_down(KEY_B));
    bool released = false;
    while (output_queue_pop(&state->output_queue, &action)) {
        if (action.type == KSI_OUTPUT_ACTION_SYNTH) {
            CHECK(!released);
            free(action.synth_inputs);
        } else {
            CHECK(action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER && action.synth_owner.connection_id == 7u);
            released = true;
        }
    }
    CHECK(released);

    CHECK(synthetic_hook_queue_push(&state->synthetic_hook_queue, &b, 1u, 1u, 0u, NULL, 0u, 8u));
    remove_client(state, 0u);
    synthetic_hook_queue_abort(&state->synthetic_hook_queue);
    CHECK(process_synthetic_hook_queue_one(state) && !process_synthetic_hook_queue_one(state));
    CHECK(output_queue_pop(&state->output_queue, &action)
        && action.type == KSI_OUTPUT_ACTION_RELEASE_SYNTH_OWNER && action.synth_owner.connection_id == 8u);
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_RELEASE_GENERIC);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    synthetic_hook_queue_close(&state->synthetic_hook_queue);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static int sink_pipe[2] = { -1, -1 };

/* The synthesis device is a pipe here, whose read end shows what reached the
 * sink. */
static bool start_sink(void)
{
    if (pipe2(sink_pipe, O_CLOEXEC | O_NONBLOCK) != 0) return false;
    uinput_fd = sink_pipe[1];
    ksi_linux_forward_attach_sink(sink_pipe[1]);
    return true;
}

static void stop_sink(void)
{
    ksi_linux_forward_attach_sink(-1);
    (void)ksi_linux_forward_take_failure();
    uinput_fd = -1;
    close(sink_pipe[0]);
    close(sink_pipe[1]);
}

static bool sink_keys(size_t n, const uint16_t *codes, const int32_t *values)
{
    struct input_event event;
    size_t keys = 0u;

    while (read(sink_pipe[0], &event, sizeof(event)) == (ssize_t)sizeof(event)) {
        if (event.type != EV_KEY) continue;
        if (keys == n || event.code != codes[keys] || event.value != values[keys]) return false;
        keys++;
    }
    return keys == n;
}

/* Applies everything queued, as the sequencer does. */
static void drain_output(ksi_daemon_state *state)
{
    ksi_output_action action;

    while (output_queue_pop(&state->output_queue, &action)) apply_output_action(state, &action);
}

static bool source_holds(uint64_t target, uint16_t code)
{
    uint8_t keys[KSI_KEY_BITMAP_BYTES] = {0};

    ksi_linux_forward_add_key_state(target, keys, sizeof(keys));
    return ksi_key_bit(keys, code);
}

static bool push_key(ksi_daemon_state *state, uint64_t target, uint16_t code, int32_t value)
{
    const ksi_forward_packet packet = { .target = target, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END, .events = {{ .type = EV_KEY, .code = code, .value = value }} };

    return output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE, &packet,
            current_input_generation(state))
        && output_queue_push_replay(&state->output_queue, &packet, current_input_generation(state));
}

/* A grab ends at its queue position, keeping what the source still holds and
 * playing nothing queued under the old target. A full queue ends it at once from
 * admitted state, since the release queued behind it is stale by then. */
static bool test_grab_end_through_output_queue(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    uint8_t kept[KSI_KEY_BITMAP_BYTES];
    uint64_t target = ksi_linux_forward_open(3, true);

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(target != 0u && !ksi_linux_forward_has_clone(target));
    atomic_store(&state->active_input_generation, 1u);
    CHECK(push_key(state, target, KEY_A, 1) && source_holds(target, KEY_A));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 1 }));

    uint64_t next = output_queue_push_end_grab(&state->output_queue, target, kept);
    CHECK(next > target && ksi_key_bit(kept, KEY_A) && source_holds(next, KEY_A));
    CHECK(push_key(state, target, KEY_B, 1) && !source_holds(next, KEY_B));
    drain_output(state);
    CHECK(sink_keys(0u, NULL, NULL));
    const ksi_forward_packet release = { .target = next, .count = 1u,
        .flags = KSI_FORWARD_REPORT_END | KSI_FORWARD_UNGRABBED,
        .events = {{ .type = EV_KEY, .code = KEY_A, .value = 0 }} };
    CHECK(daemon_forward_physical_event(state, KSI_HOOK_KEYBOARD, &release) && !source_holds(next, KEY_A));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));

    CHECK(push_key(state, next, KEY_C, 1));
    drain_output(state);
    CHECK(push_key(state, next, KEY_C, 0));
    while (output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE,
        &(ksi_forward_packet){ .count = 1u,
            .events = {{ .type = EV_KEY, .code = KEY_D, .value = 1 }} }, 1u)) {}
    target = output_queue_push_end_grab(&state->output_queue, next, kept);
    CHECK(target > next && !ksi_key_bit(kept, KEY_C));
    CHECK(sink_keys(2u, (const uint16_t[]){ KEY_C, KEY_C }, (const int32_t[]){ 1, 0 }));
    drain_output(state);
    CHECK(sink_keys(0u, NULL, NULL));

    output_queue_push_close(&state->output_queue, target);
    drain_output(state);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* What each action writes to the sink: synthesis and its owner's release, a
 * generic release that keeps source holds, release-all, output a former seat
 * admitted, and a close, which releases its source's holds whatever the seat. */
static bool test_output_actions_reach_sink(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_input a_and_b[] = {
        { .type = KSI_INPUT_KEYBOARD, .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } },
        { .type = KSI_INPUT_KEYBOARD, .data.keyboard = { .scan = KEY_A, .flags = KSI_KEY_SCANCODE } },
    };
    const ksi_input c = { .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_C, .flags = KSI_KEY_SCANCODE } };
    uint64_t target = ksi_linux_forward_open(3, true);

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    CHECK(target != 0u);
    atomic_store(&state->active_input_generation, 1u);
    state->client_count = 1u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 7u };
    output_queue_sync_owners(state);
    CHECK(push_key(state, target, KEY_A, 1));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 1 }));

    CHECK(output_queue_push_synth(&state->output_queue, a_and_b, 2u, 0u, 1u, 7u));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 1 }));
    CHECK(output_queue_push_release_generic(&state->output_queue));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 0 }));

    CHECK(output_queue_push_synth(&state->output_queue, &c, 1u, 0u, 1u, 7u));
    CHECK(output_queue_push_release_owner(&state->output_queue, &(ksi_synth_owner){ .connection_id = 7u }));
    drain_output(state);
    CHECK(sink_keys(2u, (const uint16_t[]){ KEY_C, KEY_C }, (const int32_t[]){ 1, 0 }));

    CHECK(output_queue_push_release_all(&state->output_queue) && !source_holds(target, KEY_A));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_A }, (const int32_t[]){ 0 }));

    CHECK(output_queue_push_synth(&state->output_queue, &c, 1u, 0u, 1u, 7u));
    CHECK(push_key(state, target, KEY_A, 1));
    CHECK(fence_permission_output(state));
    CHECK(push_key(state, target, KEY_B, 1));
    /* The sequencer may have taken an action off the queue before the fence. */
    ksi_output_action taken = { .type = KSI_OUTPUT_ACTION_SYNTH, .input_generation = 1u,
        .synth_inputs = malloc(sizeof(c)), .synth_count = 1u, .synth_owner = { .connection_id = 7u } };
    CHECK(taken.synth_inputs != NULL);
    *taken.synth_inputs = c;
    apply_output_action(state, &taken);
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 1 }));

    output_queue_push_close(&state->output_queue, target);
    CHECK(!source_holds(target, KEY_B));
    drain_output(state);
    CHECK(sink_keys(1u, (const uint16_t[]){ KEY_B }, (const int32_t[]){ 0 }));
    CHECK(ksi_linux_forward_failed(target, KSI_FORWARD_APPLIED));

    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* A sink that stops accepting output is recreated on the sequencer, at most
 * once per retry interval. */
static bool test_failed_sink_queues_recreation(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    const ksi_platform_backend backend = { 0 };
    ksi_output_action action;

    CHECK(state != NULL && output_queue_init(&state->output_queue, state) == 0);
    state->backend = &backend;
    run_backend_maintenance(state);
    CHECK(!output_queue_pop(&state->output_queue, &action));
    close(sink_pipe[0]);
    CHECK(ksi_linux_forward_sink_key(KEY_A, true) != 0 && !ksi_linux_synth_is_available());
    run_backend_maintenance(state);
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_RECREATE_SYNTH);
    run_backend_maintenance(state);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    last_synth_retry_ms = 0u;
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

/* Synthetic input a hook passes stays owned by its sender. A Modify of it is
 * owned by the responder's hook class alone, since no physical release ends
 * it. */
static bool test_hook_routed_send_owners(void)
{
    ksi_daemon_state *state = calloc(1u, sizeof(*state));
    ksi_lane_event *event = calloc(1u, sizeof(*event));
    ksi_lane_decision *decision = calloc(1u, sizeof(*decision));
    const ksi_synth_owner sender = { .connection_id = 9u };
    const ksi_synth_owner responder = { .connection_id = 4u, .hook_type = KSI_HOOK_KEYBOARD };
    ksi_output_action action;

    CHECK(state != NULL && event != NULL && decision != NULL);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    atomic_store(&state->active_input_generation, 1u);
    state->keyboard_lane.state = state;
    state->client_count = 2u;
    state->clients[0] = (ksi_client){ .fd = -1, .connection_id = 4u,
        .hook_subscriptions = KSI_OPERATION_HOOK_KEYBOARD };
    state->clients[1] = (ksi_client){ .fd = -1, .connection_id = 9u };
    output_queue_sync_owners(state);
    event->hook_type = KSI_HOOK_KEYBOARD;
    event->input_generation = 1u;
    event->egress = (ksi_lane_egress){ .type = KSI_LANE_EGRESS_SYNTH, .connection_id = 9u,
        .synth_count = 1u, .synth_inputs = {{ .type = KSI_INPUT_KEYBOARD,
            .data.keyboard = { .scan = KEY_A, .flags = KSI_KEY_SCANCODE | KSI_KEY_UP } }} };

    CHECK(lane_emit_output(&state->keyboard_lane, event, KSI_HOOK_PASS, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH
        && memcmp(&action.synth_owner, &sender, sizeof(sender)) == 0);
    free(action.synth_inputs);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    *decision = (ksi_lane_decision){ .decision = KSI_HOOK_MODIFY,
        .responder_connection_id = 4u, .input_count = 1u };
    decision->inputs[0] = (ksi_input){ .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = { .scan = KEY_B, .flags = KSI_KEY_SCANCODE } };
    CHECK(lane_emit_output(&state->keyboard_lane, event, KSI_HOOK_MODIFY, decision));
    CHECK(output_queue_pop(&state->output_queue, &action) && action.type == KSI_OUTPUT_ACTION_SYNTH
        && memcmp(&action.synth_owner, &responder, sizeof(responder)) == 0);
    free(action.synth_inputs);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    output_queue_close(&state->output_queue);
    free(decision);
    free(event);
    free(state);
    return true;
}

int main(void)
{
    if (!test_daemon_admission_and_operation_gates()
        || !test_observer_admission_and_backpressure()
        || !test_nonblocking_observer_transport()
        || !test_permission_fence_preserves_key_release()
        || !test_permission_io_does_not_block_input_admission()
        || !test_physical_and_generated_egress()
        || !test_synth_recreation_resets_logical_queue_state()
        || !test_disconnect_releases_client_output()
        || !test_unsubscribe_revokes_hook_output()
        || !test_lane_decision_output()
        || !test_output_admission_rules()
        || !test_lane_order_reserve()
        || !test_quarantine_revokes_hook_output()
        || !test_raw_fragments_and_seat_gate()
        || !test_panic_fails_open()
        || !test_hook_class_end_releases_holds()
        || !test_closed_connection_release_order()
        || !test_hook_routed_send_owners()) {
        return 1;
    }
    /* A broken sink is a pipe without a reader, as the daemon ignores. */
    signal(SIGPIPE, SIG_IGN);
    if (!start_sink() || !test_grab_end_through_output_queue()
        || !test_output_actions_reach_sink() || !test_failed_sink_queues_recreation()) {
        return 1;
    }
    stop_sink();
    puts("PASS daemon admission and operation gates");
    return 0;
}
