#include <stdbool.h>
#include <errno.h>
#include <linux/input-event-codes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "platform/vk_evdev.h"

bool g_verbose = false;

/* White-box coverage for daemon-private queue and transaction invariants. */
#include "../src/daemon.c"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

static void destroy_client_ref(ksi_client *client, int peer_fd)
{
    hook_send_ref_invalidate(client->hook_send_ref);
    hook_send_ref_release(client->hook_send_ref);
    client->hook_send_ref = NULL;
    close(peer_fd);
}

static void cleanup_test_auth_store(const char *store_path, uid_t uid,
                                    const char *const *hashes,
                                    size_t hash_count)
{
    char shared[KSI_AUTH_MAX_PATH + 16u];
    char runtime[KSI_AUTH_MAX_PATH + 16u];
    char path[KSI_AUTH_MAX_PATH + 128u];

    (void)snprintf(shared, sizeof(shared), "%s.shared-v1", store_path);
    (void)snprintf(runtime, sizeof(runtime), "%s.runtime", store_path);
    for (size_t hash_index = 0u; hash_index < hash_count; hash_index++)
        for (uint32_t bit = 1u; bit <= KSP_SCOPE_INPUT_CONTROL; bit <<= 1u) {
            (void)snprintf(path, sizeof(path),
                "%s/grant-%lu-%s-%08x.grant", shared,
                (unsigned long)uid, hashes[hash_index], bit);
            (void)unlink(path);
        }
    for (size_t hash_index = 0u; hash_index < hash_count; hash_index++) {
        (void)snprintf(path, sizeof(path), "%s/.prompt-%lu-%s.lock", runtime,
            (unsigned long)uid, hashes[hash_index]);
        (void)unlink(path);
    }
    (void)snprintf(path, sizeof(path), "%s/.lock", shared);
    (void)unlink(path);
    (void)rmdir(shared);
    (void)snprintf(path, sizeof(path), "%s/revoke-%lu.generation", runtime,
        (unsigned long)uid);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s/.revoke-%lu.lock", runtime,
        (unsigned long)uid);
    (void)unlink(path);
    (void)rmdir(runtime);
    (void)unlink(store_path);
}

static bool read_hello_result(
    int fd,
    uint64_t correlation_id,
    ksi_client_hello_result_payload *result)
{
    uint8_t buffer[sizeof(ksi_message_header) + sizeof(*result)];
    ksi_message_header header;
    size_t message_size = 0u;
    struct pollfd wait = { .fd = fd, .events = POLLIN };

    CHECK(poll(&wait, 1u, 5000) == 1);
    CHECK(ksi_ipc_read_framed_message(
        fd, buffer, sizeof(buffer), &message_size) == 1);
    CHECK(message_size == sizeof(buffer));
    memcpy(&header, buffer, sizeof(header));
    memcpy(result, buffer + sizeof(header), sizeof(*result));
    CHECK(header.type == KSI_MESSAGE_CLIENT_HELLO);
    CHECK(header.correlation_id == correlation_id);
    return true;
}

static bool read_status_result(
    int fd,
    uint32_t type,
    uint64_t correlation_id,
    ksi_status_payload *result)
{
    uint8_t buffer[sizeof(ksi_message_header) + sizeof(*result)];
    ksi_message_header header;
    size_t message_size = 0u;
    struct pollfd wait = { .fd = fd, .events = POLLIN };

    CHECK(poll(&wait, 1u, 5000) == 1);
    CHECK(ksi_ipc_read_framed_message(
        fd, buffer, sizeof(buffer), &message_size) == 1);
    CHECK(message_size == sizeof(buffer));
    memcpy(&header, buffer, sizeof(header));
    memcpy(result, buffer + sizeof(header), sizeof(*result));
    CHECK(header.type == type);
    CHECK(header.correlation_id == correlation_id);
    return true;
}

static bool read_payload_result(
    int fd,
    uint32_t type,
    uint64_t correlation_id,
    void *payload,
    size_t expected_payload_size)
{
    uint8_t buffer[sizeof(ksi_message_header) + sizeof(ksi_key_state_payload)];
    ksi_message_header header;
    size_t message_size = 0u;
    struct pollfd wait = { .fd = fd, .events = POLLIN };

    CHECK(sizeof(header) + expected_payload_size <= sizeof(buffer));
    CHECK(poll(&wait, 1u, 5000) == 1);
    CHECK(ksi_ipc_read_framed_message(
        fd, buffer, sizeof(buffer), &message_size) == 1);
    CHECK(message_size == sizeof(header) + expected_payload_size);
    memcpy(&header, buffer, sizeof(header));
    CHECK(header.type == type);
    CHECK(header.correlation_id == correlation_id);
    if (payload != NULL && expected_payload_size != 0u) {
        memcpy(payload, buffer + sizeof(header), expected_payload_size);
    }
    return true;
}

static bool test_nested_parent_mismatch_fails_open_as_one_batch(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_nested_transaction *transaction;
    ksi_output_action action;

    CHECK(state != NULL);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    state->keyboard_lane.state = state;
    atomic_store(&state->keyboard_lane.current_event_id, 1u);
    atomic_store(&state->keyboard_lane.current_responder_connection_id, 42u);

    transaction = calloc(1,
        sizeof(*transaction) + 2u * sizeof(transaction->members[0]));
    CHECK(transaction != NULL);
    transaction->count = 2u;
    transaction->depth = 1u;
    transaction->origin_connection_id = 42u;
    transaction->parent_hook_event_id = 99u;
    transaction->members[0].input.type = KSI_INPUT_KEYBOARD;
    transaction->members[0].input.data.keyboard.vk = KSI_VK_LCONTROL;
    transaction->members[1].input = transaction->members[0].input;
    transaction->members[1].input.data.keyboard.flags = KSI_KEYEVENTF_KEYUP;

    CHECK(lane_process_nested_transaction(&state->keyboard_lane, transaction));
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_SYNTH);
    CHECK(action.synth_count == 2u);
    CHECK((action.synth_flags & KSI_SYNTH_FLAG_BYPASS_HOOK) != 0u);
    CHECK(action.synth_inputs[0].data.keyboard.flags == 0u);
    CHECK((action.synth_inputs[1].data.keyboard.flags & KSI_KEYEVENTF_KEYUP) != 0u);

    free(action.synth_inputs);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_subscriber_snapshot_uses_hook_install_order(void)
{
    const uint64_t ordinals[] = { 10u, 30u, 20u };
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_keyboard_hook_event hook_event = { 0 };
    ksi_lane_event *event;
    int sockets[3][2];

    CHECK(state != NULL);
    state->client_count = 3u;
    state->next_event_id = 1u;

    for (size_t i = 0u; i < 3u; i++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets[i]) == 0);
        state->clients[i].fd = sockets[i][0];
        state->clients[i].connection_id = i + 1u;
        state->clients[i].hook_subscriptions = KSI_CAP_HOOK_KEYBOARD;
        state->clients[i].hook_subscription_ordinal[0] = ordinals[i];
        state->clients[i].hook_send_ref = hook_send_ref_create(sockets[i][0]);
        CHECK(state->clients[i].hook_send_ref != NULL);
    }

    event = create_hook_lane_event(state, KSI_HOOK_KEYBOARD_LL,
        &hook_event, sizeof(hook_event), NULL, NULL, 0u, 0u);
    CHECK(event != NULL);
    CHECK(event->subscriber_count == 3u);
    CHECK(event->subscribers[0].connection_id == 2u);
    CHECK(event->subscribers[1].connection_id == 3u);
    CHECK(event->subscribers[2].connection_id == 1u);
    lane_event_release_send_refs(event);
    free(event);

    for (size_t i = 0u; i < 3u; i++) {
        destroy_client_ref(&state->clients[i], sockets[i][1]);
    }

    free(state);
    return true;
}

static bool test_only_active_seat_user_enters_hook_snapshot(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_keyboard_hook_event hook_event = { 0 };
    ksi_lane_event *event;
    int sockets[2][2];

    CHECK(state != NULL);
    state->input_owner_enforced = true;
    atomic_init(&state->active_input_uid_valid, true);
    atomic_init(&state->active_input_uid, 1000u);
    state->client_count = 2u;
    state->next_event_id = 1u;

    for (size_t i = 0u; i < 2u; i++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets[i]) == 0);
        state->clients[i].fd = sockets[i][0];
        state->clients[i].uid = (uid_t)(1000u + i);
        state->clients[i].connection_id = i + 1u;
        state->clients[i].hook_subscriptions = KSI_CAP_HOOK_KEYBOARD;
        state->clients[i].hook_subscription_ordinal[0] = i + 1u;
        state->clients[i].hook_send_ref = hook_send_ref_create(sockets[i][0]);
        CHECK(state->clients[i].hook_send_ref != NULL);
    }

    event = create_hook_lane_event(state, KSI_HOOK_KEYBOARD_LL,
        &hook_event, sizeof(hook_event), NULL, NULL, 0u, 0u);
    CHECK(event != NULL);
    CHECK(event->subscriber_count == 1u);
    CHECK(event->subscribers[0].connection_id == 1u);
    lane_event_release_send_refs(event);
    free(event);

    for (size_t i = 0u; i < 2u; i++) {
        destroy_client_ref(&state->clients[i], sockets[i][1]);
    }

    free(state);
    return true;
}

static bool test_seat_transition_fences_output_and_preserves_subscriptions(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_input old_input = { .type = KSI_INPUT_KEYBOARD };
    ksi_output_action action;

    CHECK(state != NULL);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    state->input_owner_enforced = true;
    atomic_init(&state->active_input_uid_valid, true);
    atomic_init(&state->active_input_uid, 1000u);
    atomic_init(&state->active_input_generation, 1u);
    state->client_count = 2u;
    state->clients[0].uid = 1000u;
    state->clients[0].hook_subscriptions = KSI_CAP_HOOK_KEYBOARD;
    state->clients[1].uid = 1001u;
    state->clients[1].hook_subscriptions = KSI_CAP_HOOK_MOUSE;

    CHECK(active_hook_subscription_mask(state) == KSI_CAP_HOOK_KEYBOARD);
    CHECK(output_queue_push_synth(
        &state->output_queue, &old_input, 1u, 0u, 1u));
    CHECK(output_queue_push_release_all(&state->output_queue));

    set_active_input_owner(state, true, 1001u);

    CHECK(atomic_load(&state->active_input_uid_valid));
    CHECK(atomic_load(&state->active_input_uid) == 1001u);
    CHECK(atomic_load(&state->active_input_generation) == 2u);
    CHECK(active_hook_subscription_mask(state) == KSI_CAP_HOOK_MOUSE);
    CHECK(state->clients[0].hook_subscriptions == KSI_CAP_HOOK_KEYBOARD);
    CHECK(state->clients[1].hook_subscriptions == KSI_CAP_HOOK_MOUSE);

    /* The old generation was discarded. Only the pre-existing internal safety
     * release and the transition's new release remain. */
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_RELEASE_ALL);
    CHECK(output_queue_pop(&state->output_queue, &action));
    CHECK(action.type == KSI_OUTPUT_ACTION_RELEASE_ALL);
    CHECK(!output_queue_pop(&state->output_queue, &action));

    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_cancelled_callback_is_not_delivered_after_turn_claim(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_lane_event *event;
    ksi_lane_decision decision;
    ksi_subscriber_result result;
    int sockets[2];
    char byte;

    CHECK(state != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    state->keyboard_lane.state = state;
    atomic_store(&state->keyboard_lane.flush_generation, 2u);

    event = calloc(1, sizeof(*event) + sizeof(event->subscribers[0]));
    CHECK(event != NULL);
    event->event_id = 9u;
    event->hook_type = KSI_HOOK_KEYBOARD_LL;
    event->generation = 1u;
    event->subscriber_count = 1u;
    event->subscribers[0].send_ref = hook_send_ref_create(sockets[0]);
    CHECK(event->subscribers[0].send_ref != NULL);
    event->subscribers[0].connection_id = 7u;

    result = lane_call_subscriber(&state->keyboard_lane, event,
        &event->subscribers[0], &decision);
    CHECK(result == KSI_SUBSCRIBER_EVENT_CANCELLED);
    errno = 0;
    CHECK(recv(sockets[1], &byte, sizeof(byte), MSG_DONTWAIT) == -1);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

    lane_event_release_send_refs(event);
    free(event);
    close(sockets[1]);
    free(state);
    return true;
}

static bool test_quarantine_retries_in_daemon(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    int sockets[2];

    CHECK(state != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    state->client_count = 1u;
    state->clients[0].fd = sockets[0];
    state->clients[0].connection_id = 77u;
    state->clients[0].hook_subscriptions = KSI_CAP_HOOK_KEYBOARD;
    state->clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state->clients[0].hook_send_ref != NULL);

    record_client_hook_failure(state, 0u, KSI_HOOK_KEYBOARD_LL,
        1u, 0u, KSI_HOOK_DECISION_TIMEOUT_MS,
        KSI_HOOK_QUARANTINE_REASON_TIMEOUT);
    CHECK((state->clients[0].quarantined_hooks & KSI_CAP_HOOK_KEYBOARD) != 0u);
    CHECK(hook_send_ref_is_stalled(state->clients[0].hook_send_ref, 0u));

    state->clients[0].quarantine_rearm_after_ms[0] = 1u;
    retry_quarantined_hooks(state);
    CHECK((state->clients[0].quarantined_hooks & KSI_CAP_HOOK_KEYBOARD) == 0u);
    CHECK(!hook_send_ref_is_stalled(state->clients[0].hook_send_ref, 0u));

    destroy_client_ref(&state->clients[0], sockets[1]);
    output_queue_close(&state->output_queue);
    free(state);
    return true;
}

static bool test_fifth_timeout_invalidates_only_that_session(void)
{
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    int sockets[2];

    CHECK(state != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(output_queue_init(&state->output_queue, state) == 0);
    state->client_count = 1u;
    state->clients[0].fd = sockets[0];
    state->clients[0].connection_id = 77u;
    state->clients[0].hook_subscriptions = KSI_CAP_HOOK_KEYBOARD;
    state->clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state->clients[0].hook_send_ref != NULL);

    for (unsigned int strike = 1u;
            strike <= KSI_MAX_CONSECUTIVE_HOOK_FAILURES; strike++) {
        record_client_hook_failure(state, 0u, KSI_HOOK_KEYBOARD_LL,
            strike, 0u, KSI_HOOK_DECISION_TIMEOUT_MS,
            KSI_HOOK_QUARANTINE_REASON_TIMEOUT);

        if (strike < KSI_MAX_CONSECUTIVE_HOOK_FAILURES) {
            CHECK(state->client_count == 1u);
            state->clients[0].quarantined_hooks = 0u;
            hook_send_ref_clear_stalled(state->clients[0].hook_send_ref, 0u);
        }
    }

    CHECK(state->client_count == 0u);
    output_queue_close(&state->output_queue);
    close(sockets[1]);
    free(state);
    return true;
}

static bool test_release_transitions_keep_reserved_output_capacity(void)
{
    ksi_daemon_state state = { 0 };
    ksi_input down = { .type = KSI_INPUT_KEYBOARD };
    ksi_input up = { .type = KSI_INPUT_KEYBOARD };
    ksi_hook_event_payload replay = { .hook_type = KSI_HOOK_KEYBOARD_LL };
    size_t occupied = KSI_MAX_OUTPUT_ACTIONS - KSI_OUTPUT_CLEANUP_RESERVE;
    size_t slot;

    up.data.keyboard.flags = KSI_KEYEVENTF_KEYUP;
    CHECK(output_queue_init(&state.output_queue, &state) == 0);
    state.output_queue.count = occupied;
    CHECK(!output_queue_push_synth(&state.output_queue, &down, 1u, 0u, 0u));
    CHECK(output_queue_push_synth(&state.output_queue, &up, 1u, 0u, 0u));

    slot = occupied % KSI_MAX_OUTPUT_ACTIONS;
    free(state.output_queue.actions[slot].synth_inputs);
    memset(&state.output_queue.actions[slot], 0,
        sizeof(state.output_queue.actions[slot]));
    state.output_queue.count = occupied;
    state.output_queue.synth_bytes = 0u;

    replay.event.keyboard.message = KSI_WM_KEYDOWN;
    CHECK(!output_queue_push_replay(
        &state.output_queue, KSI_HOOK_KEYBOARD_LL, &replay, 0u));
    replay.event.keyboard.message = KSI_WM_KEYUP;
    CHECK(output_queue_push_replay(
        &state.output_queue, KSI_HOOK_KEYBOARD_LL, &replay, 0u));

    state.output_queue.count = 0u;
    ksi_linux_synth_reset_enqueued_synth();
    output_queue_close(&state.output_queue);
    return true;
}

static bool test_synthetic_queue_rejects_whole_batch(void)
{
    ksi_synthetic_hook_queue queue;
    ksi_input inputs[2] = {
        { .type = KSI_INPUT_KEYBOARD },
        { .type = KSI_INPUT_KEYBOARD },
    };

    CHECK(synthetic_hook_queue_init(&queue) == 0);
    queue.count = KSI_MAX_SYNTH_HOOK_ACTIONS - 1u;
    CHECK(!synthetic_hook_queue_push(
        &queue, inputs, 2u, 2u, 123u, NULL, 0u));
    CHECK(queue.count == KSI_MAX_SYNTH_HOOK_ACTIONS - 1u);
    queue.count = 0u;
    synthetic_hook_queue_close(&queue);
    return true;
}

static bool test_detached_synth_completion_keeps_batch_atomic(void)
{
    ksi_daemon_state state = { 0 };
    ksi_synthetic_hook_queue queue;
    ksi_synth_completion *completion;
    ksi_synth_completion *popped_completion;
    ksi_input inputs[2] = {
        { .type = KSI_INPUT_KEYBOARD },
        { .type = KSI_INPUT_KEYBOARD },
    };
    ksi_input popped;
    uint64_t queued_at;
    uint64_t generation;
    bool batch_start;

    CHECK(synthetic_hook_queue_init(&queue) == 0);
    completion = synth_completion_create(&state, NULL, NULL);
    CHECK(completion != NULL);
    synth_completion_begin_atomic(completion);
    CHECK(atomic_load(&state.active_synthetic_transactions) == 1u);
    CHECK(synthetic_hook_queue_push(
        &queue, inputs, 2u, 2u, 123u, completion, 7u));

    CHECK(synthetic_hook_queue_pop(&queue, &popped, &queued_at,
        &popped_completion, &batch_start, &generation));
    CHECK(popped_completion == completion);
    CHECK(batch_start);
    synth_completion_complete(popped_completion);
    CHECK(atomic_load(&state.active_synthetic_transactions) == 1u);

    CHECK(synthetic_hook_queue_pop(&queue, &popped, &queued_at,
        &popped_completion, &batch_start, &generation));
    CHECK(popped_completion == completion);
    CHECK(!batch_start);
    synth_completion_complete(popped_completion);
    CHECK(atomic_load(&state.active_synthetic_transactions) == 0u);

    synthetic_hook_queue_close(&queue);
    return true;
}

static unsigned int prepare_capabilities_calls;

static void record_prepare_capabilities(uint32_t requested)
{
    if (requested != 0u) {
        prepare_capabilities_calls++;
    }
}

static uint32_t prepared_available_capabilities(void)
{
    return prepare_capabilities_calls == 0u ? 0u : KSI_CAP_HOOK_KEYBOARD;
}

static bool test_capless_query_does_not_prepare_input_devices(void)
{
    const ksi_platform_backend backend = {
        .prepare_capabilities = record_prepare_capabilities,
        .get_available_capabilities = prepared_available_capabilities,
    };
    ksi_daemon_state state = { .backend = &backend };

    prepare_capabilities_calls = 0u;
    prepare_requested_capabilities(&state, 0u);
    CHECK(prepare_capabilities_calls == 0u);
    CHECK(state.available_capabilities == 0u);
    prepare_requested_capabilities(&state, KSI_CAP_HOOK_KEYBOARD);
    CHECK(prepare_capabilities_calls == 1u);
    CHECK(state.available_capabilities == KSI_CAP_HOOK_KEYBOARD);
    return true;
}

static bool test_protocol_minor_must_match_exactly(void)
{
    ksi_daemon_state state = { 0 };
    ksi_client client = { .fd = -1 };
    ksi_message_header header = {
        .size = sizeof(header),
        .major = KSI_PROTOCOL_MAJOR,
        .minor = KSI_PROTOCOL_MINOR - 1u,
        .type = KSI_MESSAGE_HEARTBEAT,
    };
    uint8_t buffer[sizeof(header)];

    memcpy(buffer, &header, sizeof(header));
    client.rx_buffer = buffer;
    client.rx_used = sizeof(buffer);
    CHECK(!process_client_buffer_direct(&state, &client));
    CHECK(!client.protocol_version_seen);
    return true;
}

static bool test_query_permission_boundaries(void)
{
    ksi_daemon_state state = { 0 };
    ksi_client_hello_payload hello = {
        .requested_capabilities = 0u,
        .role = KSI_CONNECTION_GENERAL_RPC,
    };
    ksi_message_header header = {
        .type = KSI_MESSAGE_CLIENT_HELLO,
        .client_id = 7u,
        .correlation_id = 70u,
    };
    ksi_binary_message_view message = {
        .header = &header,
        .payload = (const uint8_t *)(const void *)&hello,
        .payload_size = sizeof(hello),
    };
    ksi_client_hello_result_payload hello_result;
    ksi_indicator_state_payload indicators;
    ksi_pointer_position_payload pointer;
    ksi_modifier_state_payload modifiers;
    ksi_key_state_payload keys;
    ksi_pointer_buttons_payload buttons;
    ksi_status_payload denied;
    int sockets[2];

    CHECK(sizeof(ksi_modifier_state_payload) == 12u);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    state.client_count = 1u;
    state.clients[0].fd = sockets[0];
    state.clients[0].uid = getuid();
    state.clients[0].state = KSI_CLIENT_STATE_READY;
    state.clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);

    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_hello_result(sockets[1], header.correlation_id, &hello_result));
    CHECK(hello_result.status == 0);
    CHECK(hello_result.granted_capabilities == 0u);
    CHECK(state.clients[0].authenticated);

    header.type = KSI_MESSAGE_GET_INDICATOR_STATE;
    header.correlation_id++;
    message.payload = NULL;
    message.payload_size = 0u;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_INDICATOR_STATE_RESULT,
        header.correlation_id, &indicators, sizeof(indicators)));

    header.type = KSI_MESSAGE_GET_POINTER_POSITION;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_POINTER_POSITION_RESULT,
        header.correlation_id, &pointer, sizeof(pointer)));

    header.type = KSI_MESSAGE_MODIFIER_STATE;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_MODIFIER_STATE,
        header.correlation_id, &modifiers, sizeof(modifiers)));

    header.type = KSI_MESSAGE_GET_KEY_STATE;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_KEY_STATE_RESULT,
        header.correlation_id, &denied, sizeof(denied)));
    CHECK(denied.status == -1);
    CHECK(denied.detail == KSI_DETAIL_PERMISSION_DENIED);

    header.type = KSI_MESSAGE_GET_POINTER_BUTTONS;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_POINTER_BUTTONS_RESULT,
        header.correlation_id, &denied, sizeof(denied)));
    CHECK(denied.status == -1);
    CHECK(denied.detail == KSI_DETAIL_PERMISSION_DENIED);

    state.clients[0].granted_capabilities =
        KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE;
    header.type = KSI_MESSAGE_GET_KEY_STATE;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_KEY_STATE_RESULT,
        header.correlation_id, &keys, sizeof(keys)));
    header.type = KSI_MESSAGE_GET_POINTER_BUTTONS;
    header.correlation_id++;
    handle_binary_message(NULL, &state, &state.clients[0], &message);
    CHECK(read_payload_result(sockets[1], KSI_MESSAGE_POINTER_BUTTONS_RESULT,
        header.correlation_id, &buttons, sizeof(buttons)));

    destroy_client_ref(&state.clients[0], sockets[1]);
    return true;
}

static bool test_input_scope_mapping(void)
{
    CHECK(permission_scopes_for_operations(KSI_CAP_HOOK_KEYBOARD)
        == KSP_SCOPE_INPUT_MONITORING);
    CHECK(permission_scopes_for_operations(KSI_CAP_SYNTH_MOUSE)
        == KSP_SCOPE_INPUT_CONTROL);
    CHECK(permission_scopes_for_operations(
        KSI_CAP_HOOK_MOUSE | KSI_CAP_BLOCK_INPUT)
        == KSP_INPUT_SCOPES);
    CHECK(operations_allowed_by_scopes(KSI_INPUT_CAPABILITIES,
        KSP_SCOPE_INPUT_MONITORING)
        == (KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE));
    CHECK(operations_allowed_by_scopes(KSI_INPUT_CAPABILITIES,
        KSP_SCOPE_INPUT_CONTROL)
        == (KSI_CAP_SYNTH_KEYBOARD | KSI_CAP_SYNTH_MOUSE
            | KSI_CAP_BLOCK_INPUT));
    return true;
}

static bool test_monitoring_revoke_closes_only_hook_stream(void)
{
    static const char hash[] =
        "abababababababababababababababababababababababababababababababab";
    ksi_daemon_state state = { 0 };
    int hook_sockets[2];
    int rpc_sockets[2];
    char byte;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, hook_sockets) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, rpc_sockets) == 0);
    state.client_count = 2u;

    state.clients[0].fd = hook_sockets[0];
    state.clients[0].uid = getuid();
    state.clients[0].has_identity = true;
    state.clients[0].connection_role = KSI_CONNECTION_HOOK_STREAM;
    state.clients[0].hook_send_ref = hook_send_ref_create(hook_sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);
    (void)snprintf(state.clients[0].exe_hash,
        sizeof(state.clients[0].exe_hash), "%s", hash);

    state.clients[1].fd = rpc_sockets[0];
    state.clients[1].uid = getuid();
    state.clients[1].has_identity = true;
    state.clients[1].connection_role = KSI_CONNECTION_GENERAL_RPC;
    state.clients[1].hook_send_ref = hook_send_ref_create(rpc_sockets[0]);
    CHECK(state.clients[1].hook_send_ref != NULL);
    (void)snprintf(state.clients[1].exe_hash,
        sizeof(state.clients[1].exe_hash), "%s", hash);

    invalidate_connected_permissions(&state, getuid(), hash,
        KSP_SCOPE_INPUT_MONITORING);

    CHECK(!hook_send_ref_is_valid(state.clients[0].hook_send_ref));
    CHECK(recv(hook_sockets[1], &byte, sizeof(byte), 0) == 0);
    CHECK(hook_send_ref_is_valid(state.clients[1].hook_send_ref));

    destroy_client_ref(&state.clients[0], hook_sockets[1]);
    destroy_client_ref(&state.clients[1], rpc_sockets[1]);
    return true;
}

static bool test_unauthorized_hook_decision_fails_open_immediately(void)
{
    ksi_daemon_state state = { 0 };
    ksi_hook_decision_payload payload = {
        .event_id = 900u,
        .decision = KSI_HOOK_DECISION_BLOCK,
        .input_count = 0u,
    };
    ksi_message_header header = {
        .type = KSI_MESSAGE_HOOK_DECISION,
        .client_id = 11u,
        .correlation_id = 901u,
    };
    ksi_binary_message_view message = {
        .header = &header,
        .payload = (const uint8_t *)(const void *)&payload,
        .payload_size = sizeof(payload),
    };
    ksi_lane_decision decision;
    ksi_status_payload status;
    int sockets[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(lane_decision_queue_init(&state.keyboard_lane.decision_queue) == 0);
    atomic_store(&state.keyboard_lane.current_event_id, payload.event_id);
    atomic_store(&state.keyboard_lane.current_responder_connection_id, 55u);
    state.client_count = 1u;
    state.clients[0].fd = sockets[0];
    state.clients[0].connection_id = 55u;
    state.clients[0].uid = getuid();
    state.clients[0].authenticated = true;
    state.clients[0].granted_capabilities = KSI_CAP_HOOK_KEYBOARD;
    state.clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);

    handle_hook_decision(&state, &state.clients[0], &message);
    CHECK(read_status_result(sockets[1], KSI_MESSAGE_HOOK_DECISION,
        header.correlation_id, &status));
    CHECK(status.status == -1);
    CHECK(status.detail == KSI_DETAIL_PERMISSION_DENIED);
    CHECK(lane_decision_queue_pop(&state.keyboard_lane.decision_queue,
        &decision));
    CHECK(decision.event_id == payload.event_id);
    CHECK(decision.responder_connection_id == state.clients[0].connection_id);
    CHECK(decision.decision == KSI_HOOK_DECISION_PASS);
    CHECK(decision.input_count == 0u);

    state.clients[0].granted_capabilities |= KSI_CAP_BLOCK_INPUT;
    header.correlation_id++;
    handle_hook_decision(&state, &state.clients[0], &message);
    CHECK(read_status_result(sockets[1], KSI_MESSAGE_HOOK_DECISION,
        header.correlation_id, &status));
    CHECK(status.status == 0);
    CHECK(lane_decision_queue_pop(&state.keyboard_lane.decision_queue,
        &decision));
    CHECK(decision.decision == KSI_HOOK_DECISION_BLOCK);

    lane_decision_queue_close(&state.keyboard_lane.decision_queue);
    destroy_client_ref(&state.clients[0], sockets[1]);
    return true;
}

static bool test_block_input_can_always_be_released(void)
{
    ksi_daemon_state state = { 0 };
    ksi_block_input_payload payload = {
        .block_mask = KSI_BLOCK_INPUT_KEYBOARD,
    };
    ksi_message_header header = {
        .type = KSI_MESSAGE_SET_BLOCK_INPUT,
        .client_id = 12u,
        .correlation_id = 1000u,
    };
    ksi_binary_message_view message = {
        .header = &header,
        .payload = (const uint8_t *)(const void *)&payload,
        .payload_size = sizeof(payload),
    };
    ksi_status_payload status;
    int sockets[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    state.client_count = 1u;
    state.clients[0].fd = sockets[0];
    state.clients[0].authenticated = true;
    state.clients[0].granted_capabilities = KSI_CAP_BLOCK_INPUT;
    state.clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);
    handle_set_block_input(&state, &state.clients[0], &message);
    CHECK(read_status_result(sockets[1], KSI_MESSAGE_SET_BLOCK_INPUT,
        header.correlation_id, &status));
    CHECK(status.status == 0);
    CHECK(state.clients[0].block_input_mask == KSI_BLOCK_INPUT_KEYBOARD);

    state.clients[0].authenticated = false;
    state.clients[0].granted_capabilities = 0u;
    payload.block_mask = 0u;
    header.correlation_id++;
    handle_set_block_input(&state, &state.clients[0], &message);
    CHECK(read_status_result(sockets[1], KSI_MESSAGE_SET_BLOCK_INPUT,
        header.correlation_id, &status));
    CHECK(status.status == 0);
    CHECK(state.clients[0].block_input_mask == 0u);

    destroy_client_ref(&state.clients[0], sockets[1]);
    return true;
}

static bool test_check_only_hello_never_prompts(void)
{
    static const char hash[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ksi_platform_backend backend = {
        .prepare_capabilities = record_prepare_capabilities,
        .get_available_capabilities = prepared_available_capabilities,
    };
    char directory[] = "/tmp/keysharp-input-hello-XXXXXX";
    char store_path[KSI_AUTH_MAX_PATH];
    ksi_auth_store *store = NULL;
    ksi_daemon_state state = { .backend = &backend };
    ksi_client_hello_payload payload = {
        .requested_capabilities = KSI_CAP_HOOK_KEYBOARD,
        .flags = KSI_CLIENT_HELLO_FLAG_CHECK_ONLY,
        .role = KSI_CONNECTION_GENERAL_RPC,
    };
    ksi_message_header header = {
        .type = KSI_MESSAGE_CLIENT_HELLO,
        .client_id = 8u,
        .correlation_id = 100u,
    };
    ksi_binary_message_view message = {
        .header = &header,
        .payload = (const uint8_t *)(const void *)&payload,
        .payload_size = sizeof(payload),
    };
    ksi_client_hello_result_payload result;
    int sockets[2];

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/grants.tsv", directory)
        < (int)sizeof(store_path));
    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    state.permissions = store;
    state.client_count = 1u;
    state.clients[0].fd = sockets[0];
    state.clients[0].uid = getuid();
    state.clients[0].state = KSI_CLIENT_STATE_READY;
    state.clients[0].identity_attempted = true;
    state.clients[0].has_identity = true;
    (void)snprintf(state.clients[0].exe_path,
        sizeof(state.clients[0].exe_path), "/tmp/keysharp-test-client");
    (void)snprintf(state.clients[0].exe_hash,
        sizeof(state.clients[0].exe_hash), "%s", hash);
    state.clients[0].hook_send_ref = hook_send_ref_create(sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);

    prepare_capabilities_calls = 0u;
    handle_client_hello(&state, &state.clients[0], &message);
    CHECK(read_hello_result(sockets[1], header.correlation_id, &result));
    CHECK(result.status == KSI_CLIENT_HELLO_STATUS_PERMISSION_DENIED);
    CHECK(result.granted_capabilities == 0u);
    CHECK(state.clients[0].state == KSI_CLIENT_STATE_READY);
    CHECK(!state.clients[0].pending_hello_valid);
    CHECK(ksi_auth_store_get_allowed(store, getuid(), hash) == 0u);

    CHECK(ksi_auth_store_grant(store, getuid(), hash,
        state.clients[0].exe_path, KSP_SCOPE_INPUT_MONITORING) == 0);
    header.correlation_id++;
    handle_client_hello(&state, &state.clients[0], &message);
    CHECK(read_hello_result(sockets[1], header.correlation_id, &result));
    CHECK(result.status == 0);
    CHECK(result.granted_capabilities == KSI_CAP_HOOK_KEYBOARD);
    CHECK(state.clients[0].authenticated);

    destroy_client_ref(&state.clients[0], sockets[1]);
    ksi_auth_store_destroy(store);
    const char *hashes[] = { hash };
    cleanup_test_auth_store(store_path, getuid(), hashes, 1u);
    CHECK(rmdir(directory) == 0);
    return true;
}

static bool test_revoke_invalidates_connected_clients(void)
{
    static const char target_hash[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char cli_hash[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const uint32_t monitoring_operations =
        KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE;
    const uint32_t control_operations = KSI_CAP_SYNTH_KEYBOARD
        | KSI_CAP_SYNTH_MOUSE | KSI_CAP_BLOCK_INPUT;
    const uint32_t all_operations = monitoring_operations | control_operations;
    char directory[] = "/tmp/keysharp-input-revoke-XXXXXX";
    char store_path[KSI_AUTH_MAX_PATH];
    ksi_auth_store *store = NULL;
    ksi_daemon_state state = { 0 };
    ksi_revoke_permissions_payload payload = {
        .target_uid = KSI_REVOKE_PERMISSIONS_UID_SELF,
        .scopes = KSP_SCOPE_INPUT_MONITORING,
    };
    ksi_message_header header = {
        .type = KSI_MESSAGE_REVOKE_PERMISSIONS,
        .client_id = 9u,
        .correlation_id = 200u,
    };
    ksi_binary_message_view message = {
        .header = &header,
        .payload = (const uint8_t *)(const void *)&payload,
        .payload_size = sizeof(payload),
    };
    ksi_daemon_command prompt_result = { 0 };
    ksi_status_payload result;
    ksi_client_hello_result_payload hello_result;
    int target_sockets[2];
    int cli_sockets[2];

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/grants.tsv", directory)
        < (int)sizeof(store_path));
    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(ksi_auth_store_grant(store, getuid(), target_hash,
        "/tmp/keysharp-test-client", KSP_INPUT_SCOPES) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, target_sockets) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, cli_sockets) == 0);

    state.permissions = store;
    state.permission_generation = 4u;
    state.client_count = 2u;
    atomic_init(&state.keyboard_lane.flush_generation, 0u);
    atomic_init(&state.mouse_lane.flush_generation, 0u);

    state.clients[0].fd = target_sockets[0];
    state.clients[0].connection_id = 21u;
    state.clients[0].uid = getuid();
    state.clients[0].has_identity = true;
    state.clients[0].authenticated = true;
    state.clients[0].granted_capabilities = all_operations;
    state.clients[0].hook_subscriptions =
        KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE;
    state.clients[0].hook_subscription_ordinal[0] = 10u;
    state.clients[0].hook_subscription_ordinal[1] = 11u;
    state.clients[0].block_input_mask =
        KSI_BLOCK_INPUT_KEYBOARD | KSI_BLOCK_INPUT_MOUSE;
    state.clients[0].consecutive_hook_failures[0] = 2u;
    state.clients[0].consecutive_hook_failures[1] = 3u;
    state.clients[0].quarantined_hooks =
        KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE;
    state.clients[0].pending_hello_permission_generation = 4u;
    state.clients[0].pending_hello_valid = true;
    state.clients[0].pending_hello_requested = KSI_CAP_SYNTH_KEYBOARD;
    state.clients[0].pending_hello_client_id = 10u;
    state.clients[0].pending_hello_correlation_id = 201u;
    state.clients[0].state = KSI_CLIENT_STATE_AWAITING_PROMPT;
    state.clients[0].lease_expires_ms = 99u;
    (void)snprintf(state.clients[0].exe_hash,
        sizeof(state.clients[0].exe_hash), "%s", target_hash);
    state.clients[0].hook_send_ref = hook_send_ref_create(target_sockets[0]);
    CHECK(state.clients[0].hook_send_ref != NULL);
    hook_send_ref_mark_stalled(state.clients[0].hook_send_ref, 0u);
    hook_send_ref_mark_stalled(state.clients[0].hook_send_ref, 1u);

    state.clients[1].fd = cli_sockets[0];
    state.clients[1].uid = getuid();
    state.clients[1].has_identity = true;
    state.clients[1].authenticated = true;
    state.clients[1].granted_capabilities = KSI_CAP_SYNTH_KEYBOARD;
    (void)snprintf(state.clients[1].exe_hash,
        sizeof(state.clients[1].exe_hash), "%s", cli_hash);
    state.clients[1].hook_send_ref = hook_send_ref_create(cli_sockets[0]);
    CHECK(state.clients[1].hook_send_ref != NULL);

    (void)snprintf(payload.exe_hash, sizeof(payload.exe_hash), "%s", target_hash);
    handle_revoke_permissions(&state, &state.clients[1], &message);
    CHECK(read_status_result(cli_sockets[1], KSI_MESSAGE_REVOKE_PERMISSIONS,
        header.correlation_id, &result));
    CHECK(result.status == 0);
    CHECK(ksi_auth_store_get_allowed(store, getuid(), target_hash)
        == KSP_SCOPE_INPUT_CONTROL);
    CHECK(state.permission_generation == 5u);
    CHECK(state.clients[0].pending_hello_permission_generation
        != state.permission_generation);
    CHECK(state.clients[0].granted_capabilities == control_operations);
    CHECK(state.clients[0].hook_subscriptions == 0u);
    CHECK(state.clients[0].hook_subscription_ordinal[0] == 0u);
    CHECK(state.clients[0].hook_subscription_ordinal[1] == 0u);
    CHECK(state.clients[0].block_input_mask
        == (KSI_BLOCK_INPUT_KEYBOARD | KSI_BLOCK_INPUT_MOUSE));
    CHECK(state.clients[0].consecutive_hook_failures[0] == 0u);
    CHECK(state.clients[0].consecutive_hook_failures[1] == 0u);
    CHECK(state.clients[0].quarantined_hooks == 0u);
    CHECK(!hook_send_ref_is_stalled(state.clients[0].hook_send_ref, 0u));
    CHECK(!hook_send_ref_is_stalled(state.clients[0].hook_send_ref, 1u));
    CHECK(atomic_load(&state.keyboard_lane.flush_generation) == 1u);
    CHECK(atomic_load(&state.mouse_lane.flush_generation) == 1u);
    CHECK(state.clients[1].granted_capabilities == KSI_CAP_SYNTH_KEYBOARD);

    CHECK(ksi_auth_store_grant(store, getuid(), target_hash,
        "/tmp/keysharp-test-client", KSP_SCOPE_INPUT_MONITORING) == 0);
    state.clients[0].granted_capabilities = all_operations;
    state.clients[0].hook_subscriptions = monitoring_operations;
    state.clients[0].hook_subscription_ordinal[0] = 12u;
    state.clients[0].hook_subscription_ordinal[1] = 13u;
    state.clients[0].block_input_mask =
        KSI_BLOCK_INPUT_KEYBOARD | KSI_BLOCK_INPUT_MOUSE;
    state.clients[0].pending_hello_permission_generation = 5u;
    state.clients[0].pending_hello_valid = true;
    state.clients[0].pending_hello_requested = KSI_CAP_SYNTH_KEYBOARD;
    state.clients[0].pending_hello_client_id = 10u;
    state.clients[0].pending_hello_correlation_id = 202u;
    state.clients[0].state = KSI_CLIENT_STATE_AWAITING_PROMPT;

    payload.scopes = KSP_SCOPE_INPUT_CONTROL;
    header.correlation_id++;
    handle_revoke_permissions(&state, &state.clients[1], &message);
    CHECK(read_status_result(cli_sockets[1], KSI_MESSAGE_REVOKE_PERMISSIONS,
        header.correlation_id, &result));
    CHECK(result.status == 0);
    CHECK(ksi_auth_store_get_allowed(store, getuid(), target_hash)
        == KSP_SCOPE_INPUT_MONITORING);
    CHECK(state.permission_generation == 6u);
    CHECK(state.clients[0].granted_capabilities == monitoring_operations);
    CHECK(state.clients[0].hook_subscriptions == monitoring_operations);
    CHECK(state.clients[0].hook_subscription_ordinal[0] == 12u);
    CHECK(state.clients[0].hook_subscription_ordinal[1] == 13u);
    CHECK(state.clients[0].block_input_mask == 0u);
    CHECK(atomic_load(&state.keyboard_lane.flush_generation) == 1u);
    CHECK(atomic_load(&state.mouse_lane.flush_generation) == 1u);

    prompt_result.type = KSI_DAEMON_COMMAND_CLIENT_PROMPT_DONE;
    prompt_result.client_fd = target_sockets[0];
    prompt_result.connection_id = 21u;
    prompt_result.data.prompt_done.decision = KSI_AUTH_GRANTED;
    prompt_result.data.prompt_done.requested_capabilities = KSI_CAP_SYNTH_KEYBOARD;
    prompt_result.data.prompt_done.missing_scopes =
        KSP_SCOPE_INPUT_CONTROL;
    /* Simulate a second daemon performing the revoke without advancing this
     * process's in-memory epoch.  The shared generation must still fence the
     * prompt completion and prevent a persisted re-grant. */
    state.clients[0].pending_hello_permission_generation =
        state.permission_generation;
    process_client_prompt_done(&state, &prompt_result);
    CHECK(read_hello_result(target_sockets[1], 202u, &hello_result));
    CHECK(hello_result.status == -1);
    CHECK(hello_result.granted_capabilities == 0u);
    CHECK(ksi_auth_store_get_allowed(store, getuid(), target_hash)
        == KSP_SCOPE_INPUT_MONITORING);
    CHECK(state.clients[0].granted_capabilities == monitoring_operations);

    destroy_client_ref(&state.clients[0], target_sockets[1]);
    destroy_client_ref(&state.clients[1], cli_sockets[1]);
    ksi_auth_store_destroy(store);
    const char *hashes[] = { target_hash, cli_hash };
    cleanup_test_auth_store(store_path, getuid(), hashes, 2u);
    CHECK(rmdir(directory) == 0);
    return true;
}

static bool test_external_revoke_refreshes_connected_clients(void)
{
    static const char hash[] =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    char directory[] = "/tmp/keysharp-input-external-revoke-XXXXXX";
    char store_path[KSI_AUTH_MAX_PATH];
    ksi_auth_store *store = NULL;
    ksi_daemon_state state = { 0 };
    uint64_t generation;

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/grants.tsv", directory)
        < (int)sizeof(store_path));
    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(ksi_auth_store_grant(store, getuid(), hash,
        "/tmp/keysharp-test-client", KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksi_auth_store_get_generation(store, getuid(), &generation) == 0);

    state.permissions = store;
    state.permission_notify_fd = -1;
    state.permission_notify_watch = -1;
    state.client_count = 1u;
    state.clients[0].uid = getuid();
    state.clients[0].has_identity = true;
    state.clients[0].granted_capabilities = KSI_CAP_HOOK_MOUSE;
    state.clients[0].permission_store_generation = generation;
    state.clients[0].permission_store_generation_valid = true;
    (void)snprintf(state.clients[0].exe_hash,
        sizeof(state.clients[0].exe_hash), "%s", hash);
    CHECK(permission_monitor_init(&state) == 0);

    /* Mutate only the shared store, as keysharp-desktop authority mode would. */
    CHECK(ksi_auth_store_revoke(store, getuid(), hash,
        KSP_SCOPE_INPUT_MONITORING) == 0);
    struct pollfd notification = {
        .fd = state.permission_notify_fd,
        .events = POLLIN,
    };
    CHECK(poll(&notification, 1u, 1000) == 1);
    process_permission_notifications(&state, notification.revents);
    CHECK(state.clients[0].granted_capabilities == 0u);
    CHECK(state.permission_generation == 1u);
    CHECK(!state.permission_monitor_failed);

    CHECK(ksi_auth_store_grant(store, getuid(), hash,
        "/tmp/keysharp-test-client", KSP_SCOPE_INPUT_MONITORING) == 0);
    state.clients[0].granted_capabilities = KSI_CAP_HOOK_KEYBOARD;
    process_permission_notifications(&state, POLLERR);
    CHECK(state.permission_monitor_failed);
    CHECK(state.permission_notify_fd == -1);
    CHECK(state.clients[0].granted_capabilities == 0u);

    ksi_auth_store_destroy(store);
    const char *hashes[] = { hash };
    cleanup_test_auth_store(store_path, getuid(), hashes, 1u);
    CHECK(rmdir(directory) == 0);
    return true;
}

static bool test_prompt_worker_reuses_serialized_grant(void)
{
    static const char hash[] =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    char directory[] = "/tmp/keysharp-input-prompt-lock-XXXXXX";
    char store_path[KSI_AUTH_MAX_PATH];
    ksi_auth_store *store = NULL;
    ksi_daemon_command_queue commands;
    ksi_daemon_command result;
    ksi_prompt_task *task;

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/grants.tsv", directory)
        < (int)sizeof(store_path));
    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(ksi_auth_store_grant(store, getuid(), hash,
        "/tmp/keysharp-test-client", KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(command_queue_init(&commands) == 0);

    task = calloc(1u, sizeof(*task));
    CHECK(task != NULL);
    task->commands = &commands;
    task->permissions = store;
    task->client_fd = 20;
    task->connection_id = 30u;
    task->requested_capabilities = KSI_CAP_HOOK_MOUSE;
    task->missing_scopes = KSP_SCOPE_INPUT_MONITORING;
    task->uid = getuid();
    task->pid = getpid();
    task->start_time = ksi_auth_get_process_start_time(getpid());
    (void)snprintf(task->exe_path, sizeof(task->exe_path),
        "/tmp/keysharp-test-client");
    (void)snprintf(task->exe_hash, sizeof(task->exe_hash), "%s", hash);

    (void)prompt_worker(task);
    CHECK(ksi_pipe_ring_pop(&commands.ring, &result));
    CHECK(result.type == KSI_DAEMON_COMMAND_CLIENT_PROMPT_DONE);
    CHECK(result.data.prompt_done.decision == KSI_AUTH_GRANTED);
    CHECK(result.data.prompt_done.missing_scopes == 0u);
    CHECK(result.data.prompt_done.prompt_lock_held);
    CHECK(result.data.prompt_done.prompt_lock_fd >= 0);
    free_daemon_command(&result);
    command_queue_destroy(&commands);

    ksi_auth_store_destroy(store);
    const char *hashes[] = { hash };
    cleanup_test_auth_store(store_path, getuid(), hashes, 1u);
    CHECK(rmdir(directory) == 0);
    return true;
}

static bool test_vk_evdev_mapping_covers_portable_and_alternate_codes(void)
{
    CHECK(ksi_vk_to_evdev(0x03u) == KEY_CANCEL);
    CHECK(ksi_vk_to_evdev(0x15u) == KEY_KATAKANAHIRAGANA);
    CHECK(ksi_vk_to_evdev(0x19u) == KEY_HANJA);
    CHECK(ksi_vk_to_evdev(0xB4u) == KEY_MAIL);
    CHECK(ksi_vk_to_evdev(0xABu) == KEY_BOOKMARKS);
    CHECK(ksi_vk_to_evdev(0xE2u) == KEY_102ND);
    CHECK(ksi_evdev_to_vk(KEY_KATAKANA) == 0x15u);
    CHECK(ksi_evdev_to_vk(KEY_HANGEUL) == 0x15u);
    CHECK(ksi_evdev_to_vk(KEY_KPJPCOMMA) == 0x6Cu);
    CHECK(ksi_evdev_to_vk(KEY_KPEQUAL) == 0xBBu);
    CHECK(ksi_evdev_to_vk(KEY_YEN) == 0xDCu);
    CHECK(ksi_evdev_to_vk(KEY_MENU) == 0x5Du);
    CHECK(ksi_evdev_to_vk(KEY_WWW) == 0xACu);
    CHECK(ksi_evdev_to_vk(KEY_BOOKMARKS) == 0xABu);
    CHECK(ksi_evdev_to_vk(KEY_FAVORITES) == 0xABu);
    CHECK(ksi_evdev_to_vk(KEY_EMAIL) == 0xB4u);
    CHECK(ksi_evdev_to_vk(KEY_RO) == 0xE2u);
    return true;
}

static bool test_panic_chord_requires_all_physical_keys(void)
{
    uint8_t keys[KSI_KEY_STATE_BITMAP_BYTES] = { 0 };

    keys[KEY_BACKSPACE >> 3u] |= (uint8_t)(1u << (KEY_BACKSPACE & 7u));
    keys[KEY_ESC >> 3u] |= (uint8_t)(1u << (KEY_ESC & 7u));
    CHECK(!panic_chord_is_down(keys));
    keys[KEY_ENTER >> 3u] |= (uint8_t)(1u << (KEY_ENTER & 7u));
    CHECK(panic_chord_is_down(keys));
    keys[KEY_ESC >> 3u] &= (uint8_t)~(1u << (KEY_ESC & 7u));
    CHECK(!panic_chord_is_down(keys));
    return true;
}

static bool test_lane_event_allocation_benchmark(void)
{
    const unsigned int iterations = 100000u;
    ksi_daemon_state *state = calloc(1, sizeof(*state));
    ksi_keyboard_hook_event event = {
        .message = KSI_WM_KEYDOWN,
        .vk_code = 0x41u,
    };
    struct timespec begin;
    struct timespec end;
    uint64_t elapsed_ns;

    CHECK(state != NULL);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);

    for (unsigned int i = 0u; i < iterations; i++) {
        ksi_lane_event *lane_event = create_hook_lane_event(
            state, KSI_HOOK_KEYBOARD_LL, &event, sizeof(event),
            NULL, NULL, 0u, 0u);
        CHECK(lane_event != NULL);
        free(lane_event);
    }

    CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    elapsed_ns = ((uint64_t)(end.tv_sec - begin.tv_sec) * 1000000000u)
        + (uint64_t)(end.tv_nsec - begin.tv_nsec);
    printf("lane event snapshot: %.1f ns/event\n",
        (double)elapsed_ns / iterations);
    free(state);
    return true;
}

int main(void)
{
    const struct {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        { "VK/evdev mapping covers portable and alternate codes", test_vk_evdev_mapping_covers_portable_and_alternate_codes },
        { "panic chord requires all physical keys", test_panic_chord_requires_all_physical_keys },
        { "stale nested transaction preserves its whole batch", test_nested_parent_mismatch_fails_open_as_one_batch },
        { "hook snapshot follows install order", test_subscriber_snapshot_uses_hook_install_order },
        { "only active seat user receives callbacks", test_only_active_seat_user_enters_hook_snapshot },
        { "seat transition fences output and preserves subscriptions", test_seat_transition_fences_output_and_preserves_subscriptions },
        { "cancelled callback is not delivered after turn claim", test_cancelled_callback_is_not_delivered_after_turn_claim },
        { "quarantine retries within the daemon", test_quarantine_retries_in_daemon },
        { "fifth timeout invalidates one session", test_fifth_timeout_invalidates_only_that_session },
        { "output queue reserves release capacity", test_release_transitions_keep_reserved_output_capacity },
        { "synthetic queue rejects whole batch", test_synthetic_queue_rejects_whole_batch },
        { "detached synthesis completion preserves batch atomicity", test_detached_synth_completion_keeps_batch_atomic },
        { "capless query leaves devices inactive", test_capless_query_does_not_prepare_input_devices },
        { "protocol minor must match exactly", test_protocol_minor_must_match_exactly },
        { "query permission boundaries", test_query_permission_boundaries },
        { "input operations map to two scopes", test_input_scope_mapping },
        { "Monitoring revoke closes only hook stream", test_monitoring_revoke_closes_only_hook_stream },
        { "unauthorized hook decisions fail open immediately", test_unauthorized_hook_decision_fails_open_immediately },
        { "BlockInput can always be released", test_block_input_can_always_be_released },
        { "check-only hello never prompts", test_check_only_hello_never_prompts },
        { "revocation invalidates connected clients", test_revoke_invalidates_connected_clients },
        { "external revocation refreshes connected clients", test_external_revoke_refreshes_connected_clients },
        { "serialized prompt reuses an existing grant", test_prompt_worker_reuses_serialized_grant },
        { "lane snapshot allocation benchmark", test_lane_event_allocation_benchmark },
    };

    for (size_t i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (!tests[i].run()) {
            return 1;
        }

        printf("PASS %s\n", tests[i].name);
    }

    return 0;
}
