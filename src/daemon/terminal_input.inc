#include "platform/linux_terminal.h"
#include "terminal_contract.h"

typedef struct ksi_terminal_task {
    ksi_daemon_state *state;
    ksi_hook_send_ref *send_ref;
    uint64_t connection_id;
    uint64_t request_id;
    uint64_t input_generation;
    uint64_t permission_generation;
    uint64_t deadline_ms;
    uid_t uid;
    uint32_t target;
    uint32_t flags;
    uint32_t count;
    uint8_t bytes[KSI_MAX_TERMINAL_INPUT_BYTES];
} ksi_terminal_task;

static void free_terminal_task(void *context)
{
    ksi_terminal_task *task = context;
    hook_send_ref_release(task->send_ref);
    free(task);
}

static bool terminal_task_live(const ksi_terminal_task *task)
{
    return !permissions_cancelled(NULL) && monotonic_ms() < task->deadline_ms
        && hook_send_ref_is_valid(task->send_ref)
        && input_owner_matches_uid(task->state, task->uid)
        && current_input_generation(task->state) == task->input_generation
        && atomic_load(&task->state->permission_generation) == task->permission_generation
        && output_owner_is_live(&task->state->output_queue, task->connection_id);
}

static bool terminal_gate_begin(void *context)
{
    ksi_terminal_task *task = context;
    pthread_mutex_lock(&task->state->output_queue.execution_mutex);
    if (terminal_task_live(task)) return true;
    pthread_mutex_unlock(&task->state->output_queue.execution_mutex);
    return false;
}

static void terminal_gate_end(void *context)
{
    ksi_terminal_task *task = context;
    pthread_mutex_unlock(&task->state->output_queue.execution_mutex);
}

static bool terminal_gate_check(void *context)
{
    return terminal_task_live(context);
}

static bool terminal_send_result(const ksi_terminal_task *task, const uint8_t *response)
{
    uint64_t deadline = monotonic_ms() + 1000u;
    do {
        int sent = hook_send_ref_try_send(task->send_ref, KSI_OPCODE_TERMINAL_INPUT,
            KSI_FRAME_FLAG_RESPONSE, task->request_id, response, KSI_TERMINAL_INPUT_RESULT_SIZE);
        if (sent != 0) return sent == 1;
        /* Only the acknowledgement is retried; injection must never be replayed. */
        const struct timespec pause = { .tv_nsec = 1000000L };
        (void)nanosleep(&pause, NULL);
    } while (!permissions_cancelled(NULL) && monotonic_ms() < deadline);
    return false;
}

static void *terminal_worker(void *context)
{
    ksi_terminal_task *task = context;
    uint32_t accepted = 0u;
    int system_error = ECANCELED;
    ksi_status status = KSI_STATUS_REVOKED;
    if (terminal_task_live(task)) {
        const ksi_terminal_gate gate = {
            .begin = terminal_gate_begin, .check = terminal_gate_check,
            .end = terminal_gate_end, .context = task,
        };
        status = ksi_linux_terminal_input(task->uid, task->target, task->flags,
            task->bytes, task->count, &gate, &accepted, &system_error);
    }
    if (status == KSI_STATUS_REVOKED && monotonic_ms() >= task->deadline_ms) {
        status = KSI_STATUS_TIMEOUT;
        system_error = ETIMEDOUT;
    }
    uint8_t response[KSI_TERMINAL_INPUT_RESULT_SIZE];
    ksi_status_encode(response, status, KSI_DETAIL_NONE);
    ksi_wire_write_u32(response + 8u, accepted);
    ksi_wire_write_u32(response + 12u, (uint32_t)system_error);
    if (!terminal_send_result(task, response))
        hook_send_ref_invalidate(task->send_ref);
    free_terminal_task(task);
    return NULL;
}

static void handle_terminal_input(ksi_daemon_state *state, ksi_client *client,
    const ksi_binary_message_view *message)
{
    if (client->connection_role != KSI_ROLE_RPC
        && client->connection_role != KSI_ROLE_AUTHORIZATION_LEASE) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_WRONG_ROLE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)
        || !client_has_scope(client, KSP_SCOPE_INPUT_CONTROL)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED, KSI_DETAIL_NONE);
        return;
    }
    if (message->payload_size < KSI_TERMINAL_INPUT_PREFIX_SIZE) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    uint32_t kind = ksi_wire_read_u32(message->payload);
    uint32_t target = ksi_wire_read_u32(message->payload + 4u);
    uint32_t flags = ksi_wire_read_u32(message->payload + 8u);
    uint32_t count = ksi_wire_read_u32(message->payload + 12u);
    if (message->payload_size - KSI_TERMINAL_INPUT_PREFIX_SIZE != count
        || !ksi_terminal_request_valid(kind, target, flags,
            message->payload + KSI_TERMINAL_INPUT_PREFIX_SIZE, count)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_VALUE_RANGE);
        return;
    }
    if ((state->available_operations & KSI_OPERATION_TERMINAL_INPUT) == 0u
        || !state->output_queue.execution_mutex_initialized) {
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE);
        return;
    }
    ksi_terminal_task *task = calloc(1u, sizeof(*task));
    if (task == NULL || !hook_send_ref_acquire(client->hook_send_ref)) {
        free(task);
        send_status(client->fd, message->header, KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
        return;
    }
    task->state = state;
    task->send_ref = client->hook_send_ref;
    task->connection_id = client->connection_id;
    task->request_id = message->header->request_id;
    task->input_generation = current_input_generation(state);
    task->permission_generation = atomic_load(&state->permission_generation);
    task->deadline_ms = monotonic_ms() + 5000u;
    task->uid = client->uid;
    task->target = target;
    task->flags = flags;
    task->count = count;
    memcpy(task->bytes, message->payload + KSI_TERMINAL_INPUT_PREFIX_SIZE, count);
    if (!ksi_worker_pool_submit(&g_terminal_worker_pool, terminal_worker, free_terminal_task, task)) {
        free_terminal_task(task);
        send_status(client->fd, message->header, KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
    }
}
