typedef enum ksi_permission_task_kind {
    KSI_PERMISSION_CHECK,
    KSI_PERMISSION_LIST,
    KSI_PERMISSION_REVOKE,
    KSI_PERMISSION_REFRESH,
} ksi_permission_task_kind;

typedef struct ksi_permission_snapshot {
    uid_t uid;
    char hash[KSP_HASH_HEX_LENGTH + 1u];
    uint32_t allowed;
    uint64_t generation;
} ksi_permission_snapshot;

struct ksi_permission_task {
    ksi_permission_task_kind kind;
    ksi_daemon_state *state;
    ksi_hook_send_ref *send_ref;
    int client_fd;
    uint64_t connection_id;
    uint64_t request_id;
    uint64_t permission_generation;
    uint64_t input_generation;
    uint64_t deadline_ms;
    uid_t uid;
    ksp_identity identity;
    ksi_permissions_revoke_payload revoke;
    char hash[KSP_HASH_HEX_LENGTH + 1u];
    uint32_t requested;
    uint32_t allowed;
    uint64_t store_generation;
    uint32_t status;
    size_t snapshot_count;
    ksi_permission_snapshot snapshots[KSI_MAX_CLIENTS];
};

static bool permission_task_cancelled(const ksi_permission_task *task)
{
    return permissions_cancelled(NULL) || monotonic_ms() >= task->deadline_ms
        || (task->kind != KSI_PERMISSION_REFRESH
            && (!hook_send_ref_is_valid(task->send_ref)
                || !input_owner_matches_uid(task->state, task->uid)
                || current_input_generation(task->state) != task->input_generation))
        || (task->kind == KSI_PERMISSION_CHECK
            && atomic_load(&task->state->permission_generation) != task->permission_generation);
}

static void free_permission_task(void *context)
{
    ksi_permission_task *task = context;
    if (task == NULL) return;
    if (task->send_ref != NULL) hook_send_ref_release(task->send_ref);
    free(task);
}

static bool permission_send_list_frame(ksi_permission_task *task, uint16_t flags,
    const uint8_t *payload, size_t length)
{
    while (!permission_task_cancelled(task)) {
        int sent = hook_send_ref_try_send(task->send_ref, KSI_OPCODE_PERMISSIONS_LIST,
            flags, task->request_id, payload, length);
        if (sent == 1) return true;
        if (sent < 0) return false;
        /* Wait outside the send mutex so control replies never wait behind a
         * worker stalled by this reader's socket backpressure. */
        const struct timespec pause = { .tv_nsec = 1000000L };
        (void)nanosleep(&pause, NULL);
    }
    return false;
}

static void permission_list_worker(ksi_permission_task *task)
{
    ksp_permission_entry *entries = NULL;
    size_t count = 0u;
    uint8_t buffer[KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE + KSP_PATH_CAPACITY];
    if (ksp_store_list(task->state->permissions, task->uid, &entries, &count) != 0) {
        task->status = KSI_STATUS_INTERNAL;
        return;
    }
    for (size_t i = 0u; i < count; i++) {
        uint32_t scopes = entries[i].scopes & KSI_INPUT_PERMISSION_SCOPES;
        if (permission_task_cancelled(task)) {
            task->status = KSI_STATUS_CANCELLED;
            break;
        }
        if (scopes == 0u || !ksp_hash_is_canonical(entries[i].app_hash)) continue;
        size_t length = strnlen(entries[i].executable, KSP_PATH_CAPACITY);
        ksi_status_encode(buffer, KSI_STATUS_OK, KSI_DETAIL_NONE);
        ksi_wire_write_u32(buffer + 8u, scopes);
        ksi_wire_write_u32(buffer + 12u, (uint32_t)length);
        ksi_wire_write_u64(buffer + 16u, entries[i].granted_at_utc);
        ksi_protocol_encode_hash(entries[i].app_hash, buffer + 24u);
        memcpy(buffer + KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE, entries[i].executable, length);
        if (!permission_send_list_frame(task, KSI_FRAME_FLAG_RESPONSE | KSI_FRAME_FLAG_MORE,
                buffer, KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE + length)) {
            task->status = KSI_STATUS_CANCELLED;
            break;
        }
    }
    ksp_store_list_free(entries);
}

static void *permission_worker(void *context)
{
    ksi_permission_task *task = context;
    task->status = KSI_STATUS_OK;
    if (permission_task_cancelled(task)) {
        task->status = KSI_STATUS_CANCELLED;
    } else if (task->kind == KSI_PERMISSION_CHECK) {
        ksp_identity verified;
        if (ksp_identity_revalidate_cached(&task->identity, &verified) != 0
            || ksp_store_check_at_generation(task->state->permissions, task->uid,
                task->identity.hash, KSI_INPUT_PERMISSION_SCOPES,
                &task->allowed, &task->store_generation) != 0) task->status = KSI_STATUS_DENIED;
    } else if (task->kind == KSI_PERMISSION_LIST) {
        permission_list_worker(task);
    } else if (task->kind == KSI_PERMISSION_REVOKE) {
        if (task->revoke.target_kind == KSI_PERMISSION_TARGET_PID) {
            ksp_identity identity;
            if (ksp_identity_capture((pid_t)task->revoke.pid, task->uid, &identity) != 0)
                task->status = KSI_STATUS_NOT_FOUND;
            else (void)snprintf(task->hash, sizeof(task->hash), "%s", identity.hash);
        }
        if (task->status == KSI_STATUS_OK && permission_task_cancelled(task)) task->status = KSI_STATUS_CANCELLED;
        if (task->status == KSI_STATUS_OK) {
            int result = task->revoke.target_kind == KSI_PERMISSION_TARGET_ALL
                ? ksp_store_revoke_uid(task->state->permissions, task->uid, task->revoke.scopes)
                : ksp_store_revoke(task->state->permissions, task->uid, task->hash, task->revoke.scopes);
            if (result != 0) task->status = KSI_STATUS_INTERNAL;
        }
    } else {
        for (size_t i = 0u; i < task->snapshot_count; i++) {
            ksi_permission_snapshot *snapshot = &task->snapshots[i];
            if (permission_task_cancelled(task)
                || ksp_store_check_at_generation(task->state->permissions, snapshot->uid,
                    snapshot->hash, KSI_INPUT_PERMISSION_SCOPES, &snapshot->allowed,
                    &snapshot->generation) != 0) {
                task->status = KSI_STATUS_UNAVAILABLE;
                break;
            }
        }
    }
    if (task->kind == KSI_PERMISSION_CHECK && permission_task_cancelled(task))
        task->status = KSI_STATUS_CANCELLED;
    if (task->kind == KSI_PERMISSION_LIST && hook_send_ref_is_valid(task->send_ref)) {
        uint8_t result[KSI_STATUS_PAYLOAD_SIZE];
        ksi_status_encode(result, task->status, KSI_DETAIL_NONE);
        if (!permission_send_list_frame(task, KSI_FRAME_FLAG_RESPONSE, result, sizeof(result)))
            hook_send_ref_invalidate(task->send_ref);
    }
    ksi_daemon_command command = {
        .type = KSI_DAEMON_COMMAND_PERMISSION_DONE,
        .client_fd = task->client_fd, .connection_id = task->connection_id,
        .data.permission = task,
    };
    if (!ksi_pipe_ring_push(&task->state->commands->ring, &command)) {
        if (task->send_ref != NULL) hook_send_ref_invalidate(task->send_ref);
        free_permission_task(task);
    }
    return NULL;
}

static ksi_permission_task *new_permission_task(ksi_daemon_state *state,
    ksi_client *client, ksi_permission_task_kind kind, uint64_t request_id)
{
    if (client != NULL && (client->permission_task != NULL
            || !hook_send_ref_acquire(client->hook_send_ref))) return NULL;
    ksi_permission_task *task = calloc(1u, sizeof(*task));
    if (task == NULL) {
        if (client != NULL) hook_send_ref_release(client->hook_send_ref);
        return NULL;
    }
    task->state = state;
    task->kind = kind;
    task->permission_generation = atomic_load(&state->permission_generation);
    task->input_generation = current_input_generation(state);
    task->deadline_ms = monotonic_ms() + KSI_PERMISSION_IO_TIMEOUT_MS;
    if (client != NULL) {
        task->send_ref = client->hook_send_ref;
        task->client_fd = client->fd;
        task->connection_id = client->connection_id;
        task->uid = client->uid;
        task->identity = client->identity;
        task->request_id = request_id;
    }
    return task;
}

static bool submit_permission_task(ksi_permission_task *task, ksi_client *client)
{
    if (task == NULL) return false;
    uint64_t deadline_ms = task->deadline_ms;
    if (!ksi_worker_pool_submit(&g_permission_worker_pool, permission_worker,
            free_permission_task, task)) {
        free_permission_task(task);
        return false;
    }
    if (client != NULL) {
        client->permission_task = task;
        client->permission_task_deadline_ms = deadline_ms;
    }
    return true;
}

static bool start_permission_check(ksi_daemon_state *state, ksi_client *client)
{
    ksi_permission_task *task = new_permission_task(state, client,
        KSI_PERMISSION_CHECK, client->pending_request_id);
    if (task != NULL) task->requested = client->pending_requested_scopes;
    client->pending_permission_generation = atomic_load(&state->permission_generation);
    return submit_permission_task(task, client);
}
