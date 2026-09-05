static void process_permission_done(ksi_daemon_state *state, ksi_permission_task *task)
{
    if (task == NULL) return;
    if (task->kind == KSI_PERMISSION_REFRESH) {
        state->permission_refresh_inflight = false;
        if (state->permission_monitor_failed) return;
        if (task->permission_generation != atomic_load(&state->permission_generation)) {
            if (!refresh_external_permissions(state)) permission_monitor_fail_open(state);
            return;
        }
        if (task->status != KSI_STATUS_OK) {
            permission_monitor_fail_open(state);
            return;
        }
        for (size_t i = 0u; i < task->snapshot_count; i++) {
            const ksi_permission_snapshot *snapshot = &task->snapshots[i];
            uint32_t revoked = 0u;
            for (nfds_t j = 0u; j < state->client_count; j++) {
                ksi_client *client = &state->clients[j];
                if (!client->has_identity || client->uid != snapshot->uid
                    || strcmp(client->exe_hash, snapshot->hash) != 0) continue;
                revoked |= client->granted_scopes & ~snapshot->allowed;
                client->permission_store_generation = snapshot->generation;
                client->permission_store_generation_valid = true;
            }
            if (revoked != 0u)
                invalidate_connected_permissions(state, snapshot->uid, snapshot->hash, false, revoked);
        }
        for (nfds_t i = 0u; i < state->client_count; i++) state->clients[i].permission_refresh_pending = false;
        if (update_grab_state(state) != 0) permission_monitor_fail_open(state);
        return;
    }

    /* Revocation affects other connections even if its requester has left. */
    if (task->kind == KSI_PERMISSION_REVOKE && task->status == KSI_STATUS_OK) {
        if (!fence_permission_output(state)) permission_monitor_fail_open(state);
        invalidate_connected_permissions(state, task->uid, task->hash,
            task->revoke.target_kind == KSI_PERMISSION_TARGET_ALL, task->revoke.scopes);
    }
    ssize_t index = find_client_index_by_connection(state, task->client_fd, task->connection_id);
    if (index < 0) return;
    ksi_client *client = &state->clients[index];
    if (client->permission_task != task) return;
    client->permission_task = NULL;
    if (!hook_send_ref_is_valid(client->hook_send_ref)) return;
    if (task->kind == KSI_PERMISSION_REVOKE) {
        const ksi_message_header request = { .opcode = KSI_OPCODE_PERMISSIONS_REVOKE, .request_id = task->request_id };
        send_status(client->fd, &request, task->status, KSI_DETAIL_NONE);
        return;
    }
    if (task->kind != KSI_PERMISSION_CHECK || !client->pending_authorization
        || client->pending_request_id != task->request_id) return;
    if (task->status != KSI_STATUS_OK || permission_task_cancelled(task)
        || state->permission_monitor_failed || state->permission_refresh_inflight) {
        client->pending_authorization = false;
        send_pending_authorization_status(client, KSI_STATUS_DENIED, KSI_DETAIL_NONE, 0u);
        return;
    }
    client->permission_store_generation = task->store_generation;
    client->permission_store_generation_valid = true;
    uint32_t granted = task->allowed & task->requested;
    uint32_t missing = task->requested & ~task->allowed;
    if (missing != 0u && client->pending_authorization_mode == KSI_AUTH_REQUEST) {
        if (start_prompt_task(state, client->hook_send_ref, state->commands, state->permissions,
                client->fd, client->connection_id, task->requested, missing,
                client->exe_path, client->exe_hash, client->pid, client->uid, client->start_time)) {
            client->state = KSI_CLIENT_STATE_AWAITING_PROMPT;
            return;
        }
        client->pending_authorization = false;
        send_pending_authorization_status(client, KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE, 0u);
        return;
    }
    if (granted != 0u && (client->connection_role != KSI_ROLE_OBSERVER_STREAM
            || (granted & KSP_SCOPE_INPUT_CONTROL) != 0u)) prepare_requested_scopes(state, granted);
    client->pending_authorization = false;
    finish_client_authorization(client, client->pending_authorization_opcode,
        client->pending_request_id, task->requested, granted);
}
