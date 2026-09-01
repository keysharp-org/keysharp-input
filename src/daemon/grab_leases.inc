static void send_status(
    int client_fd,
    const ksi_message_header *request,
    uint32_t status,
    uint32_t detail)
{
    uint8_t payload[KSI_STATUS_PAYLOAD_SIZE];

    ksi_protocol_encode_status(payload, status, detail);
    (void)ipc_send_locked(
        client_fd,
        request->opcode,
        KSI_FRAME_FLAG_RESPONSE,
        request->request_id,
        &payload,
        sizeof(payload));
}

static void send_hello_status(
    const ksi_client *client,
    uint64_t request_id,
    uint32_t status,
    uint32_t detail,
    uint32_t granted_scopes)
{
    uint8_t payload[KSI_HELLO_RESULT_PAYLOAD_SIZE];
    size_t payload_size;

    payload_size = ksi_protocol_encode_hello_result(
        payload,
        status,
        detail,
        granted_scopes,
        client->advertised_operations);
    (void)ipc_send_locked(
        client->fd,
        KSI_OPCODE_HELLO,
        KSI_FRAME_FLAG_RESPONSE,
        request_id,
        &payload,
        payload_size);
}

static void send_authorize_status(
    const ksi_client *client,
    uint64_t request_id,
    uint32_t status,
    uint32_t detail,
    uint32_t granted_scopes)
{
    uint8_t payload[KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE];
    size_t payload_size = ksi_protocol_encode_authorize_result(
        payload,
        status,
        detail,
        granted_scopes);

    (void)ipc_send_locked(client->fd, KSI_OPCODE_AUTHORIZE,
        KSI_FRAME_FLAG_RESPONSE, request_id, payload, payload_size);
}

static void send_authorization_status(
    const ksi_client *client,
    uint16_t opcode,
    uint64_t request_id,
    uint32_t status,
    uint32_t detail,
    uint32_t granted_scopes)
{
    if (opcode == KSI_OPCODE_AUTHORIZE) {
        send_authorize_status(client, request_id, status, detail,
            granted_scopes);
    } else {
        send_hello_status(client, request_id, status, detail,
            granted_scopes);
    }
}

static void send_pending_authorization_status(
    const ksi_client *client,
    uint32_t status,
    uint32_t detail,
    uint32_t granted_scopes)
{
    send_authorization_status(client, client->pending_authorization_opcode,
        client->pending_request_id, status, detail, granted_scopes);
}

static uint32_t client_persistent_allowed(const ksi_daemon_state *state, const ksi_client *client)
{
    uint32_t allowed = 0u;

    if (state == NULL || state->permission_monitor_failed) {
        return 0u;
    }
    if (ksp_store_check(state->permissions, client->uid, client->exe_hash,
            KSI_INPUT_PERMISSION_SCOPES, &allowed) != 0) {
        return 0u;
    }
    return allowed;
}

/* Returns scopes currently granted from the store without prompting.
 * Sets *out_missing to the durable permission scopes not yet granted. */
static uint32_t check_scopes_sync(
    ksi_daemon_state *state,
    ksi_client *client,
    uint32_t requested,
    uint32_t *out_missing)
{
    uint32_t granted = 0u;
    uint32_t missing = 0u;

    if (out_missing != NULL) {
        *out_missing = 0u;
    }

    if (state == NULL || client == NULL || requested == 0u) {
        return 0u;
    }

    if (!client->has_identity || state->permissions == NULL
        || state->permission_monitor_failed) {
        return 0u;
    }

    uint32_t allowed;
    uint64_t generation;

    if (ksp_store_check_at_generation(state->permissions,
            client->uid, client->exe_hash, requested,
            &allowed, &generation) != 0) {
        return 0u;
    }

    granted = requested & allowed;
    missing = requested & ~allowed;
    client->permission_store_generation = generation;
    client->permission_store_generation_valid = true;

    if (out_missing != NULL) {
        *out_missing = missing;
    }

    return granted;
}

static void finish_client_authorization(
    ksi_client *client,
    uint16_t opcode,
    uint64_t request_id,
    uint32_t requested,
    uint32_t granted)
{
    bool complete = requested == 0u || (granted & requested) == requested;

    client->granted_scopes |= granted;

    if (complete) {
        send_authorization_status(client, opcode, request_id, KSI_STATUS_OK,
            KSI_DETAIL_NONE, client->granted_scopes);
        return;
    }

    send_authorization_status(client, opcode, request_id, KSI_STATUS_DENIED,
        KSI_DETAIL_NONE, 0u);
}

/* A revoke is rare control-plane work. Clear cached privileges and active grab
 * state here so hook dispatch and synthesis checks remain memory-only. */
static void invalidate_connected_permissions(
    ksi_daemon_state *state,
    uid_t uid,
    const char *exe_hash,
    bool all_executables,
    uint32_t scopes)
{
    bool flush_keyboard = false;
    bool flush_mouse = false;
    bool grabs_changed = false;

    if (state == NULL || (!all_executables && exe_hash == NULL)) {
        return;
    }

    state->permission_generation++;

    if (state->permission_generation == 0u) {
        state->permission_generation = 1u;
    }

    for (nfds_t i = 0u; i < state->client_count; i++) {
        ksi_client *client = &state->clients[i];
        uint32_t old_grants;

        if (!client->has_identity || client->uid != uid
            || (!all_executables
                && strcmp(client->exe_hash, exe_hash) != 0)) {
            continue;
        }

        uint8_t notification[KSI_SESSION_REVOKED_PAYLOAD_SIZE];

        old_grants = client->granted_scopes;
        ksi_wire_write_u32(notification, scopes & old_grants);
        ksi_wire_write_u32(notification + 4u, 0u);
        if ((scopes & old_grants) != 0u) {
            (void)ipc_send_locked(client->fd, KSI_OPCODE_SESSION_REVOKED,
                KSI_FRAME_FLAG_EVENT, 0u, notification,
                sizeof(notification));
        }
        client->granted_scopes &= ~scopes;

        if ((scopes & KSP_SCOPE_INPUT_MONITORING) != 0u) {
            flush_keyboard = flush_keyboard
                || (old_grants & KSP_SCOPE_INPUT_MONITORING) != 0u
                || (client->hook_subscriptions & KSI_OPERATION_HOOK_KEYBOARD) != 0u;
            grabs_changed = grabs_changed
                || (client->hook_subscriptions & KSI_OPERATION_HOOK_KEYBOARD) != 0u;
            client->hook_subscriptions &=
                (uint32_t)~KSI_OPERATION_HOOK_KEYBOARD;
            client->hook_subscription_ordinal[0] = 0u;
            client->consecutive_hook_failures[0] = 0u;
            client->quarantined_hooks &=
                (uint32_t)~KSI_OPERATION_HOOK_KEYBOARD;
            client->quarantine_rearm_after_ms[0] = 0u;
            client->last_hook_quarantine_ms[0] = 0u;

            if (client->hook_send_ref != NULL) {
                hook_send_ref_clear_stalled(client->hook_send_ref, 0u);
            }
        }

        if ((scopes & KSP_SCOPE_INPUT_MONITORING) != 0u) {
            flush_mouse = flush_mouse
                || (old_grants & KSP_SCOPE_INPUT_MONITORING) != 0u
                || (client->hook_subscriptions & KSI_OPERATION_HOOK_MOUSE) != 0u;
            grabs_changed = grabs_changed
                || (client->hook_subscriptions & KSI_OPERATION_HOOK_MOUSE) != 0u;
            client->hook_subscriptions &=
                (uint32_t)~KSI_OPERATION_HOOK_MOUSE;
            client->hook_subscription_ordinal[1] = 0u;
            client->consecutive_hook_failures[1] = 0u;
            client->quarantined_hooks &=
                (uint32_t)~KSI_OPERATION_HOOK_MOUSE;
            client->quarantine_rearm_after_ms[1] = 0u;
            client->last_hook_quarantine_ms[1] = 0u;

            if (client->hook_send_ref != NULL) {
                hook_send_ref_clear_stalled(client->hook_send_ref, 1u);
            }
        }

        if ((scopes & KSP_SCOPE_INPUT_CONTROL) != 0u
            && client->block_input_mask != 0u) {
            client->block_input_mask = 0u;
            grabs_changed = true;
        }

        if (client->hook_subscriptions == 0u && client->block_input_mask == 0u) {
            client->lease_expires_ms = 0u;
        }

        /* A hook reader otherwise has no deterministic way to distinguish a
         * live but unsubscribed stream from a revoked one. Invalidating its
         * transport wakes the reader and every retained lane snapshot now;
         * ordinary control connections stay open so independently retained
         * Input Control operations remain usable. */
        if ((scopes & KSP_SCOPE_INPUT_MONITORING) != 0u
            && client->connection_role == KSI_ROLE_CALLBACK_STREAM) {
            hook_send_ref_invalidate(client->hook_send_ref);
        }
    }

    if (flush_keyboard) {
        lane_flush_passthrough(&state->keyboard_lane);
    }

    if (flush_mouse) {
        lane_flush_passthrough(&state->mouse_lane);
    }

    if (grabs_changed && update_grab_state(state) != 0) {
        fprintf(stderr,
            "keysharp-input: failed to release grabs after permission revocation\n");
    }
}

/* Refreshes after an inotify edge from the shared control-plane directory.
 * There is no timer-driven permission I/O on the physical-input poll path. */
static bool refresh_external_permissions(ksi_daemon_state *state)
{
    if (state == NULL || state->permissions == NULL) {
        return false;
    }

    for (nfds_t uid_index = 0u; uid_index < state->client_count; uid_index++) {
        ksi_client *uid_client = &state->clients[uid_index];
        uint64_t generation;

        if (!uid_client->has_identity) {
            continue;
        }

        bool uid_already_checked = false;

        for (nfds_t prior = 0u; prior < uid_index; prior++) {
            ksi_client *other = &state->clients[prior];

            if (other->has_identity && other->uid == uid_client->uid) {
                uid_already_checked = true;
                break;
            }
        }

        if (uid_already_checked) {
            continue;
        }
        if (ksp_store_generation(state->permissions, uid_client->uid,
                &generation) != 0) {
            return false;
        }

        for (nfds_t identity_index = uid_index;
             identity_index < state->client_count; identity_index++) {
            ksi_client *identity_client = &state->clients[identity_index];
            uint32_t revoked = 0u;
            uint32_t allowed = 0u;

            if (!identity_client->has_identity
                || identity_client->uid != uid_client->uid) {
                continue;
            }

            bool identity_already_checked = false;

            for (nfds_t prior = uid_index; prior < identity_index; prior++) {
                ksi_client *other = &state->clients[prior];

                if (other->has_identity && other->uid == identity_client->uid
                    && strcmp(other->exe_hash, identity_client->exe_hash) == 0) {
                    identity_already_checked = true;
                    break;
                }
            }

            if (identity_already_checked) {
                continue;
            }

            bool changed = false;

            for (nfds_t current = identity_index;
                 current < state->client_count; current++) {
                ksi_client *matching = &state->clients[current];

                if (!matching->has_identity
                    || matching->uid != identity_client->uid
                    || strcmp(matching->exe_hash,
                              identity_client->exe_hash) != 0) {
                    continue;
                }

                changed = changed
                    || (matching->permission_store_generation_valid
                        && matching->permission_store_generation != generation);
            }

            if (changed) {
                allowed = client_persistent_allowed(state, identity_client);
            }

            for (nfds_t current = identity_index;
                 current < state->client_count; current++) {
                ksi_client *matching = &state->clients[current];

                if (!matching->has_identity
                    || matching->uid != identity_client->uid
                    || strcmp(matching->exe_hash,
                              identity_client->exe_hash) != 0) {
                    continue;
                }

                matching->permission_store_generation = generation;
                matching->permission_store_generation_valid = true;

                if (changed) {
                    revoked |= matching->granted_scopes & ~allowed;
                }
            }

            if (!changed) {
                continue;
            }

            if (revoked != 0u) {
                invalidate_connected_permissions(state, identity_client->uid,
                    identity_client->exe_hash, false, revoked);
            } else {
                /* Even a revoke in another capability domain fences an input
                 * authorization which began before that explicit user action. */
                state->permission_generation++;

                if (state->permission_generation == 0u) {
                    state->permission_generation = 1u;
                }
            }
        }
    }

    return true;
}

static bool is_permission_generation_event(const char *name)
{
    unsigned long uid;
    char trailing;

    return name != NULL
        && sscanf(name, "revoke-%lu.generation%c", &uid, &trailing) == 1;
}

static void permission_monitor_close(ksi_daemon_state *state)
{
    if (state == NULL) {
        return;
    }
    if (state->permission_notify_fd >= 0
        && state->permission_notify_watch >= 0) {
        (void)inotify_rm_watch(
            state->permission_notify_fd, state->permission_notify_watch);
    }
    if (state->permission_notify_fd >= 0) {
        close(state->permission_notify_fd);
    }
    state->permission_notify_fd = -1;
    state->permission_notify_watch = -1;
}

static void permission_monitor_fail_open(ksi_daemon_state *state)
{
    uint64_t input_generation;

    if (state == NULL || state->permission_monitor_failed) {
        return;
    }

    state->permission_monitor_failed = true;
    permission_monitor_close(state);
    input_generation = advance_input_generation(state);

    for (nfds_t index = 0u; index < state->client_count; index++) {
        ksi_client *client = &state->clients[index];
        bool already_invalidated = false;

        client->permission_store_generation_valid = false;

        if (!client->has_identity) {
            client->granted_scopes &= ~KSI_INPUT_PERMISSION_SCOPES;
            continue;
        }
        for (nfds_t prior = 0u; prior < index; prior++) {
            ksi_client *other = &state->clients[prior];
            if (other->has_identity && other->uid == client->uid
                && strcmp(other->exe_hash, client->exe_hash) == 0) {
                already_invalidated = true;
                break;
            }
        }
        if (!already_invalidated) {
            invalidate_connected_permissions(
                state, client->uid, client->exe_hash, false,
                KSI_INPUT_PERMISSION_SCOPES);
        }
    }

    /* Also fences a pending prompt when no identified client had a grant. */
    state->permission_generation++;
    if (state->permission_generation == 0u) {
        state->permission_generation = 1u;
    }
    clear_hook_state(state);
    output_queue_wait_for_inflight(&state->output_queue);
    output_queue_discard_stale(&state->output_queue, input_generation);
    if (state->output_queue.mutex_initialized
        && !output_queue_push_release_all(&state->output_queue)) {
        fprintf(stderr,
            "keysharp-input: failed to enqueue release-all after permission monitor failure\n");
    }
    if (update_grab_state(state) != 0) {
        fprintf(stderr,
            "keysharp-input: failed to release grabs after permission monitor failure\n");
    }
}

static int permission_monitor_init(ksi_daemon_state *state)
{
    const char *runtime_directory;
    uint32_t mask = IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE
        | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT
        | IN_ONLYDIR | IN_DONT_FOLLOW;

    if (state == NULL || state->permissions == NULL
        || (runtime_directory = ksp_store_runtime_directory(
                state->permissions)) == NULL) {
        return -1;
    }
    state->permission_notify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (state->permission_notify_fd < 0) {
        return -1;
    }
    state->permission_notify_watch = inotify_add_watch(
        state->permission_notify_fd, runtime_directory, mask);
    if (state->permission_notify_watch < 0) {
        permission_monitor_close(state);
        return -1;
    }
    return 0;
}

static void process_permission_notifications(
    ksi_daemon_state *state,
    short revents)
{
    union {
        struct inotify_event alignment;
        unsigned char bytes[16384];
    } buffer;
    bool refresh = false;

    if (state == NULL || state->permission_monitor_failed) {
        return;
    }
    if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        permission_monitor_fail_open(state);
        return;
    }

    for (;;) {
        ssize_t length = read(state->permission_notify_fd,
            buffer.bytes, sizeof(buffer.bytes));
        size_t offset = 0u;

        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            permission_monitor_fail_open(state);
            return;
        }
        if (length == 0) {
            permission_monitor_fail_open(state);
            return;
        }

        while (offset + sizeof(struct inotify_event) <= (size_t)length) {
            const struct inotify_event *event =
                (const struct inotify_event *)(const void *)(buffer.bytes + offset);
            size_t event_size = sizeof(*event) + event->len;

            if (event_size > (size_t)length - offset) {
                permission_monitor_fail_open(state);
                return;
            }
            if ((event->mask & (IN_Q_OVERFLOW | IN_IGNORED | IN_DELETE_SELF
                    | IN_MOVE_SELF | IN_UNMOUNT)) != 0u) {
                permission_monitor_fail_open(state);
                return;
            }
            if (event->len != 0u
                && is_permission_generation_event(event->name)) {
                if ((event->mask & IN_DELETE) != 0u) {
                    permission_monitor_fail_open(state);
                    return;
                }
                refresh = true;
            }
            offset += event_size;
        }
        if (offset != (size_t)length) {
            permission_monitor_fail_open(state);
            return;
        }
    }

    if (refresh && !refresh_external_permissions(state)) {
        permission_monitor_fail_open(state);
    }
}

/* Applies a completed prompt decision and sends its authorization response. */
static void process_client_prompt_done(ksi_daemon_state *state, ksi_daemon_command *command)
{
    ssize_t client_index;
    ksi_client *client;
    ksp_polkit_result decision;
    uint32_t requested;
    uint32_t missing;
    uint32_t granted;

    if (state == NULL || command == NULL) {
        return;
    }

    client_index = find_client_index_by_connection(
        state, command->client_fd, command->connection_id);

    if (client_index < 0) {
        free_daemon_command(command);
        return;
    }

    client = &state->clients[client_index];
    client->state = KSI_CLIENT_STATE_READY;

    if (!client->pending_authorization) {
        free_daemon_command(command);
        return;
    }

    client->pending_authorization = false;

    if (!input_owner_matches_uid(state, client->uid)) {
        send_pending_authorization_status(client, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE, 0u);
        free_daemon_command(command);
        return;
    }

    decision = command->data.prompt_done.decision;
    requested = command->data.prompt_done.requested_scopes
        & KSI_INPUT_PERMISSION_SCOPES;
    missing = command->data.prompt_done.missing_scopes
        & KSI_INPUT_PERMISSION_SCOPES;

    if (client->pending_permission_generation
        != state->permission_generation) {
        decision = KSP_POLKIT_DENIED;
    }

    if (decision == KSP_POLKIT_GRANTED && missing != 0u) {
        ksp_identity identity = {
            .uid = client->uid,
            .pid = client->pid,
            .start_time = client->start_time,
        };
        (void)snprintf(identity.executable, sizeof(identity.executable),
            "%s", client->exe_path);
        (void)snprintf(identity.hash, sizeof(identity.hash),
            "%s", client->exe_hash);
        int grant_result = ksp_store_grant_if_generation(
            state->permissions, &identity, missing,
            command->data.prompt_done.store_generation);

        if (grant_result != 0) {
            decision = grant_result > 0
                ? KSP_POLKIT_DENIED : KSP_POLKIT_UNAVAILABLE;
        }
    }

    granted = requested & client_persistent_allowed(state, client);

    if (decision != KSP_POLKIT_GRANTED) {
        client->granted_scopes |= granted;
        send_pending_authorization_status(client, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE, 0u);
        free_daemon_command(command);
        return;
    }

    finish_client_authorization(client,
        client->pending_authorization_opcode,
        client->pending_request_id,
            requested,
            granted);
    free_daemon_command(command);
}
/* Stores the identification result and resumes pending authorization. */
static void process_client_identified(ksi_daemon_state *state, ksi_daemon_command *command)
{
    ssize_t client_index;
    ksi_client *client;
    ksi_client_identified_result *result;

    if (state == NULL || command == NULL) {
        return;
    }

    result = command->data.identified.result;
    client_index = find_client_index_by_connection(
        state,
        command->client_fd,
        command->connection_id);

    if (client_index < 0) {
        return;
    }

    client = &state->clients[client_index];

    if (!input_owner_matches_uid(state, client->uid)) {
        client->state = KSI_CLIENT_STATE_READY;

        if (client->pending_authorization) {
            client->pending_authorization = false;
            send_pending_authorization_status(client, KSI_STATUS_DENIED,
                KSI_DETAIL_NONE, 0u);
        }

        return;
    }

    /* A changed start time means the pid was recycled while identity was read. */
    if (result != NULL && result->has_identity
        && (result->start_time == 0u || client->start_time == 0u
            || result->start_time != client->start_time)) {
        fprintf(stderr,
            "keysharp-input: rejecting identity for client pid=%ld: process start time changed "
            "between accept and identify (pid recycled)\n", (long)client->pid);
        result = NULL;
    }

    if (result != NULL && result->has_identity) {
        client->has_identity = true;
        client->start_time = result->start_time;
        (void)snprintf(client->exe_path, sizeof(client->exe_path), "%s", result->exe_path);
        (void)snprintf(client->exe_hash, sizeof(client->exe_hash), "%s", result->exe_hash);

        if (g_verbose) {
            printf("identified client fd=%d hash=%s path=%s\n",
                client->fd, client->exe_hash, client->exe_path);
        }
    } else {
        client->has_identity = false;
        fprintf(stderr, "keysharp-input: unable to identify process for client pid=%ld uid=%ld\n",
            (long)client->pid, (long)client->uid);
    }

    client->state = KSI_CLIENT_STATE_READY;

    if (!client->pending_authorization) {
        return;
    }

    /* Resume the request that waited for identity. */
	{
        uint32_t requested = client->pending_requested_scopes;
        uint32_t authorization_mode = client->pending_authorization_mode;
		uint32_t missing = 0u;
		uint32_t granted;

        prepare_requested_scopes(state, requested);
        granted = check_scopes_sync(state, client, requested, &missing);

        if (missing != 0u && state->permissions != NULL
            && !state->permission_monitor_failed
            && authorization_mode == KSI_AUTH_REQUEST) {
            /* Need to prompt. Transition to AWAITING_PROMPT and start the worker. */
            client->pending_permission_generation =
                state->permission_generation;
            if (!start_prompt_task(state->commands, state->permissions,
                                   client->fd, client->connection_id, requested, missing,
                                   client->exe_path, client->exe_hash,
                                   client->pid, client->uid, client->start_time)) {
                /* Prompt thread failed; deny immediately. */
                client->pending_authorization = false;
                client->state = KSI_CLIENT_STATE_READY;
                send_pending_authorization_status(client, KSI_STATUS_UNAVAILABLE,
                    KSI_DETAIL_NONE, 0u);
            } else {
                client->state = KSI_CLIENT_STATE_AWAITING_PROMPT;
            }
            return;
        }

        /* No prompt needed — grant immediately. */
        client->pending_authorization = false;

        finish_client_authorization(client,
            client->pending_authorization_opcode, client->pending_request_id,
            requested, granted);
    }
}

static uint64_t daemon_available_operations(const ksi_platform_backend *backend)
{
    if (backend->get_available_operations != NULL) {
        return backend->get_available_operations();
    }

    return 0;
}

static void prepare_requested_scopes(ksi_daemon_state *state, uint32_t requested)
{
    if (state == NULL || state->backend == NULL || requested == 0u) {
        return;
    }

    if (state->backend->prepare_scopes != NULL) {
        state->backend->prepare_scopes(requested);
    }

    state->available_operations = daemon_available_operations(state->backend);
    state->ready_operations = state->backend->get_ready_operations != NULL
        ? state->backend->get_ready_operations()
        : state->available_operations;
}

static bool client_has_scope(const ksi_client *client, uint32_t scope)
{
    if (!client->hello_complete)
        return false;
    return (client->granted_scopes & scope) == scope;
}

static uint32_t hook_type_to_operation(uint32_t hook_type)
{
    if (hook_type == KSI_HOOK_KEYBOARD) {
        return (uint32_t)KSI_OPERATION_HOOK_KEYBOARD;
    }

    if (hook_type == KSI_HOOK_MOUSE) {
        return (uint32_t)KSI_OPERATION_HOOK_MOUSE;
    }

    return 0;
}


static uint32_t active_hook_subscription_mask(const ksi_daemon_state *state)
{
    uint32_t mask = 0;

    if (state == NULL) {
        return 0;
    }

    for (nfds_t i = 0; i < state->client_count; i++) {
        if (input_owner_matches_uid(state, state->clients[i].uid)) {
            mask |= state->clients[i].hook_subscriptions
                & (uint32_t)~state->clients[i].quarantined_hooks;
        }
    }

    return mask;
}

static uint32_t active_block_input_mask(const ksi_daemon_state *state)
{
    uint32_t mask = 0;

    if (state == NULL) {
        return 0;
    }

    for (nfds_t i = 0; i < state->client_count; i++) {
        if (input_owner_matches_uid(state, state->clients[i].uid)) {
            mask |= state->clients[i].block_input_mask;
        }
    }

    return mask;
}

static bool any_matching_hook_subscriptions(const ksi_daemon_state *state, uint32_t hook_type)
{
    uint32_t subscription_bit;

    if (state == NULL) {
        return false;
    }

    subscription_bit = hook_type_to_operation(hook_type);

    if (subscription_bit == 0) {
        return false;
    }

    for (nfds_t i = 0; i < state->client_count; i++) {
        if ((state->clients[i].hook_subscriptions & subscription_bit) != 0
            && (state->clients[i].quarantined_hooks & subscription_bit) == 0u
            && input_owner_matches_uid(state, state->clients[i].uid)) {
            return true;
        }
    }

    return false;
}

static int update_grab_state(ksi_daemon_state *state)
{
    uint32_t hook_mask = active_hook_subscription_mask(state);
    uint32_t block_mask = active_block_input_mask(state);
    uint64_t ready;
    uint32_t effective_hook_mask;
    bool keyboard_grabbed;
    bool interception_active;
    int result;

    if (state == NULL || state->backend == NULL) {
        return 0;
    }

    /* Fail open when synthetic output is unavailable. A HOOK grab EVIOCGRAB's the
     * physical device and relies on the synth device to replay every passed event;
     * if that output is dead (write failure, torn-down uinput) an already-grabbed
     * keyboard/mouse would stay captured while every replay write() fails -- a
     * fully dead device. Mask the hook portion of the grab by the operations
     * the backend can currently honor: when synth is down, get_available_
     * readiness drops hook operations and the grab is released, letting raw
     * hardware pass through. The next update_grab_state (re-run by
     * run_backend_maintenance on the availability-change edge) restores the real
     * mask once synth recovers. Input blocking is not gated this way:
     * blocking only drops events and needs no synth, so its grab must persist. */
    ready = state->backend->get_ready_operations != NULL
        ? state->backend->get_ready_operations()
        : KSI_OPERATION_ALL;
    effective_hook_mask = hook_mask & (uint32_t)ready;
    interception_active = effective_hook_mask != 0u || block_mask != 0u;

    /* Idle tracking is an ordinary read-only observer and must not preempt the
     * desktop at SCHED_FIFO priority. Promote the main reader immediately before
     * an interception grab can be acquired; demote it after all grabs are gone. */
    if (interception_active && !state->reader_realtime) {
        state->reader_realtime = set_realtime_priority("evdev reader");
    }

    /* Page locking is valuable only while grabbed input depends on this
     * process meeting hook deadlines. Do not reserve resident memory for the
     * boot-time idle observer. */
    if (interception_active && !state->memory_locked) {
        if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
            state->memory_locked = true;
        } else {
            fprintf(stderr,
                "keysharp-input: note: mlockall failed (%s); hook latency may degrade under "
                "memory pressure\n", strerror(errno));
        }
    }

    result = state->backend->set_grab_hook_mask == NULL
        ? 0
        : state->backend->set_grab_hook_mask(effective_hook_mask);

    if (result != 0) {
        return result;
    }

    /* Platforms without input-blocking support must not advertise the operation.
     * If a non-zero block mask somehow arrives on such a platform, fail so that
     * handle_set_block_input rolls back and reports an error rather than silently
     * accepting a mask that cannot be enforced. */
    result = state->backend->set_block_input_mask == NULL
        ? (block_mask == 0 ? 0 : -1)
        : state->backend->set_block_input_mask(block_mask);

    if (result != 0) {
        return result;
    }

    state->interception_active = interception_active;

    /* When the keyboard grab is released, any key the daemon replayed "down" on the
     * uinput virtual device would be stranded there: the user's physical key-up lands
     * on the now-ungrabbed real device and does not cancel the uinput key, so the
     * compositor keeps seeing it held. Enqueue the release on the OUTPUT SEQUENCER
     * thread (not here) so it is serialized with replay/synth -- no race on the synth
     * state -- and the daemon main thread never blocks doing it. Fires only on the
     * held->released edge so a steady grab does not repeatedly release. */
    /* Use the EFFECTIVE hook mask (post fail-open) so the held->released edge
     * fires -- and the stranded-key RELEASE_ALL below runs -- when a dead synth
     * drops the keyboard grab, not only on a client unsubscribe. */
    keyboard_grabbed = (effective_hook_mask & KSI_OPERATION_HOOK_KEYBOARD) != 0
        || (block_mask & KSI_BLOCK_KEYBOARD) != 0;

    if (state->keyboard_grab_active && !keyboard_grabbed) {
        /* Only consume the held->released edge once the release is actually queued.
         * If the enqueue fails (queue saturated / OOM), leave keyboard_grab_active set
         * so the next update_grab_state call -- there are many callers and the queue
         * drains continuously -- retries, rather than stranding a key "down" on uinput
         * with no recovery until the next grab cycle. */
        if (output_queue_push_release_all(&state->output_queue)) {
            state->keyboard_grab_active = false;
        } else {
            fprintf(stderr, "keysharp-input: failed to enqueue synthetic key release on keyboard ungrab; will retry\n");
        }
    } else {
        state->keyboard_grab_active = keyboard_grabbed;
    }

    if (!interception_active && state->reader_realtime) {
        if (set_normal_priority("evdev reader")) {
            state->reader_realtime = false;
        }
    }

    if (!interception_active && state->memory_locked) {
        if (munlockall() == 0) {
            state->memory_locked = false;
        } else {
            fprintf(stderr, "keysharp-input: note: munlockall failed: %s\n", strerror(errno));
        }
    }

    return 0;
}

static void clear_hook_state(ksi_daemon_state *state)
{
    if (state == NULL) {
        return;
    }

    lane_flush_passthrough(&state->keyboard_lane);
    lane_flush_passthrough(&state->mouse_lane);
    synthetic_hook_queue_abort(&state->synthetic_hook_queue);

    for (nfds_t i = 0; i < state->client_count; i++) {
        state->clients[i].hook_subscriptions = 0;
        state->clients[i].hook_subscription_ordinal[0] = 0u;
        state->clients[i].hook_subscription_ordinal[1] = 0u;
        state->clients[i].block_input_mask = 0;
        state->clients[i].consecutive_hook_failures[0] = 0;
        state->clients[i].consecutive_hook_failures[1] = 0;
        state->clients[i].lease_expires_ms = 0u;
    }
}

static void renew_client_lease(ksi_client *client)
{
    if (client == NULL) {
        return;
    }

    if (client->hook_subscriptions != 0u || client->block_input_mask != 0u) {
        client->lease_expires_ms = monotonic_ms() + KSI_GRAB_LEASE_TIMEOUT_MS;
    } else {
        client->lease_expires_ms = 0u;
    }
}

static void expire_client_leases(ksi_daemon_state *state)
{
    uint64_t now;

    if (state == NULL) {
        return;
    }

    now = monotonic_ms();

    for (nfds_t i = state->client_count; i > 0; i--) {
        nfds_t index = i - 1u;
        ksi_client *client = &state->clients[index];
        if (client->lease_expires_ms == 0u || now < client->lease_expires_ms) {
            continue;
        }

        /* A switched-away user's stored hook state is deliberately dormant,
         * not abandoned. Pause its lease while logind says another uid owns
         * seat0; refresh it when that uid becomes active again. */
        if (!input_owner_matches_uid(state, client->uid)) {
            continue;
        }

        fprintf(stderr,
            "keysharp-input: client fd=%d grab lease expired; failing open and disconnecting\n",
            client->fd);

        remove_client(state, index);
    }
}

/* Drops connections that never completed HELLO within the handshake
 * window. A peer that connects and sends nothing otherwise keeps its slot forever
 * (leases arm only for hook/block clients), so N such peers could exhaust the
 * client table and deny the broker to everyone. Authenticated idle clients (e.g. a
 * query connection that sent a zero-scope hello) completed HELLO and are kept. */
static void expire_unauthenticated_clients(ksi_daemon_state *state)
{
    uint64_t now;

    if (state == NULL) {
        return;
    }

    now = monotonic_ms();

    for (nfds_t i = state->client_count; i > 0; i--) {
        nfds_t index = i - 1u;
        ksi_client *client = &state->clients[index];

        /* Capless-idle reaper: an authenticated connection holding no grants and
         * no hook/block subscriptions, idle past the timeout, is dropped so it
         * cannot pin a per-uid slot forever. Guarded on idle ready state so
         * a client mid-identify or mid-prompt is never reaped; any message resets
         * last_activity_ms, so a live query channel that polls is kept. */
        if (client->hello_complete
            && client->state == KSI_CLIENT_STATE_READY
            && !client->pending_authorization
            && client->granted_scopes == 0u
            && client->hook_subscriptions == 0u
            && client->block_input_mask == 0u
            && client->last_activity_ms != 0u
            && now >= client->last_activity_ms + KSI_CAPLESS_IDLE_TIMEOUT_MS) {
            fprintf(stderr,
                "keysharp-input: dropping client fd=%d: scope-less and idle for %u ms\n",
                client->fd, (unsigned)KSI_CAPLESS_IDLE_TIMEOUT_MS);
            remove_client(state, index);
            continue;
        }

        if (client->hello_complete || client->connected_at_ms == 0u
            || now < client->connected_at_ms + KSI_HANDSHAKE_TIMEOUT_MS) {
            continue;
        }

        fprintf(stderr,
            "keysharp-input: dropping client fd=%d: no HELLO within %u ms\n",
            client->fd, (unsigned)KSI_HANDSHAKE_TIMEOUT_MS);
        remove_client(state, index);
    }
}

static void apply_fail_open_if_requested(ksi_daemon_state *state)
{
    if (state == NULL || atomic_exchange(&g_fail_open_requested, 0) == 0) {
        return;
    }

    fprintf(stderr,
        "keysharp-input: safety-critical command queue overflow; clearing hooks and BlockInput\n");
    clear_hook_state(state);

    if (update_grab_state(state) != 0) {
        fprintf(stderr, "keysharp-input: failed to release grabs during fail-open recovery\n");
    }
}

static void record_client_hook_success(ksi_daemon_state *state, nfds_t index, uint32_t hook_type)
{
    ksi_client *client;
    size_t lane_index;

    if (state == NULL || index >= state->client_count) {
        return;
    }

    client = &state->clients[index];

    if (!input_owner_matches_uid(state, client->uid)) {
        return;
    }
    lane_index = hook_type_to_lane_index(hook_type);

    if (client->last_hook_quarantine_ms[lane_index] != 0u
        && monotonic_ms() >= client->last_hook_quarantine_ms[lane_index] + 60000u) {
        client->consecutive_hook_failures[lane_index] = 0u;
    }
}

static void retry_quarantined_hooks(ksi_daemon_state *state)
{
    uint64_t now = monotonic_ms();
    bool changed = false;

    if (state == NULL) {
        return;
    }

    for (nfds_t i = 0u; i < state->client_count; i++) {
        ksi_client *client = &state->clients[i];

        for (size_t lane = 0u; lane < 2u; lane++) {
            uint32_t bit = lane == 0u
                ? (uint32_t)KSI_OPERATION_HOOK_KEYBOARD
                : (uint32_t)KSI_OPERATION_HOOK_MOUSE;

            if ((client->quarantined_hooks & bit) == 0u
                || client->quarantine_rearm_after_ms[lane] == 0u
                || now < client->quarantine_rearm_after_ms[lane]) {
                continue;
            }

            client->quarantined_hooks &= ~bit;
            client->quarantine_rearm_after_ms[lane] = 0u;
            hook_send_ref_clear_stalled(client->hook_send_ref, lane);
            changed = true;
        }
    }

    if (changed && update_grab_state(state) != 0) {
        fprintf(stderr, "keysharp-input: failed to restore grabs after hook retry\n");
    }
}

static void record_client_hook_failure(
    ksi_daemon_state *state, nfds_t index, uint32_t hook_type,
    uint64_t event_id, uint32_t nesting_depth, uint32_t elapsed_ms,
    uint32_t reason)
{
    ksi_client *client;
    size_t lane_index;
    uint32_t lane_bit;
    uint32_t retry_after_ms;
    uint64_t now;
    ksi_hook_quarantined_payload notification;
    uint8_t wire_notification[KSI_HOOK_QUARANTINED_PAYLOAD_SIZE];

    if (state == NULL || index >= state->client_count) {
        return;
    }

    client = &state->clients[index];

    if (!input_owner_matches_uid(state, client->uid)) {
        return;
    }

    lane_index = hook_type_to_lane_index(hook_type);
    lane_bit = (lane_index == 1u)
        ? (uint32_t)KSI_OPERATION_HOOK_MOUSE
        : (uint32_t)KSI_OPERATION_HOOK_KEYBOARD;

    if ((client->hook_subscriptions & lane_bit) == 0u
        || (client->quarantined_hooks & lane_bit) != 0u) {
        return;
    }

    now = monotonic_ms();

    if (client->last_hook_quarantine_ms[lane_index] != 0u
        && now >= client->last_hook_quarantine_ms[lane_index] + 60000u) {
        client->consecutive_hook_failures[lane_index] = 0u;
    }

    client->consecutive_hook_failures[lane_index]++;
    client->last_hook_quarantine_ms[lane_index] = now;
    client->quarantined_hooks |= lane_bit;
    hook_send_ref_mark_stalled(client->hook_send_ref, lane_index);
    retry_after_ms = 1000u << (client->consecutive_hook_failures[lane_index] > 5u
        ? 4u
        : client->consecutive_hook_failures[lane_index] - 1u);
    client->quarantine_rearm_after_ms[lane_index] = now + retry_after_ms;

    fprintf(stderr,
        "keysharp-input: hook quarantined pid=%ld fd=%d hook=%u event=%llu depth=%u "
        "elapsed=%ums reason=%s strike=%u retry=%ums\n",
        (long)client->pid, client->fd, hook_type,
        (unsigned long long)event_id, nesting_depth, elapsed_ms,
        reason == KSI_HOOK_QUARANTINE_TIMEOUT ? "timeout" : "transport",
        client->consecutive_hook_failures[lane_index], retry_after_ms);

    memset(&notification, 0, sizeof(notification));
    notification.hook_type = hook_type;
    notification.reason = reason;
    notification.event_id = event_id;
    notification.generation = 0u;
    notification.strike_count = client->consecutive_hook_failures[lane_index];
    notification.retry_after_ms = retry_after_ms;

    (void)ksi_protocol_encode_hook_quarantined(
        wire_notification, &notification);
    (void)ipc_send_locked(client->fd, KSI_OPCODE_HOOK_QUARANTINED,
        KSI_FRAME_FLAG_EVENT, 0u, wire_notification,
        sizeof(wire_notification));

    if (update_grab_state(state) != 0) {
        fprintf(stderr, "keysharp-input: failed to update grabs after hook quarantine\n");
    }

    if (client->consecutive_hook_failures[lane_index] < KSI_MAX_CONSECUTIVE_HOOK_FAILURES) {
        return;
    }

    fprintf(stderr,
        "keysharp-input: invalidating hook session pid=%ld fd=%d after %u consecutive %s timeouts\n",
        (long)client->pid, client->fd, KSI_MAX_CONSECUTIVE_HOOK_FAILURES,
        lane_index == 1u ? "mouse" : "keyboard");

    remove_client(state, index);
}

/* Constructs a ksi_lane_event snapshotting the current hook subscribers and
 * pushes it onto the matching lane's action queue.  If allocation or enqueue
 * fails, the event is dropped; replaying it would violate the hook contract by
 * turning a backpressured hooked key into delayed text later.
 *
 * Called only from the main thread (via daemon_handle_hook_event from the
 * platform backend).  Reads state->clients[] without locking — that array is
 * owned by the main thread. */
