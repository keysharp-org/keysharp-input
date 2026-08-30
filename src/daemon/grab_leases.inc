static void send_status(
    int client_fd,
    const ksi_message_header *request,
    uint32_t response_type,
    int32_t status,
    uint32_t detail)
{
    ksi_status_payload payload = {
        .status = status,
        .detail = detail,
    };

    (void)ipc_send_locked(
        client_fd,
        response_type,
        request->client_id,
        request->correlation_id,
        &payload,
        sizeof(payload));
}

static void send_hello_status(
    const ksi_client *client,
    uint32_t client_id,
    uint64_t correlation_id,
    int32_t status,
    uint32_t granted_capabilities)
{
    ksi_client_hello_result_payload payload = {
        .status = status,
        .granted_capabilities = granted_capabilities,
    };

    (void)ipc_send_locked(
        client->fd,
        KSI_MESSAGE_CLIENT_HELLO,
        client_id,
        correlation_id,
        &payload,
        sizeof(payload));
}

static uint32_t permission_scopes_for_operations(uint32_t operations)
{
    uint32_t scopes = 0u;

    if ((operations & (KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE)) != 0u) {
        scopes |= KSP_SCOPE_INPUT_MONITORING;
    }
    if ((operations & (KSI_CAP_SYNTH_KEYBOARD | KSI_CAP_SYNTH_MOUSE
            | KSI_CAP_BLOCK_INPUT)) != 0u) {
        scopes |= KSP_SCOPE_INPUT_CONTROL;
    }
    return scopes;
}

static uint32_t operations_allowed_by_scopes(
    uint32_t operations, uint32_t scopes)
{
    uint32_t allowed = 0u;

    if ((scopes & KSP_SCOPE_INPUT_MONITORING) != 0u) {
        allowed |= operations & (KSI_CAP_HOOK_KEYBOARD | KSI_CAP_HOOK_MOUSE);
    }
    if ((scopes & KSP_SCOPE_INPUT_CONTROL) != 0u) {
        allowed |= operations & (KSI_CAP_SYNTH_KEYBOARD | KSI_CAP_SYNTH_MOUSE
            | KSI_CAP_BLOCK_INPUT);
    }
    return allowed;
}

static uint32_t client_persistent_allowed(const ksi_daemon_state *state, const ksi_client *client)
{
    if (state == NULL || state->permission_monitor_failed) {
        return 0u;
    }
    return ksi_auth_store_get_allowed(
        state->permissions, client->uid, client->exe_hash);
}

/* Returns the capabilities currently granted from the store without prompting.
 * Sets *out_missing to the durable permission scopes not yet granted. */
static uint32_t check_capabilities_sync(
    ksi_daemon_state *state,
    ksi_client *client,
    uint32_t requested,
    uint32_t *out_missing)
{
    uint32_t available_requested;
    uint32_t required_scopes;
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

    available_requested = requested & KSI_INPUT_CAPABILITIES
        & state->available_capabilities;
    required_scopes = permission_scopes_for_operations(available_requested);

    uint32_t allowed;
    uint64_t generation;

    if (ksi_auth_store_get_allowed_at_generation(state->permissions,
            client->uid, client->exe_hash, &allowed, &generation) != 0) {
        return 0u;
    }

    granted = operations_allowed_by_scopes(available_requested, allowed);
    missing = required_scopes & ~allowed;
    client->permission_store_generation = generation;
    client->permission_store_generation_valid = true;

    if (out_missing != NULL) {
        *out_missing = missing;
    }

    return granted;
}

static void finish_client_hello(
    ksi_client *client,
    uint32_t client_id,
    uint64_t correlation_id,
    uint32_t requested,
    uint32_t flags,
    uint32_t granted)
{
    bool complete = requested == 0u || (granted & requested) == requested;
    int32_t denied_status = (flags & KSI_CLIENT_HELLO_FLAG_CHECK_ONLY) != 0u
        ? KSI_CLIENT_HELLO_STATUS_PERMISSION_DENIED
        : -1;

    client->granted_capabilities |= granted;

    if (complete) {
        client->authenticated = true;
        send_hello_status(client, client_id, correlation_id, 0, granted);
        return;
    }

    client->authenticated =
        client->authenticated || client->granted_capabilities != 0u;
    send_hello_status(client, client_id, correlation_id, denied_status, granted);
}

/* A revoke is rare control-plane work. Clear cached privileges and active grab
 * state here so hook dispatch and synthesis checks remain memory-only. */
static void invalidate_connected_permissions(
    ksi_daemon_state *state,
    uid_t uid,
    const char *exe_hash,
    uint32_t scopes)
{
    bool flush_keyboard = false;
    bool flush_mouse = false;
    bool grabs_changed = false;

    if (state == NULL || exe_hash == NULL) {
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
            || strcmp(client->exe_hash, exe_hash) != 0) {
            continue;
        }

        uint32_t revoked_operations = operations_allowed_by_scopes(
            KSI_INPUT_CAPABILITIES, scopes);

        old_grants = client->granted_capabilities;
        client->granted_capabilities &= ~revoked_operations;

        if ((revoked_operations & KSI_CAP_HOOK_KEYBOARD) != 0u) {
            flush_keyboard = flush_keyboard
                || (old_grants & KSI_CAP_HOOK_KEYBOARD) != 0u
                || (client->hook_subscriptions & KSI_CAP_HOOK_KEYBOARD) != 0u;
            grabs_changed = grabs_changed
                || (client->hook_subscriptions & KSI_CAP_HOOK_KEYBOARD) != 0u;
            client->hook_subscriptions &=
                (uint32_t)~KSI_CAP_HOOK_KEYBOARD;
            client->hook_subscription_ordinal[0] = 0u;
            client->consecutive_hook_failures[0] = 0u;
            client->quarantined_hooks &=
                (uint32_t)~KSI_CAP_HOOK_KEYBOARD;
            client->quarantine_rearm_after_ms[0] = 0u;
            client->last_hook_quarantine_ms[0] = 0u;

            if (client->hook_send_ref != NULL) {
                hook_send_ref_clear_stalled(client->hook_send_ref, 0u);
            }
        }

        if ((revoked_operations & KSI_CAP_HOOK_MOUSE) != 0u) {
            flush_mouse = flush_mouse
                || (old_grants & KSI_CAP_HOOK_MOUSE) != 0u
                || (client->hook_subscriptions & KSI_CAP_HOOK_MOUSE) != 0u;
            grabs_changed = grabs_changed
                || (client->hook_subscriptions & KSI_CAP_HOOK_MOUSE) != 0u;
            client->hook_subscriptions &=
                (uint32_t)~KSI_CAP_HOOK_MOUSE;
            client->hook_subscription_ordinal[1] = 0u;
            client->consecutive_hook_failures[1] = 0u;
            client->quarantined_hooks &=
                (uint32_t)~KSI_CAP_HOOK_MOUSE;
            client->quarantine_rearm_after_ms[1] = 0u;
            client->last_hook_quarantine_ms[1] = 0u;

            if (client->hook_send_ref != NULL) {
                hook_send_ref_clear_stalled(client->hook_send_ref, 1u);
            }
        }

        if ((revoked_operations & KSI_CAP_BLOCK_INPUT) != 0u
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
            && client->connection_role == KSI_CONNECTION_HOOK_STREAM) {
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
            "inputd: failed to release grabs after permission revocation\n");
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
        if (ksi_auth_store_get_generation(state->permissions, uid_client->uid,
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
                    revoked |= permission_scopes_for_operations(
                        matching->granted_capabilities) & ~allowed;
                }
            }

            if (!changed) {
                continue;
            }

            if (revoked != 0u) {
                invalidate_connected_permissions(state, identity_client->uid,
                                                   identity_client->exe_hash,
                                                   revoked);
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
            client->granted_capabilities &= ~KSI_INPUT_CAPABILITIES;
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
                state, client->uid, client->exe_hash,
                KSP_INPUT_SCOPES);
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
            "inputd: failed to enqueue release-all after permission monitor failure\n");
    }
    if (update_grab_state(state) != 0) {
        fprintf(stderr,
            "inputd: failed to release grabs after permission monitor failure\n");
    }
}

static int permission_monitor_init(ksi_daemon_state *state)
{
    const char *runtime_directory;
    uint32_t mask = IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE
        | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT
        | IN_ONLYDIR | IN_DONT_FOLLOW;

    if (state == NULL || state->permissions == NULL
        || (runtime_directory = ksi_auth_store_runtime_directory(
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

/* Applies a completed prompt decision and sends the CLIENT_HELLO response. */
static void process_client_prompt_done(ksi_daemon_state *state, ksi_daemon_command *command)
{
    ssize_t client_index;
    ksi_client *client;
    ksi_auth_result decision;
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

    if (!client->pending_hello_valid) {
        free_daemon_command(command);
        return;
    }

    client->pending_hello_valid = false;

    if (!input_owner_matches_uid(state, client->uid)) {
        send_hello_status(client,
            client->pending_hello_client_id,
            client->pending_hello_correlation_id,
            -1, 0u);
        free_daemon_command(command);
        return;
    }

    decision = command->data.prompt_done.decision;
    requested = command->data.prompt_done.requested_capabilities
        & KSI_INPUT_CAPABILITIES;
    missing = command->data.prompt_done.missing_scopes
        & KSP_INPUT_SCOPES;

    if (client->pending_hello_permission_generation
        != state->permission_generation) {
        decision = KSI_AUTH_DENIED;
    }

    if (decision == KSI_AUTH_GRANTED && missing != 0u) {
        int grant_result = ksi_auth_store_grant_if_generation(
            state->permissions, client->uid, client->exe_hash,
            client->exe_path, missing,
            command->data.prompt_done.store_generation);

        if (grant_result != 0) {
            decision = grant_result > 0 ? KSI_AUTH_DENIED : KSI_AUTH_UNAVAILABLE;
        }
    }

    granted = operations_allowed_by_scopes(
        requested & state->available_capabilities
            & command->data.prompt_done.available_capabilities_at_start,
        client_persistent_allowed(state, client));

    if (decision != KSI_AUTH_GRANTED) {
        client->granted_capabilities |= granted;
        client->authenticated =
            client->authenticated || client->granted_capabilities != 0u;
        send_hello_status(client,
            client->pending_hello_client_id,
            client->pending_hello_correlation_id,
            -1, granted);
        free_daemon_command(command);
        return;
    }

    finish_client_hello(client,
        client->pending_hello_client_id,
        client->pending_hello_correlation_id,
        requested,
        client->pending_hello_flags,
        granted);
    free_daemon_command(command);
}
/* Stores the identification result and, if a CLIENT_HELLO was buffered,
 * processes it immediately or starts the permission prompt. */
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

        if (client->pending_hello_valid) {
            client->pending_hello_valid = false;
            send_hello_status(client,
                client->pending_hello_client_id,
                client->pending_hello_correlation_id,
                -1, 0u);
        }

        return;
    }

    /* Reject the identity if the process the worker read is not the one we
     * accepted: a zero/mismatched start time means the pid was recycled between
     * accept and the /proc read (TOCTOU). Deny caps rather than trust a possibly
     * different process's exe. (Note: exec() within the same pid does NOT change
     * start_time, so this closes pid-reuse only, not a fork-then-exec-in-pid race;
     * that residual is accepted — the (uid, exe) boundary is same-uid-weak by
     * design, see auth.c.) */
    if (result != NULL && result->has_identity
        && (result->start_time == 0u || client->accept_start_time == 0u
            || result->start_time != client->accept_start_time)) {
        fprintf(stderr,
            "inputd: rejecting identity for client pid=%ld: process start time changed "
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
        fprintf(stderr, "inputd: unable to identify process for client pid=%ld uid=%ld\n",
            (long)client->pid, (long)client->uid);
    }

    client->state = KSI_CLIENT_STATE_READY;

    if (!client->pending_hello_valid) {
        return;
    }

    /* There is a buffered CLIENT_HELLO — process it now that we have identity. */
	{
		uint32_t requested = client->pending_hello_requested;
		uint32_t flags = client->pending_hello_flags;
		uint32_t missing = 0u;
		uint32_t granted;

		prepare_requested_capabilities(state, requested);
		granted = check_capabilities_sync(state, client, requested, &missing);

        if (missing != 0u && state->permissions != NULL
            && !state->permission_monitor_failed
            && (flags & KSI_CLIENT_HELLO_FLAG_CHECK_ONLY) == 0u) {
            /* Need to prompt. Transition to AWAITING_PROMPT and start the worker. */
            client->pending_hello_permission_generation =
                state->permission_generation;
            if (!start_prompt_task(state->commands, state->permissions,
                                   client->fd, client->connection_id, requested, missing,
                                   state->available_capabilities,
                                   client->exe_path, client->exe_hash,
                                   client->pid, client->uid, client->start_time)) {
                /* Prompt thread failed; deny immediately. */
                client->pending_hello_valid = false;
                client->state = KSI_CLIENT_STATE_READY;
                send_hello_status(client,
                    client->pending_hello_client_id, client->pending_hello_correlation_id,
                    -1, 0u);
            } else {
                client->state = KSI_CLIENT_STATE_AWAITING_PROMPT;
            }
            return;
        }

        /* No prompt needed — grant immediately. */
        client->pending_hello_valid = false;

        finish_client_hello(client,
            client->pending_hello_client_id, client->pending_hello_correlation_id,
            requested, flags, granted);
    }
}

static uint32_t daemon_available_capabilities(const ksi_platform_backend *backend)
{
    if (backend->get_available_capabilities != NULL) {
        return backend->get_available_capabilities();
    }

    return 0;
}

static void prepare_requested_capabilities(ksi_daemon_state *state, uint32_t requested)
{
    if (state == NULL || state->backend == NULL || requested == 0u) {
        return;
    }

    if (state->backend->prepare_capabilities != NULL) {
        state->backend->prepare_capabilities(requested);
    }

    state->available_capabilities = daemon_available_capabilities(state->backend);
}

static bool client_has_capability(const ksi_client *client, uint32_t capability)
{
    if (!client->authenticated)
        return false;
    return (client->granted_capabilities & capability) == capability;
}

static uint32_t hook_type_to_cap_bit(uint32_t hook_type)
{
    if (hook_type == KSI_HOOK_KEYBOARD_LL) {
        return KSI_CAP_HOOK_KEYBOARD;
    }

    if (hook_type == KSI_HOOK_MOUSE_LL) {
        return KSI_CAP_HOOK_MOUSE;
    }

    return 0;
}


static uint32_t required_synthesis_capabilities(const ksi_input *inputs, size_t count)
{
    uint32_t required = 0;

    for (size_t i = 0; i < count; i++) {
        if (inputs[i].type == KSI_INPUT_KEYBOARD) {
            required |= KSI_CAP_SYNTH_KEYBOARD;
        } else if (inputs[i].type == KSI_INPUT_MOUSE) {
            required |= KSI_CAP_SYNTH_MOUSE;
        }
    }

    return required;
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

    subscription_bit = hook_type_to_cap_bit(hook_type);

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
    uint32_t available;
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
     * fully dead device. So mask the hook portion of the grab by the capabilities
     * the backend can currently honor: when synth is down, get_available_
     * capabilities() drops KSI_CAP_HOOK_* and the grab is released, letting raw
     * hardware pass through. The next update_grab_state (re-run by
     * run_backend_maintenance on the availability-change edge) restores the real
     * mask once synth recovers. BlockInput is intentionally NOT gated this way:
     * blocking only drops events and needs no synth, so its grab must persist. */
    available = state->backend->get_available_capabilities != NULL
        ? state->backend->get_available_capabilities()
        : ~0u; /* no availability query -> assume everything honorable */
    effective_hook_mask = hook_mask & available;
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
                "inputd: note: mlockall failed (%s); hook latency may degrade under "
                "memory pressure\n", strerror(errno));
        }
    }

    result = state->backend->set_grab_hook_mask == NULL
        ? 0
        : state->backend->set_grab_hook_mask(effective_hook_mask);

    if (result != 0) {
        return result;
    }

    /* Platforms without BlockInput support must not advertise KSI_CAP_BLOCK_INPUT.
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
    keyboard_grabbed = (effective_hook_mask & KSI_CAP_HOOK_KEYBOARD) != 0
        || (block_mask & KSI_BLOCK_INPUT_KEYBOARD) != 0;

    if (state->keyboard_grab_active && !keyboard_grabbed) {
        /* Only consume the held->released edge once the release is actually queued.
         * If the enqueue fails (queue saturated / OOM), leave keyboard_grab_active set
         * so the next update_grab_state call -- there are many callers and the queue
         * drains continuously -- retries, rather than stranding a key "down" on uinput
         * with no recovery until the next grab cycle. */
        if (output_queue_push_release_all(&state->output_queue)) {
            state->keyboard_grab_active = false;
        } else {
            fprintf(stderr, "inputd: failed to enqueue synthetic key release on keyboard ungrab; will retry\n");
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
            fprintf(stderr, "inputd: note: munlockall failed: %s\n", strerror(errno));
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
            "inputd: client fd=%d grab lease expired; failing open and disconnecting\n",
            client->fd);

        remove_client(state, index);
    }
}

/* Drops connections that never completed a CLIENT_HELLO within the handshake
 * window. A peer that connects and sends nothing otherwise keeps its slot forever
 * (leases arm only for hook/block clients), so N such peers could exhaust the
 * client table and deny the broker to everyone. Authenticated idle clients (e.g. a
 * query connection that sent a zero-capability hello) set hello_seen and are kept. */
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
         * cannot pin a per-uid slot forever. Guarded on READY + !pending_hello so
         * a client mid-identify or mid-prompt is never reaped; any message resets
         * last_activity_ms, so a live query channel that polls is kept. */
        if (client->hello_seen
            && client->state == KSI_CLIENT_STATE_READY
            && !client->pending_hello_valid
            && client->granted_capabilities == 0u
            && client->hook_subscriptions == 0u
            && client->block_input_mask == 0u
            && client->last_activity_ms != 0u
            && now >= client->last_activity_ms + KSI_CAPLESS_IDLE_TIMEOUT_MS) {
            fprintf(stderr,
                "inputd: dropping client fd=%d: capability-less and idle for %u ms\n",
                client->fd, (unsigned)KSI_CAPLESS_IDLE_TIMEOUT_MS);
            remove_client(state, index);
            continue;
        }

        if (client->hello_seen || client->connected_at_ms == 0u
            || now < client->connected_at_ms + KSI_HANDSHAKE_TIMEOUT_MS) {
            continue;
        }

        fprintf(stderr,
            "inputd: dropping client fd=%d: no CLIENT_HELLO within %u ms\n",
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
        "inputd: safety-critical command queue overflow; clearing hooks and BlockInput\n");
    clear_hook_state(state);

    if (update_grab_state(state) != 0) {
        fprintf(stderr, "inputd: failed to release grabs during fail-open recovery\n");
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
            uint32_t bit = lane == 0u ? KSI_CAP_HOOK_KEYBOARD : KSI_CAP_HOOK_MOUSE;

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
        fprintf(stderr, "inputd: failed to restore grabs after hook retry\n");
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

    if (state == NULL || index >= state->client_count) {
        return;
    }

    client = &state->clients[index];

    if (!input_owner_matches_uid(state, client->uid)) {
        return;
    }

    lane_index = hook_type_to_lane_index(hook_type);
    lane_bit = (lane_index == 1u) ? KSI_CAP_HOOK_MOUSE : KSI_CAP_HOOK_KEYBOARD;

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
        "inputd: hook quarantined pid=%ld fd=%d hook=%u event=%llu depth=%u "
        "elapsed=%ums reason=%s strike=%u retry=%ums\n",
        (long)client->pid, client->fd, hook_type,
        (unsigned long long)event_id, nesting_depth, elapsed_ms,
        reason == KSI_HOOK_QUARANTINE_REASON_TIMEOUT ? "timeout" : "transport",
        client->consecutive_hook_failures[lane_index], retry_after_ms);

    memset(&notification, 0, sizeof(notification));
    notification.hook_type = hook_type;
    notification.reason = reason;
    notification.event_id = event_id;
    notification.generation = 0u;
    notification.strike_count = client->consecutive_hook_failures[lane_index];
    notification.retry_after_ms = retry_after_ms;

    (void)ipc_send_locked(client->fd, KSI_MESSAGE_HOOK_QUARANTINED, 0,
        event_id, &notification, sizeof(notification));

    if (update_grab_state(state) != 0) {
        fprintf(stderr, "inputd: failed to update grabs after hook quarantine\n");
    }

    if (client->consecutive_hook_failures[lane_index] < KSI_MAX_CONSECUTIVE_HOOK_FAILURES) {
        return;
    }

    fprintf(stderr,
        "inputd: invalidating hook session pid=%ld fd=%d after %u consecutive %s timeouts\n",
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
