static void remember_authorization(
    ksi_client *client,
    uint16_t opcode,
    uint16_t mode,
    uint32_t scopes,
    uint64_t request_id)
{
    client->pending_authorization = true;
    client->pending_authorization_opcode = opcode;
    client->pending_authorization_mode = mode;
    client->pending_requested_scopes = scopes;
    client->pending_request_id = request_id;
}

static void begin_authorization(
    ksi_daemon_state *state,
    ksi_client *client,
    uint16_t opcode,
    uint16_t mode,
    uint32_t requested,
    uint64_t request_id)
{
    uint32_t granted;
    uint32_t missing = 0u;

    if (!input_owner_matches_uid(state, client->uid)) {
        send_authorization_status(client, opcode, request_id,
            KSI_STATUS_DENIED, KSI_DETAIL_NONE, 0u);
        return;
    }
    if (requested == 0u) {
        finish_client_authorization(client, opcode, request_id, requested, 0u);
        return;
    }
    if (client->pending_authorization
        || client->state == KSI_CLIENT_STATE_AWAITING_PROMPT) {
        send_authorization_status(client, opcode, request_id,
            KSI_STATUS_BUSY, KSI_DETAIL_WRONG_STATE, 0u);
        return;
    }

    remember_authorization(client, opcode, mode, requested, request_id);
    if (!client->identity_attempted) {
        client->identity_attempted = true;
        client->state = KSI_CLIENT_STATE_IDENTIFYING;
        if (!start_identify_task(state->commands, client->pid, client->uid,
                client->start_time, client->fd, client->connection_id)) {
            client->pending_authorization = false;
            client->state = KSI_CLIENT_STATE_READY;
            send_authorization_status(client, opcode, request_id,
                KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE, 0u);
        }
        return;
    }
    if (client->state == KSI_CLIENT_STATE_IDENTIFYING) {
        return;
    }
    if (!client->has_identity) {
        client->pending_authorization = false;
        send_authorization_status(client, opcode, request_id,
            KSI_STATUS_DENIED, KSI_DETAIL_NONE, 0u);
        return;
    }

    prepare_requested_scopes(state, requested);
    granted = check_scopes_sync(state, client, requested, &missing);
    if (missing != 0u && mode == KSI_AUTH_REQUEST
        && state->permissions != NULL && !state->permission_monitor_failed) {
        client->pending_permission_generation = state->permission_generation;
        if (start_prompt_task(state->commands, state->permissions,
                client->fd, client->connection_id, requested, missing,
                client->exe_path, client->exe_hash, client->pid, client->uid,
                client->start_time)) {
            client->state = KSI_CLIENT_STATE_AWAITING_PROMPT;
            return;
        }
        client->pending_authorization = false;
        send_authorization_status(client, opcode, request_id,
            KSI_STATUS_UNAVAILABLE, KSI_DETAIL_NONE, 0u);
        return;
    }

    client->pending_authorization = false;
    finish_client_authorization(client, opcode, request_id, requested, granted);
}

static void handle_client_hello(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_client_hello_payload payload;

    if (client->hello_complete) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_WRONG_STATE);
        return;
    }
    if (!ksi_protocol_decode_hello(message->payload, message->payload_size,
            &payload)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (payload.reserved != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_RESERVED_NONZERO);
        return;
    }
    if (payload.role != KSI_ROLE_RPC
        && payload.role != KSI_ROLE_CALLBACK_STREAM
        && payload.role != KSI_ROLE_AUTHORIZATION_LEASE) {
        send_status(client->fd, message->header, KSI_STATUS_UNSUPPORTED,
            KSI_DETAIL_WRONG_ROLE);
        return;
    }
    if (payload.authorization_mode > KSI_AUTH_REQUEST) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }
    if ((payload.requested_scopes & ~KSI_INPUT_PERMISSION_SCOPES) != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_UNKNOWN_SCOPE);
        return;
    }

    client->connection_role = payload.role;
    client->advertised_operations = state->available_operations;
    client->hello_complete = true;
    begin_authorization(state, client, KSI_OPCODE_HELLO,
        payload.authorization_mode, payload.requested_scopes,
        message->header->request_id);
}

static void handle_authorize(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_authorize_payload payload;

    if (!ksi_protocol_decode_authorize(message->payload, message->payload_size,
            &payload)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (payload.reserved0 != 0u || payload.reserved1 != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_RESERVED_NONZERO);
        return;
    }
    if (payload.authorization_mode > KSI_AUTH_REQUEST) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }
    if (payload.requested_scopes == 0u
        || (payload.requested_scopes & ~KSI_INPUT_PERMISSION_SCOPES) != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            payload.requested_scopes == 0u
                ? KSI_DETAIL_VALUE_RANGE : KSI_DETAIL_UNKNOWN_SCOPE);
        return;
    }

    begin_authorization(state, client, KSI_OPCODE_AUTHORIZE,
        payload.authorization_mode, payload.requested_scopes,
        message->header->request_id);
}

/* An absolute MouseMove is emitted on the second uinput device, whose creation
 * is non-fatal. Requiring the internal readiness bit turns a batch the backend
 * would have silently dropped into an honest UNAVAILABLE (or, for a hook
 * decision, a Pass) instead. */
static uint64_t input_needs_absolute_pointer(const ksi_input *input)
{
    const uint32_t absolute_move = (uint32_t)KSI_MOUSE_MOVE
        | (uint32_t)KSI_MOUSE_ABSOLUTE;

    if (input->type != KSI_INPUT_MOUSE
        || (input->data.mouse.flags & absolute_move) != absolute_move) {
        return 0u;
    }

    return KSI_INTERNAL_OPERATION_SYNTHESIZE_MOUSE_ABSOLUTE;
}

static void handle_get_indicator_state(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    ksi_linux_devices_refresh_indicator_state();
    send_indicator_state_result(client->fd, message->header);
}

static void handle_get_pointer_position(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    send_pointer_position_result(client->fd, message->header);
}

static void handle_get_pointer_buttons(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)
        || !client_has_scope(client, KSP_SCOPE_INPUT_MONITORING)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    send_pointer_buttons_result(client->fd, message->header);
}

static void handle_idle_time(
    const ksi_platform_backend *backend,
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_idle_time_payload result;

    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    memset(&result, 0, sizeof(result));

    if (backend != NULL && backend->get_idle_time != NULL) {
        (void)backend->get_idle_time(&result);
    }

    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_IDLE_TIME_PAYLOAD_SIZE];
    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_idle_time(response + KSI_STATUS_PAYLOAD_SIZE,
        &result);
    (void)ipc_send_locked(client->fd, KSI_OPCODE_GET_IDLE_TIME,
        KSI_FRAME_FLAG_RESPONSE, message->header->request_id,
        response, sizeof(response));
}

static void handle_list_permissions(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksp_permission_entry *entries = NULL;
    size_t count = 0u;
    uint8_t buffer[KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE + KSP_PATH_CAPACITY];

    if (client->connection_role != KSI_ROLE_RPC) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_WRONG_ROLE);
        return;
    }
    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (state->permissions == NULL) {
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }
    if (ksp_store_list(state->permissions, client->uid, &entries, &count) != 0) {
        send_status(client->fd, message->header, KSI_STATUS_INTERNAL,
            KSI_DETAIL_NONE);
        return;
    }

    for (size_t i = 0u; i < count; i++) {
        uint32_t scopes = entries[i].scopes & KSI_INPUT_PERMISSION_SCOPES;
        size_t path_length;

        if (scopes == 0u || !ksp_hash_is_canonical(entries[i].app_hash)) {
            continue;
        }
        path_length = strnlen(entries[i].executable, KSP_PATH_CAPACITY);
        ksi_status_encode(buffer, KSI_STATUS_OK, KSI_DETAIL_NONE);
        ksi_wire_write_u32(buffer + 8u, scopes);
        ksi_wire_write_u32(buffer + 12u, (uint32_t)path_length);
        ksi_wire_write_u64(buffer + 16u, entries[i].granted_at_utc);
        ksi_protocol_encode_hash(entries[i].app_hash, buffer + 24u);
        memcpy(buffer + KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE,
            entries[i].executable, path_length);
        if (ipc_send_locked(client->fd, KSI_OPCODE_PERMISSIONS_LIST,
                KSI_FRAME_FLAG_RESPONSE | KSI_FRAME_FLAG_MORE,
                message->header->request_id, buffer,
                KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE + path_length) != 0) {
            ksp_store_list_free(entries);
            return;
        }
    }

    ksp_store_list_free(entries);
    send_status(client->fd, message->header, KSI_STATUS_OK, KSI_DETAIL_NONE);
}

static bool raw_hash_is_zero(const uint8_t hash[KSI_PERMISSION_HASH_SIZE])
{
    uint8_t combined = 0u;

    for (size_t i = 0u; i < KSI_PERMISSION_HASH_SIZE; i++) {
        combined |= hash[i];
    }
    return combined == 0u;
}

static void handle_revoke_permissions(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_permissions_revoke_payload payload;
    char exe_hash[KSP_HASH_HEX_LENGTH + 1u] = { 0 };
    bool all;

    if (state == NULL || client == NULL) {
        return;
    }

    if (client->connection_role != KSI_ROLE_RPC) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_WRONG_ROLE);
        return;
    }

    if (state->permissions == NULL) {
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }

    if (!ksi_protocol_decode_permissions_revoke(
            message->payload, message->payload_size, &payload)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (payload.scopes == 0u
        || (payload.scopes & ~KSI_INPUT_PERMISSION_SCOPES) != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            payload.scopes == 0u
                ? KSI_DETAIL_VALUE_RANGE : KSI_DETAIL_UNKNOWN_SCOPE);
        return;
    }
    all = payload.target_kind == KSI_PERMISSION_TARGET_ALL;
    if (payload.target_kind == KSI_PERMISSION_TARGET_HASH) {
        if (payload.pid != 0u || raw_hash_is_zero(payload.hash)) {
            send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
                KSI_DETAIL_VALUE_RANGE);
            return;
        }
        (void)ksi_protocol_decode_hash(payload.hash, exe_hash);
    } else if (payload.target_kind == KSI_PERMISSION_TARGET_PID) {
        ksp_identity identity;

        if (payload.pid == 0u || payload.pid > (uint64_t)INT_MAX
            || !raw_hash_is_zero(payload.hash)
            || ksp_identity_capture((pid_t)payload.pid, client->uid,
                &identity) != 0) {
            send_status(client->fd, message->header, KSI_STATUS_NOT_FOUND,
                KSI_DETAIL_NONE);
            return;
        }
        (void)snprintf(exe_hash, sizeof(exe_hash), "%s", identity.hash);
    } else if (!all || payload.pid != 0u || !raw_hash_is_zero(payload.hash)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }

    int result = all
        ? ksp_store_revoke_uid(state->permissions, client->uid, payload.scopes)
        : ksp_store_revoke(state->permissions, client->uid, exe_hash,
            payload.scopes);
    if (result != 0) {
        send_status(client->fd, message->header, KSI_STATUS_INTERNAL,
            KSI_DETAIL_NONE);
        return;
    }

    invalidate_connected_permissions(state, client->uid,
        all ? NULL : exe_hash, all, payload.scopes);
    send_status(client->fd, message->header, KSI_STATUS_OK, KSI_DETAIL_NONE);
}

static void handle_hook_subscription(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_hook_subscription_payload payload;
    uint32_t subscription_bit;
    uint32_t old_subscriptions;
    uint64_t old_ordinal;
    size_t lane_index;

    if (client->connection_role != KSI_ROLE_CALLBACK_STREAM) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_WRONG_ROLE);
        return;
    }

    if (!ksi_protocol_decode_hook_subscription(
            message->payload, message->payload_size, &payload)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    subscription_bit = hook_type_to_operation(payload.hook_type);
    if (payload.reserved != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_RESERVED_NONZERO);
        return;
    }
    if (subscription_bit == 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }

    old_subscriptions = client->hook_subscriptions;
    lane_index = hook_type_to_lane_index(payload.hook_type);
    old_ordinal = client->hook_subscription_ordinal[lane_index];

    if (message->header->opcode == KSI_OPCODE_SUBSCRIBE_HOOK) {
        if (!input_owner_matches_uid(state, client->uid)
            || !client_has_scope(client, KSP_SCOPE_INPUT_MONITORING)) {
            send_status(client->fd, message->header, KSI_STATUS_DENIED,
                KSI_DETAIL_NONE);
            return;
        }
        if ((state->ready_operations & subscription_bit) == 0u) {
            send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
                KSI_DETAIL_NONE);
            return;
        }

        if ((client->hook_subscriptions & subscription_bit) == 0u) {
            uint64_t ordinal = ++state->next_hook_subscription_ordinal[lane_index];

            if (ordinal == 0u) {
                ordinal = ++state->next_hook_subscription_ordinal[lane_index];
            }

            client->hook_subscription_ordinal[lane_index] = ordinal;
        }

        client->hook_subscriptions |= subscription_bit;
    } else {
        client->hook_subscriptions &= (uint32_t)~subscription_bit;
        client->hook_subscription_ordinal[lane_index] = 0u;
    }

    if (update_grab_state(state) != 0) {
        client->hook_subscriptions = old_subscriptions;
        client->hook_subscription_ordinal[lane_index] = old_ordinal;
        (void)update_grab_state(state);
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }

    renew_client_lease(client);
    uint8_t response[KSI_HOOK_SUBSCRIPTION_RESULT_PAYLOAD_SIZE];
    size_t response_size = ksi_protocol_encode_u32_result(
        response, client->hook_subscriptions);
    (void)ipc_send_locked(client->fd, message->header->opcode,
        KSI_FRAME_FLAG_RESPONSE, message->header->request_id,
        response, response_size);
}

static void handle_set_block_input(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_block_input_payload payload;
    uint32_t old_mask;

    if (!ksi_protocol_decode_block_input(
            message->payload, message->payload_size, &payload)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (payload.reserved != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_RESERVED_NONZERO);
        return;
    }
    if ((payload.block_mask
            & (uint32_t)~(KSI_BLOCK_KEYBOARD | KSI_BLOCK_MOUSE)) != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }

    if (payload.block_mask != 0u
        && !client_has_scope(client, KSP_SCOPE_INPUT_CONTROL)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    if (payload.block_mask != 0u
        && !input_owner_matches_uid(state, client->uid)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }
    if (payload.block_mask != 0u
        && (state->ready_operations & KSI_OPERATION_BLOCK_INPUT) == 0u) {
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }

    old_mask = client->block_input_mask;
    client->block_input_mask = payload.block_mask;

    if (update_grab_state(state) != 0) {
        client->block_input_mask = old_mask;
        (void)update_grab_state(state);
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }

    renew_client_lease(client);
    uint8_t response[KSI_BLOCK_INPUT_RESULT_PAYLOAD_SIZE];
    size_t response_size = ksi_protocol_encode_u32_result(
        response, client->block_input_mask);
    (void)ipc_send_locked(client->fd, KSI_OPCODE_SET_BLOCK_INPUT,
        KSI_FRAME_FLAG_RESPONSE, message->header->request_id,
        response, response_size);
}

static bool handle_hook_decision(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_status_payload status;
    uint32_t decision_value;
    uint32_t input_count;
    size_t expected_size;
    ksi_hook_lane *lane;
    ksi_lane_decision decision;
    uint64_t required_operations = 0u;

    if (client->connection_role != KSI_ROLE_CALLBACK_STREAM
        || message->payload_size < KSI_STATUS_PAYLOAD_SIZE) {
        return false;
    }
    ksi_status_decode(message->payload, &status);
    lane = lane_for_event_id(state, message->header->request_id);
    if (lane == NULL
        || atomic_load(&lane->current_responder_connection_id)
            != client->connection_id) {
        return false;
    }
    memset(&decision, 0, offsetof(ksi_lane_decision, inputs));
    decision.event_id = message->header->request_id;
    decision.responder_connection_id = client->connection_id;

    if (status.status != KSI_STATUS_OK) {
        if (message->payload_size != KSI_STATUS_PAYLOAD_SIZE) {
            uint32_t diagnostic_length;

            if (message->payload_size < KSI_STATUS_PAYLOAD_SIZE + 4u) {
                goto invalid_decision;
            }
            diagnostic_length = ksi_wire_read_u32(
                message->payload + KSI_STATUS_PAYLOAD_SIZE);
            if ((size_t)diagnostic_length
                    != message->payload_size - KSI_STATUS_PAYLOAD_SIZE - 4u) {
                goto invalid_decision;
            }
        }
        decision.decision = KSI_HOOK_PASS;
        return lane_decision_queue_push(&lane->decision_queue, &decision);
    }
    if (!ksi_protocol_decode_hook_decision_prefix(message->payload,
            message->payload_size, &decision_value, &input_count)
        || input_count > KSI_MAX_MODIFY_INPUTS) {
        goto invalid_decision;
    }
    expected_size = KSI_HOOK_DECISION_PREFIX_SIZE
        + (size_t)input_count * KSI_INPUT_WIRE_SIZE;
    if (message->payload_size != expected_size
        || (decision_value != KSI_HOOK_PASS
            && decision_value != KSI_HOOK_BLOCK
            && decision_value != KSI_HOOK_MODIFY)
        || (decision_value == KSI_HOOK_MODIFY && input_count == 0u)) {
        goto invalid_decision;
    }
    if (!input_owner_matches_uid(state, client->uid)
        || (decision_value != KSI_HOOK_PASS
            && !client_has_scope(client, KSP_SCOPE_INPUT_CONTROL))) {
        decision.decision = KSI_HOOK_PASS;
        (void)lane_decision_queue_push(&lane->decision_queue, &decision);
        return false;
    }
    decision.decision = decision_value;
    decision.input_count = input_count;
    for (uint32_t i = 0u; i < input_count; i++) {
        if (!ksi_protocol_decode_input(
                message->payload + KSI_HOOK_DECISION_PREFIX_SIZE
                    + (size_t)i * KSI_INPUT_WIRE_SIZE,
                &decision.inputs[i])) {
            goto invalid_decision;
        }
        required_operations |= decision.inputs[i].type == KSI_INPUT_KEYBOARD
            ? KSI_OPERATION_SYNTHESIZE_KEYBOARD
            : KSI_OPERATION_SYNTHESIZE_MOUSE;
        required_operations |= input_needs_absolute_pointer(&decision.inputs[i]);
    }
    if ((required_operations & state->ready_operations) != required_operations
        || !lane_decision_queue_push(&lane->decision_queue, &decision)) {
        decision.decision = KSI_HOOK_PASS;
        decision.input_count = 0u;
        (void)lane_decision_queue_push(&lane->decision_queue, &decision);
        return false;
    }

    ssize_t resolved = find_client_index_by_fd(state, client->fd);
    if (resolved >= 0
        && state->clients[resolved].connection_id == client->connection_id) {
        record_client_hook_success(state, (nfds_t)resolved, lane->hook_type);
        renew_client_lease(&state->clients[resolved]);
    }
    return true;

invalid_decision:
    decision.decision = KSI_HOOK_PASS;
    decision.input_count = 0u;
    (void)lane_decision_queue_push(&lane->decision_queue, &decision);
    return false;
}

static void handle_synthesize_input(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_input inputs[KSI_MAX_SYNTH_INPUTS];
    uint32_t count;
    uint32_t synth_flags;
    size_t expected_size;
    uint64_t input_generation;
    uint64_t parent_hook_event_id;
    uint64_t required_operations = 0u;

    if (!input_owner_matches_uid(state, client->uid)
        || !client_has_scope(client, KSP_SCOPE_INPUT_CONTROL)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }
    if (!ksi_protocol_decode_synthesize_prefix(message->payload,
            message->payload_size, &count, &synth_flags)) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (count > KSI_MAX_SYNTH_INPUTS
        || (synth_flags & ~(uint32_t)KSI_SYNTH_BYPASS_HOOK) != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_VALUE_RANGE);
        return;
    }
    expected_size = KSI_SYNTHESIZE_PREFIX_SIZE
        + (size_t)count * KSI_INPUT_WIRE_SIZE;
    if (message->payload_size != expected_size) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    for (uint32_t i = 0u; i < count; i++) {
        if (!ksi_protocol_decode_input(
                message->payload + KSI_SYNTHESIZE_PREFIX_SIZE
                    + (size_t)i * KSI_INPUT_WIRE_SIZE,
                &inputs[i])) {
            send_status(client->fd, message->header,
                KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_VALUE_RANGE);
            return;
        }
        required_operations |= inputs[i].type == KSI_INPUT_KEYBOARD
            ? KSI_OPERATION_SYNTHESIZE_KEYBOARD
            : KSI_OPERATION_SYNTHESIZE_MOUSE;
        required_operations |= input_needs_absolute_pointer(&inputs[i]);
    }
    if ((required_operations & state->ready_operations) != required_operations) {
        send_status(client->fd, message->header, KSI_STATUS_UNAVAILABLE,
            KSI_DETAIL_NONE);
        return;
    }

    input_generation = current_input_generation(state);
    parent_hook_event_id = client->connection_role
            == KSI_ROLE_CALLBACK_STREAM
        ? hook_send_ref_current_event_id(client->hook_send_ref)
        : 0u;

    if (parent_hook_event_id != 0u) {
        ksi_hook_lane *active_lane = lane_for_event_id(
            state, parent_hook_event_id);
        ksi_nested_transaction *transaction = NULL;
        ksi_synth_completion *completion = NULL;
        size_t expanded_count = 0u;
        uint32_t depth;

        if (active_lane == NULL
            || atomic_load(&active_lane->current_responder_connection_id)
                != client->connection_id) {
            send_status(client->fd, message->header, KSI_STATUS_TIMEOUT,
                KSI_DETAIL_STALE_CALLBACK);
            return;
        }

        depth = atomic_load(&active_lane->current_nesting_depth) + 1u;

        if (depth > KSI_MAX_RECURSION_DEPTH) {
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_RECURSION_LIMIT);
            return;
        }

        if ((synth_flags & KSI_SYNTH_BYPASS_HOOK) != 0u
            || count == 0u) {
            if (!output_queue_push_synth(&state->output_queue, inputs,
                    count, synth_flags, input_generation)) {
                send_status(client->fd, message->header,
                    KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
                return;
            }

            send_status(client->fd, message->header, KSI_STATUS_OK,
                KSI_DETAIL_NONE);
            return;
        }

        if (!ksi_synthetic_hook_batch_count(inputs, count,
                KSI_MAX_SYNTH_HOOK_ACTIONS, &expanded_count)) {
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED,
                KSI_DETAIL_EXPANDED_INPUT_LIMIT);
            return;
        }

        completion = synth_completion_create(
            state, client->hook_send_ref, message->header);
        transaction = calloc(1, sizeof(*transaction)
            + expanded_count * sizeof(transaction->members[0]));

        if (completion == NULL || transaction == NULL) {
            if (completion != NULL) {
                synth_completion_fail(completion,
                    KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            } else {
                send_status(client->fd, message->header,
                    KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            }

            free(transaction);
            return;
        }

        transaction->count = (uint32_t)expanded_count;
        transaction->depth = depth;
        transaction->origin_generation = atomic_load(&active_lane->flush_generation);
        transaction->input_generation = input_generation;
        transaction->origin_connection_id = client->connection_id;
        transaction->parent_hook_event_id = parent_hook_event_id;
        transaction->completion = completion;

        if (!synth_completion_begin_recursive_synthesis(
                completion, parent_hook_event_id)) {
            synth_completion_fail(completion, KSI_STATUS_TIMEOUT,
                KSI_DETAIL_STALE_CALLBACK);
            transaction->completion = NULL;
            nested_transaction_destroy(transaction);
            return;
        }

        for (uint32_t i = 0u, offset = 0u; i < count; i++) {
            ksi_input expanded[KSI_SYNTHETIC_HOOK_MAX_EXPANSION];
            size_t expanded_one_count = ksi_synthetic_hook_expand_input(
                &inputs[i], expanded);

            for (size_t j = 0u; j < expanded_one_count; j++) {
                transaction->members[offset++].input = expanded[j];
            }
        }

        for (uint32_t i = 0u; i < transaction->count; i++) {
            ksi_nested_member *member = &transaction->members[i];

            if (!create_synthetic_lane_event(state, &member->input, i == 0u,
                    depth, NULL, &member->event,
                    input_generation)) {
                synth_completion_fail(completion,
                    KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
                transaction->completion = NULL;
                nested_transaction_destroy(transaction);
                return;
            }
        }

        synth_completion_begin_atomic(completion);

        if (!ksi_pipe_ring_push(&active_lane->nested_queue.ring, &transaction)) {
            synth_completion_fail(completion,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            transaction->completion = NULL;
            nested_transaction_destroy(transaction);
            return;
        }

        lane_decision_queue_wake(&active_lane->decision_queue);
        return;
    }

    if (synth_batch_needs_hook_queue(state, inputs, count, synth_flags)) {
        size_t expanded_count = 0u;

        if (!ksi_synthetic_hook_batch_count(inputs, count,
                KSI_MAX_SYNTH_HOOK_ACTIONS, &expanded_count)) {
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED,
                KSI_DETAIL_EXPANDED_INPUT_LIMIT);
            return;
        }

        /* Like Win32 SendInput, an ordinary sender waits only for admission to
         * the input queue. The detached completion keeps the accepted batch
         * atomic, but never holds this RPC open while hook callbacks run. */
        ksi_synth_completion *completion = synth_completion_create(
            state, NULL, NULL);

        if (completion == NULL) {
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            return;
        }

        if (!synthetic_hook_queue_push(
                &state->synthetic_hook_queue,
                inputs,
                count,
                expanded_count,
                monotonic_ns(),
                completion,
                input_generation)) {
            synth_completion_fail(completion,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            return;
        }

        send_status(client->fd, message->header, KSI_STATUS_OK,
            KSI_DETAIL_NONE);
        return;
    } else {
        if (!output_queue_push_synth(&state->output_queue,
                inputs, count, synth_flags,
                input_generation)) {
            send_status(client->fd, message->header,
                KSI_STATUS_RESOURCE_EXHAUSTED, KSI_DETAIL_NONE);
            return;
        }
    }

    send_status(client->fd, message->header, KSI_STATUS_OK, KSI_DETAIL_NONE);
}

static bool handle_binary_message(
    const ksi_platform_backend *backend,
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    /* Any message keeps the connection out of the capless-idle reaper. */
    client->last_activity_ms = monotonic_ms();

    if (g_verbose) {
        printf("client %d opcode=%u size=%u request=%llu flags=0x%04x\n",
            client->fd,
            message->header->opcode,
            message->header->payload_length,
            (unsigned long long)message->header->request_id,
            message->header->flags);
    }

    if ((message->header->flags & KSI_FRAME_FLAG_EVENT) != 0u) {
        return false;
    }
    if ((message->header->flags & KSI_FRAME_FLAG_RESPONSE) != 0u) {
        return message->header->flags == KSI_FRAME_FLAG_RESPONSE
            && message->header->opcode == KSI_OPCODE_HOOK_EVENT
            && client->hello_complete
            && handle_hook_decision(state, client, message);
    }
    if (!client->hello_complete && message->header->opcode != KSI_OPCODE_HELLO) {
        return false;
    }

    switch (message->header->opcode) {
        case KSI_OPCODE_HELLO:
            handle_client_hello(state, client, message);
            return true;
        case KSI_OPCODE_AUTHORIZE:
            handle_authorize(state, client, message);
            return true;
        case KSI_OPCODE_PING:
            if (message->payload_size != 0u) {
                send_status(client->fd, message->header,
                    KSI_STATUS_INVALID_REQUEST, KSI_DETAIL_PAYLOAD_SIZE);
                return true;
            }
            renew_client_lease(client);
            if (message->header->request_id != 0u) {
                send_status(client->fd, message->header, KSI_STATUS_OK,
                    KSI_DETAIL_NONE);
            }
            return true;
        case KSI_OPCODE_SET_BLOCK_INPUT:
            handle_set_block_input(state, client, message);
            return true;
        case KSI_OPCODE_GET_INDICATOR_STATE:
            handle_get_indicator_state(state, client, message);
            return true;
        case KSI_OPCODE_GET_POINTER_POSITION:
            handle_get_pointer_position(state, client, message);
            return true;
        case KSI_OPCODE_GET_POINTER_BUTTONS:
            handle_get_pointer_buttons(state, client, message);
            return true;
        case KSI_OPCODE_GET_KEY_STATE:
            handle_get_key_state(state, client, message);
            return true;
        case KSI_OPCODE_GET_IDLE_TIME:
            handle_idle_time(backend, state, client, message);
            return true;
        case KSI_OPCODE_GET_MODIFIER_STATE:
            handle_get_modifier_state(state, client, message);
            return true;
        case KSI_OPCODE_PERMISSIONS_LIST:
            handle_list_permissions(state, client, message);
            return true;
        case KSI_OPCODE_PERMISSIONS_REVOKE:
            handle_revoke_permissions(state, client, message);
            return true;
        case KSI_OPCODE_SUBSCRIBE_HOOK:
        case KSI_OPCODE_UNSUBSCRIBE_HOOK:
            handle_hook_subscription(state, client, message);
            return true;
        case KSI_OPCODE_SYNTHESIZE_INPUT:
            handle_synthesize_input(state, client, message);
            return true;
        default:
            send_status(client->fd, message->header, KSI_STATUS_UNSUPPORTED,
                KSI_DETAIL_UNKNOWN_OPERATION);
            return true;
    }
}

static bool process_client_buffer_direct(ksi_daemon_state *state, ksi_client *client)
{
    size_t offset = 0u;

    while (client->rx_used - offset >= KSI_FRAME_HEADER_SIZE) {
        ksi_message_header header;
        ksi_binary_message_view message;
        size_t frame_size;

        if (!ksi_frame_header_decode(client->rx_buffer + offset, &header)
            || !ksi_protocol_frame_is_valid(&header)) {
            fprintf(stderr, "client %d sent an invalid frame header\n", client->fd);
            return false;
        }

        if (header.major != KSI_PROTOCOL_MAJOR || header.minor != KSI_PROTOCOL_MINOR) {
            /* Name the daemon's own version and build so a mismatch is visible
             * from the daemon log (e.g. a newer client hitting a stale daemon). */
            fprintf(stderr,
                "client %d sent unsupported protocol version %u.%u; "
                "this daemon speaks %u.%u (%s)\n",
                client->fd,
                header.major,
                header.minor,
                (unsigned)KSI_PROTOCOL_MAJOR,
                (unsigned)KSI_PROTOCOL_MINOR,
                KSI_PRODUCT_VERSION);
            return false;
        }

        frame_size = KSI_FRAME_HEADER_SIZE + (size_t)header.payload_length;
        if (client->rx_used - offset < frame_size) {
            break;
        }

        message.header = &header;
        message.payload = client->rx_buffer + offset + KSI_FRAME_HEADER_SIZE;
        message.payload_size = header.payload_length;
        if (!handle_binary_message(state->backend, state, client, &message)) {
            return false;
        }
        offset += frame_size;
    }

    if (offset > 0u) {
        if (offset < client->rx_used) {
            memmove(client->rx_buffer, client->rx_buffer + offset, client->rx_used - offset);
        }

        client->rx_used -= offset;
    }

    return true;
}

static int read_client_frames_direct(ksi_daemon_state *state, ksi_client *client)
{
    for (int reads = 0; reads < KSI_MAX_CLIENT_READS_PER_PASS; reads++) {
        ssize_t bytes_read;
        size_t available = KSI_MAX_MESSAGE_SIZE - client->rx_used;

        if (available == 0u) {
            fprintf(stderr, "client %d receive buffer overflow\n", client->fd);
            return -1;
        }

        bytes_read = read(client->fd, client->rx_buffer + client->rx_used, available);

        if (bytes_read == 0) {
            return 0;
        }

        if (bytes_read < 0) {
            if (errno == EINTR) {
                reads--;  /* EINTR is not a real read; don't spend budget on it */
                continue;
            }

            return errno == EAGAIN || errno == EWOULDBLOCK ? 1 : -1;
        }

        client->rx_used += (size_t)bytes_read;

        if (!process_client_buffer_direct(state, client)) {
            return -1;
        }

        if ((size_t)bytes_read < available) {
            return 1;
        }
    }

    /* Budget exhausted while the client still had a full buffer of data each
     * read. Keep the client (return 1, not 0/-1): unread bytes stay in the kernel
     * recv buffer and the fd remains POLLIN-readable, so the next poll iteration
     * re-enters here — now interleaved with device/hook ingress. */
    return 1;
}

static void send_indicator_state_result(int client_fd, const ksi_message_header *request)
{
    ksi_indicator_state_payload result;
    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_INDICATOR_STATE_PAYLOAD_SIZE];
    bool caps = false;
    bool num = false;
    bool scroll = false;

    ksi_linux_devices_get_indicator_state(&caps, &num, &scroll);

    memset(&result, 0, sizeof(result));
    result.caps_lock = caps ? 1u : 0u;
    result.num_lock = num ? 1u : 0u;
    result.scroll_lock = scroll ? 1u : 0u;

    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_indicator_state(
        response + KSI_STATUS_PAYLOAD_SIZE, &result);
    (void)ipc_send_locked(client_fd, request->opcode,
        KSI_FRAME_FLAG_RESPONSE, request->request_id,
        response, sizeof(response));
}

static void handle_get_key_state(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_key_state_payload result;
    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_KEY_STATE_PAYLOAD_SIZE];
    bool caps = false, num = false, scroll = false;

    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)
        || !client_has_scope(client, KSP_SCOPE_INPUT_MONITORING)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    /* Refresh the indicator state directly from hardware (EVIOCGLED) before
     * reading it, so callers get the current LED state rather than the
     * potentially stale EV_LED-derived cache. This is important for toggle-key
     * checks immediately after a synthetic CapsLock/NumLock/ScrollLock event
     * (e.g. the ToggleKeyState call in SendKeys), where the compositor's LED
     * acknowledgement may not yet have produced an EV_LED event. */
    ksi_linux_devices_refresh_indicator_state();

    memset(&result, 0, sizeof(result));
    (void)ksi_linux_devices_get_key_state(&result);
    ksi_linux_devices_get_indicator_state(&caps, &num, &scroll);
    result.caps_lock   = caps   ? 1u : 0u;
    result.num_lock    = num    ? 1u : 0u;
    result.scroll_lock = scroll ? 1u : 0u;

    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_key_state(
        response + KSI_STATUS_PAYLOAD_SIZE, &result);
    (void)ipc_send_locked(client->fd, message->header->opcode,
        KSI_FRAME_FLAG_RESPONSE, message->header->request_id,
        response, sizeof(response));
}

static void handle_get_modifier_state(
    ksi_daemon_state *state,
    ksi_client *client,
    const ksi_binary_message_view *message)
{
    ksi_modifier_state_payload result;
    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_MODIFIER_STATE_PAYLOAD_SIZE];

    if (message->payload_size != 0u) {
        send_status(client->fd, message->header, KSI_STATUS_INVALID_REQUEST,
            KSI_DETAIL_PAYLOAD_SIZE);
        return;
    }
    if (!input_owner_matches_uid(state, client->uid)) {
        send_status(client->fd, message->header, KSI_STATUS_DENIED,
            KSI_DETAIL_NONE);
        return;
    }

    ksi_linux_devices_refresh_indicator_state();
    memset(&result, 0, sizeof(result));
    (void)ksi_linux_devices_get_modifier_state(&result);
    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_modifier_state(
        response + KSI_STATUS_PAYLOAD_SIZE, &result);
    (void)ipc_send_locked(client->fd, message->header->opcode,
        KSI_FRAME_FLAG_RESPONSE, message->header->request_id,
        response, sizeof(response));
}

static void send_pointer_position_result(int client_fd, const ksi_message_header *request)
{
    ksi_pointer_position_payload result;
    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_POINTER_POSITION_PAYLOAD_SIZE];

    memset(&result, 0, sizeof(result));
    (void)ksi_linux_devices_get_pointer_position(&result);

    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_pointer_position(
        response + KSI_STATUS_PAYLOAD_SIZE, &result);
    (void)ipc_send_locked(client_fd, request->opcode,
        KSI_FRAME_FLAG_RESPONSE, request->request_id,
        response, sizeof(response));
}

static void send_pointer_buttons_result(int client_fd, const ksi_message_header *request)
{
    ksi_pointer_buttons_payload result;
    uint8_t response[KSI_STATUS_PAYLOAD_SIZE + KSI_POINTER_BUTTONS_PAYLOAD_SIZE];

    memset(&result, 0, sizeof(result));
    (void)ksi_linux_devices_get_pointer_buttons(&result);

    ksi_status_encode(response, KSI_STATUS_OK, KSI_DETAIL_NONE);
    (void)ksi_protocol_encode_pointer_buttons(
        response + KSI_STATUS_PAYLOAD_SIZE, &result);
    (void)ipc_send_locked(client_fd, request->opcode,
        KSI_FRAME_FLAG_RESPONSE, request->request_id,
        response, sizeof(response));
}

static ssize_t find_client_index_by_fd(const ksi_daemon_state *state, int client_fd)
{
    if (state == NULL) {
        return -1;
    }

    for (nfds_t i = 0; i < state->client_count; i++) {
        if (state->clients[i].fd == client_fd) {
            return (ssize_t)i;
        }
    }

    return -1;
}

static ssize_t find_client_index_by_connection(
    const ksi_daemon_state *state,
    int client_fd,
    uint64_t connection_id)
{
    ssize_t index = find_client_index_by_fd(state, client_fd);

    if (index < 0 || connection_id == 0u) {
        return -1;
    }

    return state->clients[index].connection_id == connection_id ? index : -1;
}

static void add_client(
    ksi_daemon_state *state,
    int client_fd,
    const ksi_ipc_peer_credentials *credentials)
{
    ksi_client *client;

    if (state == NULL || credentials == NULL) {
        return;
    }

    if (state->client_count >= KSI_MAX_CLIENTS) {
        ksi_ipc_close_client(client_fd);
        return;
    }

    /* Reserve headroom so one uid cannot occupy every slot and lock out others. */
    {
        nfds_t same_uid = 0;

        for (nfds_t i = 0; i < state->client_count; i++) {
            if (state->clients[i].uid == credentials->uid) {
                same_uid++;
            }
        }

        if (same_uid >= KSI_MAX_CLIENTS_PER_UID) {
            fprintf(stderr,
                "keysharp-input: rejecting client fd=%d uid=%ld: per-uid connection limit (%u) reached\n",
                client_fd, (long)credentials->uid, (unsigned)KSI_MAX_CLIENTS_PER_UID);
            ksi_ipc_close_client(client_fd);
            return;
        }
    }

    client = &state->clients[state->client_count];
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;
    client->rx_buffer = malloc(KSI_MAX_MESSAGE_SIZE);

    if (client->rx_buffer == NULL) {
        ksi_ipc_close_client(client_fd);
        return;
    }

    client->hook_send_ref = hook_send_ref_create(client_fd);

    if (client->hook_send_ref == NULL) {
        fprintf(stderr, "keysharp-input: failed to create hook send handle for client fd=%d: %s\n",
            client_fd, strerror(errno));
        free(client->rx_buffer);
        client->rx_buffer = NULL;
        ksi_ipc_close_client(client_fd);
        return;
    }

    client->connection_id = state->next_connection_id++;

    if (client->connection_id == 0u) {
        client->connection_id = state->next_connection_id++;
    }

    client->pid = credentials->pid;
    client->uid = credentials->uid;
    client->gid = credentials->gid;
    if (ksp_process_start_time(credentials->pid, &client->start_time) != 0) {
        client->start_time = 0u;
    }
    client->state = KSI_CLIENT_STATE_READY;
    client->connected_at_ms = monotonic_ms();
    client->last_activity_ms = client->connected_at_ms;
    state->client_count++;

    if (g_verbose) {
        printf("accepted client fd=%d pid=%ld uid=%ld gid=%ld\n",
            client->fd,
            (long)client->pid,
            (long)client->uid,
            (long)client->gid);
    }
}

static bool peer_uid_allowed(
    const ksi_daemon_state *state,
    uid_t peer_uid,
    bool system_service)
{
    return system_service
        ? input_owner_matches_uid(state, peer_uid)
        : peer_uid == getuid();
}

/* A switched-away user's transports are retained for seamless reactivation,
 * but they must never prevent the newly active uid from reaching the broker.
 * clients[] remains in acceptance order, so the first inactive entry is the
 * oldest eviction candidate. Active-owner clients are never displaced here;
 * their existing per-uid limit remains the admission bound. */
static bool ensure_active_client_slot(ksi_daemon_state *state)
{
    if (state == NULL) {
        return false;
    }

    if (state->client_count < KSI_MAX_CLIENTS) {
        return true;
    }

    for (nfds_t i = 0u; i < state->client_count; i++) {
        if (!input_owner_matches_uid(state, state->clients[i].uid)) {
            fprintf(stderr,
                "keysharp-input: evicting oldest inactive client fd=%d uid=%ld "
                "to admit active seat0 user\n",
                state->clients[i].fd, (long)state->clients[i].uid);
            remove_client(state, i);
            return state->client_count < KSI_MAX_CLIENTS;
        }
    }

    return false;
}

static bool accept_client(ksi_daemon_state *state, ksi_ipc_server *server, bool system_service)
{
    ksi_ipc_peer_credentials credentials;
    int client_fd = ksi_ipc_accept_client(server);

    if (client_fd < 0) {
        return false;
    }

    if (ksi_ipc_get_peer_credentials(client_fd, &credentials) != 0) {
        ksi_ipc_close_client(client_fd);
        return true;
    }

    if (!peer_uid_allowed(state, credentials.uid, system_service)) {
        if (!system_service) {
            fprintf(stderr,
                "rejected client pid=%ld uid=%ld gid=%ld: daemon uid is %ld\n",
                (long)credentials.pid,
                (long)credentials.uid,
                (long)credentials.gid,
                (long)getuid());
            ksi_ipc_close_client(client_fd);
            return true;
        }

        fprintf(stderr,
            "rejected client pid=%ld uid=%ld gid=%ld: not active seat0 uid\n",
            (long)credentials.pid,
            (long)credentials.uid,
            (long)credentials.gid);
        ksi_ipc_close_client(client_fd);
        return true;
    }

    if (!ensure_active_client_slot(state)) {
        fprintf(stderr,
            "keysharp-input: rejecting active client pid=%ld uid=%ld: global connection limit reached\n",
            (long)credentials.pid, (long)credentials.uid);
        ksi_ipc_close_client(client_fd);
        return true;
    }

    add_client(state, client_fd, &credentials);
    return true;
}

static void process_daemon_command(ksi_daemon_state *state, ksi_daemon_command *command)
{
    if (state == NULL || command == NULL) {
        return;
    }

    switch (command->type) {
        case KSI_DAEMON_COMMAND_CLIENT_IDENTIFIED:
            process_client_identified(state, command);
            break;

        case KSI_DAEMON_COMMAND_CLIENT_PROMPT_DONE:
            process_client_prompt_done(state, command);
            break;

        case KSI_DAEMON_COMMAND_LANE_HOOK_FAILURE: {
            ssize_t client_index = -1;

            for (nfds_t i = 0; i < state->client_count; i++) {
                if (state->clients[i].connection_id
                        == command->connection_id) {
                    client_index = (ssize_t)i;
                    break;
                }
            }

            if (client_index >= 0) {
                record_client_hook_failure(state, (nfds_t)client_index,
                    command->data.hook_failure.hook_type,
                    command->data.hook_failure.event_id,
                    command->data.hook_failure.nesting_depth,
                    command->data.hook_failure.elapsed_ms,
                    command->data.hook_failure.reason);
            }

            break;
        }
    }
}

static void process_daemon_commands(ksi_daemon_state *state)
{
    ksi_daemon_command command;

    if (state == NULL || state->commands == NULL) {
        return;
    }

    while (ksi_pipe_ring_pop(&state->commands->ring, &command)) {
        process_daemon_command(state, &command);
        free_daemon_command(&command);
    }
}
