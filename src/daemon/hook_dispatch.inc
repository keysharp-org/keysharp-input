/* A key or button transition, or a report's end, must not overtake input still
 * queued in its lane: a release would precede its press, or a report would be
 * ended before its key. */
static bool keeps_lane_order(const ksi_lane_egress *egress, bool physical_input)
{
    const ksi_forward_packet *packet = &egress->replay;

    return physical_input
        && ((ksi_forward_key_values(packet) & (KSI_FORWARD_KEY_UP | KSI_FORWARD_KEY_DOWN)) != 0u
            || (packet->count == 1u && packet->events[0].type == EV_SYN
                && packet->events[0].code == SYN_REPORT));
}

/* Passes an event its lane could not take. One that keeps lane order fails
 * open instead, and ending the grab releases what the source's outputs hold. */
static void complete_hook_dispatch_fallback(
    ksi_daemon_state *state,
    const ksi_lane_egress *egress,
    ksi_synth_completion *completion,
    bool physical_input,
    uint64_t input_generation)
{
    bool ok = !keeps_lane_order(egress, physical_input)
        && enqueue_egress(state, egress, input_generation);

    if (completion != NULL) {
        if (ok) {
            synth_completion_complete(completion);
        } else {
            synth_completion_fail(completion, KSI_STATUS_RESOURCE_EXHAUSTED,
                KSI_DETAIL_NONE);
        }

        synthetic_hook_queue_complete_inflight(state);
    }

    if (!ok && physical_input) {
        request_fail_open(state);
    }
}

static ksi_lane_event *create_hook_lane_event(
    ksi_daemon_state *state,
    uint32_t hook_type,
    const void *event,
    size_t event_size,
    const ksi_lane_egress *egress,
    ksi_synth_completion *completion,
    uint32_t nesting_depth,
    uint64_t input_generation)
{
    ksi_hook_lane *lane;
    ksi_lane_event *lane_event;
    ksi_lane_subscriber candidates[KSI_MAX_CLIENTS];
    size_t candidate_count = 0u;
    uint64_t event_id;
    uint32_t subscription_bit;
    size_t lane_index;

    lane = lane_for_hook_type(state, hook_type);

    if (lane == NULL || event_size > sizeof(lane_event->payload.event)) {
        return NULL;
    }

    subscription_bit = hook_type_to_operation(hook_type);

    if (subscription_bit == 0u) {
        return NULL;
    }

    event_id = state->next_event_id++;
    lane_index = hook_type_to_lane_index(hook_type);

    /* As on Windows, the newest subscription to a hook type runs first, ordered by
     * subscription ordinal rather than connection age (the id breaks ties in zeroed
     * fixtures). Raw report fragments carry no hook payload, so they collect none. */
    for (nfds_t i = state->client_count;
            event_size != 0u &&
            i-- > 0 && candidate_count < KSI_MAX_CLIENTS; ) {
        const ksi_client *c = &state->clients[i];
        ksi_lane_subscriber candidate;
        size_t position;

        if (c->permission_refresh_pending
            || (c->hook_subscriptions & subscription_bit) == 0u
            || (c->quarantined_hooks & subscription_bit) != 0u
            || !input_owner_matches_uid(state, c->uid)) {
            continue;
        }

        candidate = (ksi_lane_subscriber) {
            .send_ref = c->hook_send_ref,
            .connection_id = c->connection_id,
            .subscription_ordinal = c->hook_subscription_ordinal[lane_index],
        };

        position = candidate_count;

        while (position > 0u
            && (candidate.subscription_ordinal
                    > candidates[position - 1u].subscription_ordinal
                || (candidate.subscription_ordinal
                        == candidates[position - 1u].subscription_ordinal
                    && candidate.connection_id
                        > candidates[position - 1u].connection_id))) {
            candidates[position] = candidates[position - 1u];
            position--;
        }

        candidates[position] = candidate;
        candidate_count++;
    }

    lane_event = lane_event_pool_acquire(lane);

    if (lane_event == NULL) {
        lane_event = calloc(1, sizeof(*lane_event));
    }

    if (lane_event == NULL) {
        return NULL;
    }

    lane_event->event_id = event_id;
    lane_event->hook_type = hook_type;
    lane_event->generation = atomic_load(&lane->flush_generation);
    lane_event->input_generation = input_generation;
    lane_event->synthetic_completion = completion;
    lane_event->nesting_depth = nesting_depth;

    lane_event->egress = *egress;

    lane_event->payload.hook_type = hook_type;
    if (event_size != 0u) memcpy(&lane_event->payload.event, event, event_size);
    lane_event->payload_size =
        sizeof(lane_event->payload.hook_type)
        + sizeof(lane_event->payload.reserved)
        + event_size;

    for (size_t i = 0u; i < candidate_count; i++) {
        ksi_lane_subscriber candidate = candidates[i];

        if (!hook_send_ref_acquire(candidate.send_ref)) {
            fprintf(stderr, "keysharp-input: hook subscriber has no send handle\n");
            continue;
        }

        lane_event->subscribers[lane_event->subscriber_count++] = candidate;
    }

    return lane_event;
}

static void enqueue_hook_lane_event(ksi_daemon_state *state, ksi_lane_event *event)
{
    ksi_hook_lane *lane = lane_for_hook_type(state, event->hook_type);
    size_t reserve = keeps_lane_order(&event->egress, event->physical_input)
        ? 0u : KSI_LANE_TRANSITION_RESERVE;

    if (event->physical_input) {
        atomic_fetch_add(&state->physical_hook_inflight, 1u);
    }

    if (!ksi_pipe_ring_push_reserved(&lane->action_queue.ring, &event, reserve)) {
        fprintf(stderr, "keysharp-input: hook lane queue full; bypassed hook event %llu\n",
            (unsigned long long)event->event_id);
        lane_event_release_send_refs(event);
        complete_hook_dispatch_fallback(state, &event->egress, event->synthetic_completion,
            event->physical_input, event->input_generation);

        if (event->physical_input) {
            atomic_fetch_sub(&state->physical_hook_inflight, 1u);
        }

        lane_event_dispose(event);
    }
}

static void dispatch_hook_event_to_lane(
    ksi_daemon_state *state,
    uint32_t hook_type,
    const void *event,
    size_t event_size,
    const ksi_lane_egress *egress,
    ksi_synth_completion *completion,
    bool physical_input,
    uint64_t input_generation)
{
    ksi_lane_event *lane_event = create_hook_lane_event(
        state, hook_type, event, event_size, egress, completion, 0u,
        input_generation);

    if (lane_event == NULL) {
        complete_hook_dispatch_fallback(
            state, egress, completion, physical_input, input_generation);
        return;
    }

    lane_event->physical_input = physical_input;
    enqueue_hook_lane_event(state, lane_event);
}

static void push_source_state(ksi_daemon_state *state, const ksi_forward_packet *packet)
{
    if (!output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE,
            packet, current_input_generation(state))) {
        request_fail_open(state);
    }
}

/* Raw fragments share their class's lane, so each report keeps its order. A
 * release from an ungrabbed source has no hook form and nothing of its source
 * waits in a lane, so it is queued directly. */
static bool daemon_forward_physical_event(
    void *context, uint32_t hook_type, const ksi_forward_packet *replay)
{
    ksi_daemon_state *state = context;
    ksi_lane_egress egress = { .type = KSI_LANE_EGRESS_REPLAY, .replay = *replay };
    uint64_t input_generation = current_input_generation(state);

    if ((replay->flags & KSI_FORWARD_UNGRABBED) != 0u) {
        return output_queue_push_packet(&state->output_queue, KSI_OUTPUT_ACTION_SOURCE_STATE,
                replay, input_generation)
            && output_queue_push_replay(&state->output_queue, replay, input_generation);
    }
    /* Input read while no seat owner is active reaches nobody. */
    if (state->input_owner_enforced
        && !atomic_load_explicit(&state->active_input_uid_valid, memory_order_acquire)) {
        return true;
    }
    push_source_state(state, replay);
    dispatch_hook_event_to_lane(state, hook_type, NULL, 0u, &egress, NULL, true, input_generation);
    return true;
}

static uint64_t daemon_end_forward_grab(void *context, uint64_t target, uint8_t *kept)
{
    return output_queue_push_end_grab(&((ksi_daemon_state *)context)->output_queue, target, kept);
}

static void daemon_close_forward(void *context, uint64_t target)
{
    output_queue_push_close(&((ksi_daemon_state *)context)->output_queue, target);
}

/* The main loop applies it, since the reader may be switching a grab. */
static void daemon_handle_panic(void *context)
{
    ksi_daemon_state *state = context;

    if (!state->interception_active) return;
    fprintf(stderr, "keysharp-input: physical input panic chord activated\n");
    request_fail_open(state);
}

static void daemon_handle_hook_event(
    void *context,
    uint32_t hook_type,
    const void *event,
    size_t event_size,
    const ksi_forward_packet *replay)
{
    ksi_daemon_state *state = context;
    uint32_t subscription_bit = hook_type_to_operation(hook_type);
    uint32_t block_bit;
    bool is_injected;

    if (state == NULL || subscription_bit == 0
        || (state->input_owner_enforced
            && !atomic_load_explicit(
                &state->active_input_uid_valid, memory_order_acquire))) {
        return;
    }

    push_source_state(state, replay);

    block_bit = hook_type == KSI_HOOK_KEYBOARD
        ? KSI_BLOCK_KEYBOARD
        : KSI_BLOCK_MOUSE;
    is_injected = hook_type == KSI_HOOK_KEYBOARD
        ? ((((const ksi_keyboard_hook_event *)event)->flags & KSI_KEYBOARD_HOOK_INJECTED) != 0)
        : ((((const ksi_mouse_hook_event *)event)->flags & KSI_MOUSE_HOOK_INJECTED) != 0);

    /* The hook that blocks input still sees events so it can unblock; only egress
     * is suppressed. Events of a class nobody hooks (a combined device grabbed for
     * the other class) still take their lane, which keeps each report in order. */
    bool block_active = !is_injected && (active_block_input_mask(state) & block_bit) != 0;
    ksi_lane_egress egress = {
        .type = (is_injected || block_active) ? KSI_LANE_EGRESS_NONE : KSI_LANE_EGRESS_REPLAY,
        .replay = *replay,
    };

    dispatch_hook_event_to_lane(
        state, hook_type, event, event_size, &egress, NULL, true,
        current_input_generation(state));
}
