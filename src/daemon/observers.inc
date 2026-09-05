static bool observer_active(const ksi_daemon_state *state, const ksi_client *client)
{
    return client->observer_subscriptions != 0u
        && client_has_scope(client, KSP_SCOPE_INPUT_MONITORING)
        && input_owner_matches_uid(state, client->uid)
        && hook_send_ref_is_valid(client->hook_send_ref);
}

static bool observer_enqueue(ksi_client *client, uint32_t kind,
    uint64_t generation, uint64_t event_id, const void *body, size_t body_size,
    uint64_t dropped)
{
    if (client->observer_queue == NULL
        || client->observer_count == KSI_OBSERVER_QUEUE_CAPACITY) return false;
    uint32_t index = (client->observer_head + client->observer_count) % KSI_OBSERVER_QUEUE_CAPACITY;
    ksi_observer_frame *frame = &client->observer_queue[index];
    memset(frame->payload, 0, KSI_OBSERVER_PREFIX_SIZE);
    ksi_wire_write_u32(frame->payload, kind);
    ksi_wire_write_u64(frame->payload + 8u, generation);
    ksi_wire_write_u64(frame->payload + 16u, dropped);
    if (body_size != 0u) memcpy(frame->payload + KSI_OBSERVER_PREFIX_SIZE, body, body_size);
    frame->size = (uint32_t)(KSI_OBSERVER_PREFIX_SIZE + body_size);
    frame->event_id = event_id;
    client->observer_count++;
    return true;
}

static void observer_publish(ksi_daemon_state *state, uint32_t kind,
    uint32_t subscription, uint64_t generation, uint64_t event_id,
    const void *body, size_t size)
{
    for (nfds_t i = 0; i < state->client_count; i++) {
        ksi_client *client = &state->clients[i];
        if (!observer_active(state, client)
            || (subscription != 0u && (client->observer_subscriptions & subscription) == 0u)) continue;
        if (client->observer_dropped != 0u
            && observer_enqueue(client, KSI_OBSERVER_OVERFLOW, generation, 0u,
                NULL, 0u, client->observer_dropped)) client->observer_dropped = 0u;
        if (!observer_enqueue(client, kind, generation, event_id, body, size, 0u)
            && client->observer_dropped != UINT64_MAX) client->observer_dropped++;
    }
}

static void daemon_observe_input(void *context, uint32_t hook_type,
    const void *event, size_t size)
{
    ksi_daemon_state *state = context;
    ksi_hook_event_payload payload = { .hook_type = hook_type };
    uint8_t wire[KSI_HOOK_EVENT_PREFIX_SIZE + KSI_MOUSE_HOOK_EVENT_SIZE];
    if (size > sizeof(payload.event)) return;
    memcpy(&payload.event, event, size);
    size_t wire_size = ksi_protocol_encode_hook_event(wire, &payload, hook_type);
    if (wire_size != 0u) observer_publish(state, KSI_OBSERVER_INPUT,
        hook_type_to_operation(hook_type), ksi_linux_devices_generation(),
        0u, wire, wire_size);
}

static void daemon_observe_device(void *context, uint32_t kind,
    const ksi_device_info *device, uint64_t generation)
{
    uint8_t wire[KSI_DEVICE_INFO_WIRE_SIZE];
    ksi_device_encode(wire, device);
    observer_publish(context, kind, 0u, generation, 0u, wire, sizeof(wire));
}

static void daemon_observe_raw(void *context, const ksi_raw_input_event *event)
{
    uint8_t wire[KSI_RAW_INPUT_WIRE_SIZE] = {0};
    ksi_wire_write_u32(wire, event->device_id);
    ksi_wire_write_u64(wire + 8u, event->time_ms);
    ksi_device_write(wire + 16u, event->type, 2u);
    ksi_device_write(wire + 18u, event->code, 2u);
    ksi_wire_write_u32(wire + 20u, (uint32_t)event->value);
    ksi_wire_write_u32(wire + 24u, event->flags);
    observer_publish(context, KSI_OBSERVER_RAW_INPUT, KSI_OPERATION_HOOK_MOUSE,
        ksi_linux_devices_generation(), 0u, wire, sizeof(wire));
}

static void update_observer_callbacks(ksi_daemon_state *state)
{
    bool active = false;
    for (nfds_t i = 0; i < state->client_count; i++)
        active |= state->clients[i].observer_subscriptions != 0u;
    ksi_linux_devices_set_observer_callback(active ? daemon_observe_input : NULL,
        active ? daemon_observe_device : NULL, active ? state : NULL);
    ksi_linux_devices_set_raw_observer_callback(active ? daemon_observe_raw : NULL,
        active ? state : NULL);
}

static void flush_observers(ksi_daemon_state *state)
{
    for (nfds_t i = 0; i < state->client_count; i++) {
        ksi_client *client = &state->clients[i];
        if (!observer_active(state, client)) {
            client->observer_count = 0u;
            client->observer_dropped = 0u;
            continue;
        }
        for (size_t budget = 0u; budget < 32u && client->observer_count != 0u; budget++) {
            ksi_observer_frame *frame = &client->observer_queue[client->observer_head];
            if (hook_send_ref_try_send(client->hook_send_ref, KSI_OPCODE_OBSERVER_EVENT,
                    KSI_FRAME_FLAG_EVENT, frame->event_id, frame->payload, frame->size) != 1) break;
            client->observer_head = (client->observer_head + 1u) % KSI_OBSERVER_QUEUE_CAPACITY;
            client->observer_count--;
        }
        if (client->observer_dropped != 0u
            && observer_enqueue(client, KSI_OBSERVER_OVERFLOW,
                ksi_linux_devices_generation(), 0u, NULL, 0u, client->observer_dropped))
            client->observer_dropped = 0u;
    }
}
