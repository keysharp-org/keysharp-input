/* Ends the holds a connection made, or with a hook type only that hook's. */
static void release_connection_output(
    ksi_daemon_state *state, uint64_t connection_id, uint32_t hook_type)
{
    const ksi_synth_owner owner = { .connection_id = connection_id, .hook_type = hook_type };

    if (!output_queue_push_release_owner(&state->output_queue, &owner)) {
        fprintf(stderr, "keysharp-input: failed to enqueue synthetic output release\n");
        request_fail_open(state);
    }
}

static void remove_client(ksi_daemon_state *state, nfds_t index)
{
    ksi_client *clients = state->clients;
    nfds_t * const count = &state->client_count;
    const uint64_t connection_id = clients[index].connection_id;

    hook_send_ref_invalidate(clients[index].hook_send_ref);
    hook_send_ref_release(clients[index].hook_send_ref);
    clients[index].hook_send_ref = NULL;
    free(clients[index].rx_buffer);
    clients[index].rx_buffer = NULL;
    free(clients[index].observer_queue);
    clients[index].observer_queue = NULL;

    /* Snapshot refs remain alive but invalid. Their lane waiters wake immediately,
     * so one disconnect never flushes unrelated scripts or hook types. */
    for (nfds_t i = index; i + 1 < *count; i++) {
        clients[i] = clients[i + 1];
    }

    (*count)--;
    update_observer_callbacks(state);

    /* Also stops the output queue admitting this client's late output. */
    if (update_grab_state(state) != 0) {
        fprintf(stderr, "keysharp-input: failed to update grab state after client removal\n");
    }

    /* The client's holds end after the batches it had already sent. The last
     * client out also ends every synthetic hold, since no survivor's hold can be
     * clobbered then. */
    if (!synthetic_hook_queue_push_release(&state->synthetic_hook_queue, connection_id)) {
        release_connection_output(state, connection_id, 0u);
        if (*count == 0) (void)output_queue_push_release_generic(&state->output_queue);
    }
}
