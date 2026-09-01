#ifndef KEYSHARP_INPUT_INTERNAL_PLATFORM_H
#define KEYSHARP_INPUT_INTERNAL_PLATFORM_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>

#include "internal/protocol.h"

typedef void (*ksi_hook_event_callback)(
    void *context,
    uint32_t hook_type,
    const void *event,
    size_t event_size);

typedef struct ksi_platform_backend {
    const char *name;
    int (*start)(void);
    void (*stop)(void);
    /* Lazily initialize resources required by the requested permission scopes. */
    void (*prepare_scopes)(uint32_t requested_scopes);
    uint64_t (*get_available_operations)(void);
    uint64_t (*get_ready_operations)(void);
    nfds_t (*poll_fds)(struct pollfd *fds, nfds_t max_fds);
    void (*process_fd)(int fd);
    /* Drain already-queued device input and return the elapsed time from the
     * newest upstream user-input event. Runs on the daemon main thread and may
     * be NULL. */
    bool (*get_idle_time)(ksi_idle_time_payload *result);
    /* Kernel CLOCK_MONOTONIC timestamp in nanoseconds, used only for admission
     * ordering. Public hook timestamps retain their Windows-compatible units. */
    bool (*peek_oldest_pending_input)(int *out_fd, uint64_t *out_time_ns);
    bool (*input_to_hook_event)(
        const ksi_input *input,
        uint32_t *hook_type,
        ksi_hook_event_payload *event,
        size_t *event_size);
    int (*send_input)(const ksi_input *inputs, size_t count, uint32_t flags);
    int (*replay_hook_event)(uint32_t hook_type, const ksi_hook_event_payload *event);
    int (*set_grab_hook_mask)(uint32_t hook_mask);
    int (*set_block_input_mask)(uint32_t block_mask);
    void (*set_hook_event_callback)(ksi_hook_event_callback callback, void *context);
    /* Called only by the output sequencer, serialized with replay and synthesis. */
    void (*release_synthetic_keys)(void);
    /* Main-thread detector; recreation stays on the output sequencer. */
    bool (*synth_needs_recovery)(void);
    /* Called only by the output sequencer after a synthetic write failure. */
    void (*recreate_synth)(void);
    /* Lets the backend retry transient failures from the daemon's main thread.
     * The backend rate-limits its work. May be NULL. */
    void (*periodic_maintenance)(void);
} ksi_platform_backend;

const ksi_platform_backend *ksi_platform_backend_get(void);

#endif
