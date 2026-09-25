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
    int (*set_grab_hook_mask)(uint32_t hook_mask);
    int (*set_block_input_mask)(uint32_t block_mask);
    /* Lets the backend retry transient failures from the daemon's main thread.
     * The backend rate-limits its work. May be NULL. */
    void (*periodic_maintenance)(void);
} ksi_platform_backend;

const ksi_platform_backend *ksi_platform_backend_get(void);

#endif
