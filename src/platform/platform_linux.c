#include "internal/platform.h"
#include "protocol_internal.h"

#include "internal/linux_devices.h"
#include "internal/linux_forward.h"
#include "internal/linux_synth.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static int linux_start(void)
{
    puts("linux input backend started");

    if (ksi_linux_devices_start() != 0) {
        return -1;
    }

    return 0;
}

static void linux_prepare_scopes(uint32_t requested_scopes)
{
    if ((requested_scopes & KSI_INPUT_PERMISSION_SCOPES) == 0u
        || ksi_linux_synth_is_started()) {
        return;
    }

    /* The idle service owns no uinput devices until an identified client asks for
     * privileged input; the synchronous rescan then tags ours and registers every
     * source before any grab. Nothing can be queued yet, as nothing is granted. */
    (void)ksi_linux_synth_start();

    if (ksi_linux_synth_is_available()) {
        ksi_linux_devices_enable_forwarding();
    }
}

static uint64_t linux_get_available_operations(void)
{
    return KSI_OPERATION_ALL;
}

static uint64_t linux_get_ready_operations(void)
{
    uint64_t operations = KSI_OPERATION_QUERY_INDICATORS
        | KSI_OPERATION_QUERY_POINTER_POSITION
        | KSI_OPERATION_QUERY_IDLE_TIME
        | KSI_OPERATION_QUERY_MODIFIERS
        | KSI_OPERATION_QUERY_DEVICES
        | KSI_OPERATION_QUERY_GAMEPADS
        | KSI_OPERATION_OBSERVE_KEYBOARD
        | KSI_OPERATION_OBSERVE_MOUSE;
    bool synth_available = ksi_linux_synth_is_available();

    if (synth_available) {
        operations |= KSI_OPERATION_SYNTHESIZE_KEYBOARD
            | KSI_OPERATION_SYNTHESIZE_MOUSE;

        /* Daemon-internal; never advertised. See the definition. */
        if (ksi_linux_synth_absolute_is_available()) {
            operations |= KSI_INTERNAL_OPERATION_SYNTHESIZE_MOUSE_ABSOLUTE;
        }
    }
    if (ksi_linux_devices_has_candidates()) {
        operations |= KSI_OPERATION_QUERY_KEY_STATE
            | KSI_OPERATION_QUERY_POINTER_BUTTONS;
        if (synth_available) {
            operations |= KSI_OPERATION_HOOK_KEYBOARD
                | KSI_OPERATION_HOOK_MOUSE
                | KSI_OPERATION_BLOCK_INPUT;
        }
    }
    return operations;
}

static void linux_stop(void)
{
    ksi_linux_devices_stop();
    ksi_linux_synth_stop();
    ksi_linux_forward_collect(true);
    puts("linux input backend stopped");
}

static nfds_t linux_poll_fds(struct pollfd *fds, nfds_t max_fds)
{
    return ksi_linux_devices_poll_fds(fds, max_fds);
}

static void linux_process_fd(int fd)
{
    ksi_linux_devices_process_fd(fd);
}

static bool linux_get_idle_time(ksi_idle_time_payload *result)
{
    ksi_linux_devices_drain_pending_input();
    return ksi_linux_devices_get_idle_time(result);
}

static bool linux_peek_oldest_pending_input(int *out_fd, uint64_t *out_time_ns)
{
    return ksi_linux_devices_peek_oldest_pending_event(out_fd, out_time_ns);
}

static int linux_set_grab_hook_mask(uint32_t hook_mask)
{
    return ksi_linux_devices_set_grab_hook_mask(hook_mask);
}

/* Synthetic-device recovery is queued to the output sequencer instead, since
 * recreating the devices here would race its writes. */
static void linux_periodic_maintenance(void)
{
    ksi_linux_devices_retry_incomplete_grabs();
}

static int linux_set_block_input_mask(uint32_t block_mask)
{
    return ksi_linux_devices_set_block_input_mask(block_mask);
}

static const ksi_platform_backend linux_backend = {
    .name = "linux",
    .start = linux_start,
    .stop = linux_stop,
    .prepare_scopes = linux_prepare_scopes,
    .get_available_operations = linux_get_available_operations,
    .get_ready_operations = linux_get_ready_operations,
    .poll_fds = linux_poll_fds,
    .process_fd = linux_process_fd,
    .get_idle_time = linux_get_idle_time,
    .peek_oldest_pending_input = linux_peek_oldest_pending_input,
    .set_grab_hook_mask = linux_set_grab_hook_mask,
    .set_block_input_mask = linux_set_block_input_mask,
    .periodic_maintenance = linux_periodic_maintenance,
};

const ksi_platform_backend *ksi_platform_backend_get(void)
{
    return &linux_backend;
}
