#ifndef KEYSHARP_INPUT_INTERNAL_LINUX_DEVICES_H
#define KEYSHARP_INPUT_INTERNAL_LINUX_DEVICES_H

#include <poll.h>
#include <stdint.h>
#include <keysharp_input/devices.h>

#include "internal/linux_forward.h"
#include "internal/platform.h"

/* replay is what passing the event writes to the source's outputs. */
typedef void (*ksi_physical_hook_callback)(
    void *context, uint32_t hook_type, const void *event, size_t event_size,
    const ksi_forward_packet *replay);
/* Backspace+Esc+Enter are held together. */
typedef void (*ksi_panic_callback)(void *context);
typedef void (*ksi_device_change_callback)(void *context, uint32_t kind,
    const ksi_device_info *device, uint64_t generation);
typedef void (*ksi_raw_device_callback)(void *context, const ksi_raw_input_event *event);
/* Returns whether the packet was admitted. */
typedef bool (*ksi_physical_forward_callback)(void *context, uint32_t hook_type,
    const ksi_forward_packet *replay);
/* End a source's grab and close it in output-queue order; see
 * ksi_linux_forward_end_grab and ksi_linux_forward_close. */
typedef uint64_t (*ksi_forward_end_grab_callback)(void *context, uint64_t target, uint8_t *kept);
typedef void (*ksi_forward_close_callback)(void *context, uint64_t target);

/* Sources and our own outputs share the table; the udev monitor adds one
 * more polled descriptor. */
#define KSI_MAX_TRACKED_DEVICES 256
#define KSI_LINUX_MAX_POLL_FDS (1u + KSI_MAX_TRACKED_DEVICES)

int ksi_linux_devices_start(void);
bool ksi_linux_devices_has_candidates(void);
void ksi_linux_devices_stop(void);
/* Registers current and future sources for forwarding and tags our own
 * outputs; called once a client may need interception. */
void ksi_linux_devices_enable_forwarding(void);
nfds_t ksi_linux_devices_poll_fds(struct pollfd *fds, nfds_t max_fds);
void ksi_linux_devices_process_fd(int fd);
void ksi_linux_devices_drain_pending_input(void);
int ksi_linux_devices_set_grab_hook_mask(uint32_t hook_mask);
int ksi_linux_devices_set_block_input_mask(uint32_t block_mask);
void ksi_linux_devices_retry_incomplete_grabs(void);
bool ksi_linux_devices_peek_oldest_pending_event(int *out_fd, uint64_t *out_time_ns);
void ksi_linux_devices_set_hook_event_callback(ksi_physical_hook_callback callback, void *context);
void ksi_linux_devices_set_forward_event_callback(ksi_physical_forward_callback callback,
    ksi_forward_end_grab_callback end_grab, ksi_forward_close_callback close_source, void *context);
void ksi_linux_devices_set_observer_callback(ksi_hook_event_callback callback,
    ksi_device_change_callback device_callback, void *context);
void ksi_linux_devices_set_raw_observer_callback(ksi_raw_device_callback callback, void *context);
uint64_t ksi_linux_devices_generation(void);
size_t ksi_linux_devices_list(uint32_t offset, ksi_device_info *entries,
    size_t capacity, uint32_t *next_offset);
size_t ksi_linux_gamepads_list(uint32_t offset, ksi_device_info *entries,
    size_t capacity, uint32_t *next_offset);
bool ksi_linux_gamepad_state(uint32_t device_id, ksi_gamepad_state *state);
void ksi_linux_devices_set_panic_callback(ksi_panic_callback callback, void *context);
void ksi_linux_devices_get_indicator_state(bool *caps_lock, bool *num_lock, bool *scroll_lock);
void ksi_linux_devices_refresh_indicator_state(void);
bool ksi_linux_devices_get_pointer_position(ksi_pointer_position_payload *position);
bool ksi_linux_devices_get_pointer_buttons(ksi_pointer_buttons_payload *result);
/* Device queries fill logical_keys and physical_keys for that source only; the
 * modifier mask and lock state always describe the seat. */
bool ksi_linux_devices_get_device_key_state(uint32_t device_id, ksi_key_state_payload *result);
bool ksi_linux_devices_get_modifier_state(ksi_modifier_state_payload *result);
bool ksi_linux_devices_get_idle_time(ksi_idle_time_payload *result);

#endif
