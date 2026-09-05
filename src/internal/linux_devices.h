#ifndef KEYSHARP_INPUT_INTERNAL_LINUX_DEVICES_H
#define KEYSHARP_INPUT_INTERNAL_LINUX_DEVICES_H

#include <poll.h>
#include <stdint.h>
#include <keysharp_input/devices.h>

#include "internal/platform.h"

typedef void (*ksi_physical_key_event_callback)(void *context, uint32_t scan_code);
typedef void (*ksi_device_change_callback)(void *context, uint32_t kind,
    const ksi_device_info *device, uint64_t generation);
typedef void (*ksi_raw_device_callback)(void *context, const ksi_raw_input_event *event);

int ksi_linux_devices_start(void);
bool ksi_linux_devices_has_candidates(void);
void ksi_linux_devices_stop(void);
void ksi_linux_devices_rescan(void);
nfds_t ksi_linux_devices_poll_fds(struct pollfd *fds, nfds_t max_fds);
void ksi_linux_devices_process_fd(int fd);
void ksi_linux_devices_drain_pending_input(void);
int ksi_linux_devices_set_grab_hook_mask(uint32_t hook_mask);
int ksi_linux_devices_set_block_input_mask(uint32_t block_mask);
void ksi_linux_devices_retry_incomplete_grabs(void);
bool ksi_linux_devices_peek_oldest_pending_event(int *out_fd, uint64_t *out_time_ns);
void ksi_linux_devices_set_hook_event_callback(ksi_hook_event_callback callback, void *context);
void ksi_linux_devices_set_observer_callback(ksi_hook_event_callback callback,
    ksi_device_change_callback device_callback, void *context);
void ksi_linux_devices_set_raw_observer_callback(ksi_raw_device_callback callback, void *context);
uint64_t ksi_linux_devices_generation(void);
size_t ksi_linux_devices_list(uint32_t offset, ksi_device_info *entries,
    size_t capacity, uint32_t *next_offset);
void ksi_linux_devices_set_physical_key_event_callback(
    ksi_physical_key_event_callback callback,
    void *context);
void ksi_linux_devices_get_indicator_state(bool *caps_lock, bool *num_lock, bool *scroll_lock);
void ksi_linux_devices_refresh_indicator_state(void);
bool ksi_linux_devices_get_pointer_position(ksi_pointer_position_payload *position);
bool ksi_linux_devices_get_pointer_buttons(ksi_pointer_buttons_payload *result);
bool ksi_linux_devices_get_key_state(ksi_key_state_payload *result);
bool ksi_linux_devices_get_modifier_state(ksi_modifier_state_payload *result);
bool ksi_linux_devices_get_idle_time(ksi_idle_time_payload *result);

#endif
