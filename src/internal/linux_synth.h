#ifndef KEYSHARP_INPUT_INTERNAL_LINUX_SYNTH_H
#define KEYSHARP_INPUT_INTERNAL_LINUX_SYNTH_H

#include "internal/protocol.h"
#include "internal/linux_forward.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Who holds a synthetic key. A Modify replacement of physical input names its
 * source's target, responder, hook class and the key it replaces; a Send
 * names only its connection. Zero fields in a release filter match any value. */
typedef struct ksi_synth_owner {
    uint64_t target;
    uint64_t connection_id;
    uint32_t hook_type;
    uint16_t source_type;
    uint16_t source_code;
} ksi_synth_owner;

int ksi_linux_synth_start(void);
void ksi_linux_synth_stop(void);
bool ksi_linux_synth_is_started(void);
bool ksi_linux_synth_is_available(void);
/* True only while the second (absolute pointer) uinput device exists. Its
 * creation is deliberately non-fatal, so the relative device can be usable when
 * absolute MouseMove is not; callers must gate absolute output on this rather
 * than on ksi_linux_synth_is_available(). */
bool ksi_linux_synth_absolute_is_available(void);
/* Main thread: whether a write failure calls for recreation (rate limited).
 * It does not touch the devices. */
bool ksi_linux_synth_needs_recovery(void);
/* Output sequencer only, since it replaces the devices that thread writes. */
void ksi_linux_synth_recreate(void);
int ksi_linux_synth_send_input(const ksi_input *inputs, size_t count, uint32_t flags,
    const ksi_synth_owner *owner);
bool ksi_linux_synth_input_to_hook_event(
    const ksi_input *input,
    uint32_t *hook_type,
    ksi_hook_event_payload *event,
    size_t *event_size);
/* Releases the generic devices only; forwarded holds belong to linux_forward. */
void ksi_linux_synth_release_all(void);
/* ENQUEUED runs when the release is admitted, APPLIED when it drains. */
void ksi_linux_synth_release_owner(const ksi_synth_owner *filter, ksi_forward_view view);
/* Sequencer: releases Modify holds whose source target has ended and destroys
 * retired forwarding devices. */
void ksi_linux_synth_maintain_output(void);
/* A physical key-up ends every Modify hold derived from it. Unless a hook
 * suppressed it, it also ends every generic hold of that key, as a Win32
 * key-up that reaches the system does. */
void ksi_linux_synth_physical_release(const ksi_forward_packet *packet, ksi_forward_view view);

/* Enqueue-time holds, reported by key-state queries. note_enqueued_synth runs
 * when a batch is admitted; reset clears the mirror when RELEASE_ALL,
 * RELEASE_GENERIC or device recreation is admitted. */
void ksi_linux_synth_add_logical_key_state(uint8_t *keys, size_t key_bytes);
void ksi_linux_synth_note_enqueued_synth(const ksi_input *inputs, size_t count,
    const ksi_synth_owner *owner);
void ksi_linux_synth_reset_enqueued_synth(void);

#endif
