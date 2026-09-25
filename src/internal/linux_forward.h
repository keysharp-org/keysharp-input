#ifndef KEYSHARP_INPUT_INTERNAL_LINUX_FORWARD_H
#define KEYSHARP_INPUT_INTERNAL_LINUX_FORWARD_H

#include <linux/input-event-codes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define KSI_FORWARD_PHYS_PREFIX "keysharp-input/forward/"
#define KSI_MAX_FORWARDING_DEVICES 128u
#define KSI_FORWARD_PACKET_EVENTS 2u
/* The packet completes its source report, so the write appends SYN_REPORT.
 * Other packets are fragments ended by the source's own forwarded SYN. */
#define KSI_FORWARD_REPORT_END 0x00000001u
/* A release a hook suppressed. It still reaches the source's outputs, which
 * ignore a key the source does not hold there, but it does not end synthetic
 * holds of the key. */
#define KSI_FORWARD_SUPPRESSED 0x00000002u
/* The source is no longer grabbed, so the packet has no hook form. */
#define KSI_FORWARD_UNGRABBED 0x00000004u
/* The packet goes to the source's own clone rather than the keyboard sink.
 * The reader sets it for the mouse lane, so each lane ends its report on the
 * device that carried it. */
#define KSI_FORWARD_CLONE 0x00000008u

/* Raw evdev values of passed physical input, kept outside the client protocol.
 * A target names one grab of one source, so a decision delayed past an ungrab
 * or unplug cannot reach its outputs. */
typedef struct ksi_forward_event {
    uint16_t type;
    uint16_t code;
    int32_t value;
} ksi_forward_event;

typedef struct ksi_forward_packet {
    uint64_t target;
    uint32_t count;
    uint32_t flags;
    ksi_forward_event events[KSI_FORWARD_PACKET_EVENTS];
} ksi_forward_packet;

#define KSI_FORWARD_KEY_UP (1u << 0)
#define KSI_FORWARD_KEY_DOWN (1u << 1)

/* Bit n is set when the packet carries an EV_KEY event of value n, so
 * KSI_FORWARD_KEY_UP marks a release and value 2 a repeat. */
static inline uint32_t ksi_forward_key_values(const ksi_forward_packet *packet)
{
    uint32_t values = 0u;

    for (uint32_t i = 0u; i < packet->count && i < KSI_FORWARD_PACKET_EVENTS; i++)
        if (packet->events[i].type == EV_KEY && (uint32_t)packet->events[i].value <= 2u)
            values |= 1u << packet->events[i].value;
    return values;
}

/* Key state is kept at two queue positions: what the sequencer has written
 * (APPLIED) and what admitted output will leave once the queue drains
 * (ENQUEUED), which key-state queries report. */
typedef enum ksi_forward_view {
    KSI_FORWARD_APPLIED = 0,
    KSI_FORWARD_ENQUEUED = 1,
} ksi_forward_view;

/* The reader opens and closes sources and holds each one's ENQUEUED target. A
 * keyboard's keyboard keys go to the shared sink; whatever else a source reports
 * goes to its own clone, created only when there is some. */
uint64_t ksi_linux_forward_open(int source_fd, bool keyboard);
bool ksi_linux_forward_has_clone(uint64_t target);
/* Closing is queue-ordered like ending a grab: close forgets the source for
 * admitted output, and apply_close releases and retires its outputs where the
 * queue reaches it. */
void ksi_linux_forward_close(uint64_t target);
void ksi_linux_forward_apply_close(uint64_t target);
/* Ending a grab replaces the target in queue order: end_grab when admitted,
 * apply_end_grab when written. Keys the source still holds (held, or with NULL the
 * view's own record) stay down, since their presses reached only its outputs. */
uint64_t ksi_linux_forward_end_grab(uint64_t target, uint8_t *held);
void ksi_linux_forward_apply_end_grab(uint64_t next, const uint8_t *held);
/* True for an unknown target, or once a clone write has failed. */
bool ksi_linux_forward_failed(uint64_t target, ksi_forward_view view);
bool ksi_linux_forward_take_failure(void);
uint64_t ksi_linux_forward_target_for_path(const char *path);
void ksi_linux_forward_sync_switches(uint64_t target);

/* Output sequencer: returns -1 on a write failure and 0 otherwise, including
 * for a packet whose grab has ended. */
int ksi_linux_forward_write(const ksi_forward_packet *packet);
void ksi_linux_forward_collect(bool shutdown);

/* Queue order; APPLIED calls run on the sequencer and write the outputs. */
void ksi_linux_forward_note_output(const ksi_forward_packet *packet);
void ksi_linux_forward_note_source(const ksi_forward_packet *packet, ksi_forward_view view);
/* Synthesis releases a key every source holds downstream, remembering holds
 * the source still has; a later synthetic press restores them. */
void ksi_linux_forward_release_key(uint16_t code, ksi_forward_view view);
bool ksi_linux_forward_restore_key(uint16_t code, ksi_forward_view view);
void ksi_linux_forward_release_all(ksi_forward_view view);
void ksi_linux_forward_add_key_state(uint64_t target, uint8_t *keys, size_t size);
/* Advances whenever a target stops accepting output in either view. */
uint32_t ksi_linux_forward_epoch(void);

/* The sink is synthesis's keyboard device (a negative fd detaches it). A key is
 * down while synthesis or any source holds it, so only the first press and last
 * release are written. Sequencer; sink_key and sink_tap return events written or -1. */
void ksi_linux_forward_attach_sink(int fd);
/* Advances whenever the sink is detached. */
uint32_t ksi_linux_forward_sink_generation(void);
bool ksi_linux_forward_sink_ready(void);
int ksi_linux_forward_sink_key(uint16_t code, bool held);
int ksi_linux_forward_sink_tap(uint16_t code);
void ksi_linux_forward_sink_clear_synth(void);

#endif
