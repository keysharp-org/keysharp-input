#ifndef KEYSHARP_INPUT_INTERNAL_PROTOCOL_H
#define KEYSHARP_INPUT_INTERNAL_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <keysharp_input/constants.h>

#include "protocol_contract.h"

#define KSI_SYNTH_DEVICE_NAME "Keysharp Virtual Input"
#define KSI_SYNTH_DEVICE_BUSTYPE 0x06u
/* keyd ignores virtual devices with its vendor id. Sharing that id prevents a
 * mutual-grab loop; the distinct device names remain the authoritative identity. */
#define KSI_SYNTH_DEVICE_VENDOR 0x0FACu
#define KSI_SYNTH_DEVICE_PRODUCT 0x0001u
#define KSI_SYNTH_DEVICE_VERSION 1u

/* Second synthetic device: pure-absolute pointer for absolute mouse moves. */
#define KSI_SYNTH_ABS_DEVICE_NAME "Keysharp Virtual Pointer"
#define KSI_SYNTH_ABS_DEVICE_PRODUCT 0x0002u
#define KSI_XBUTTON1 0x0001u
#define KSI_XBUTTON2 0x0002u
/* Indicator-state result body. */
typedef struct ksi_indicator_state_payload {
    uint8_t caps_lock;
    uint8_t num_lock;
    uint8_t scroll_lock;
    uint8_t reserved;
} ksi_indicator_state_payload;

/* Key-state result body.
 *
 * modifiers_lr: bitmask of currently logically-held modifier keys,
 *   using the protocol's stable left/right modifier assignments:
 *     bit 0 = MOD_LCONTROL, bit 1 = MOD_RCONTROL,
 *     bit 2 = MOD_LALT,     bit 3 = MOD_RALT,
 *     bit 4 = MOD_LSHIFT,   bit 5 = MOD_RSHIFT,
 *     bit 6 = MOD_LWIN,     bit 7 = MOD_RWIN.
 * caps_lock, num_lock, scroll_lock: current LED/toggle state (same as
 *   ksi_indicator_state_payload).
 * logical_keys: evdev KEY_* bitmap, one bit per key code.
 * physical_keys: evdev KEY_* bitmap of physically-held keys. */
typedef struct ksi_key_state_payload {
    uint32_t modifiers_lr;
    uint8_t  caps_lock;
    uint8_t  num_lock;
    uint8_t  scroll_lock;
    uint8_t  reserved;
    uint8_t  logical_keys[KSI_KEY_STATE_BITMAP_BYTES];
    uint8_t  physical_keys[KSI_KEY_STATE_BITMAP_BYTES];
} ksi_key_state_payload;

/* Raw absolute axis values from the last evdev ABS_X/ABS_Y pointer report. */
typedef struct ksi_pointer_position_payload {
    uint8_t valid;
    uint8_t reserved[3];
    int32_t x;
    int32_t y;
    int32_t x_min;
    int32_t x_max;
    int32_t y_min;
    int32_t y_max;
} ksi_pointer_position_payload;

/* Pointer-button result body. Snapshot of mouse button state.
 * valid==0 means no readable pointer device. logical_buttons includes synthetic
 * state; physical_buttons is EVIOCGKEY across pointer devices. */
typedef struct ksi_pointer_buttons_payload {
    uint8_t  valid;
    uint8_t  reserved[3];
    uint32_t logical_buttons;  /* bit0=left, bit1=right, bit2=middle, bit3=X1(side), bit4=X2(extra) */
    uint32_t physical_buttons; /* same bit layout */
} ksi_pointer_buttons_payload;

/* Idle-time result body. valid==0 means the daemon has
 * not observed an activity event since it started, so it cannot yet provide a
 * meaningful duration. The explicit padding fixes idle_time_ms at byte 8 on
 * every supported ABI. */
typedef struct ksi_idle_time_payload {
    uint8_t valid;
    uint8_t reserved[7];
    uint64_t idle_time_ms;
} ksi_idle_time_payload;

/* Modifier-state result body. Both masks use the ModLR
 * assignments documented on ksi_key_state_payload. Lock fields are toggle
 * state, not the physical-down state of the lock keys. */
typedef struct ksi_modifier_state_payload {
    uint32_t logical_modifiers_lr;
    uint32_t physical_modifiers_lr;
    uint8_t  caps_lock;
    uint8_t  num_lock;
    uint8_t  scroll_lock;
    uint8_t  reserved;
} ksi_modifier_state_payload;

/* Decoded host-order header. The wire header is always the 24 bytes described
 * by KSI_FRAME_*; it is never read or written as a native C structure. */
typedef struct ksi_message_header {
    uint16_t major;
    uint16_t minor;
    uint16_t opcode;
    uint16_t flags;
    uint32_t payload_length;
    uint64_t request_id;
} ksi_message_header;

static inline uint16_t ksi_wire_read_u16(const uint8_t *source)
{
    return (uint16_t)((uint16_t)source[0]
        | ((uint16_t)source[1] << 8u));
}

static inline uint32_t ksi_wire_read_u32(const uint8_t *source)
{
    return (uint32_t)source[0]
        | ((uint32_t)source[1] << 8u)
        | ((uint32_t)source[2] << 16u)
        | ((uint32_t)source[3] << 24u);
}

static inline uint64_t ksi_wire_read_u64(const uint8_t *source)
{
    return (uint64_t)ksi_wire_read_u32(source)
        | ((uint64_t)ksi_wire_read_u32(source + 4u) << 32u);
}

static inline void ksi_wire_write_u16(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8u);
}

static inline void ksi_wire_write_u32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8u);
    destination[2] = (uint8_t)(value >> 16u);
    destination[3] = (uint8_t)(value >> 24u);
}

static inline void ksi_wire_write_u64(uint8_t *destination, uint64_t value)
{
    ksi_wire_write_u32(destination, (uint32_t)value);
    ksi_wire_write_u32(destination + 4u, (uint32_t)(value >> 32u));
}

static inline bool ksi_frame_header_decode(
    const uint8_t source[KSI_FRAME_HEADER_SIZE],
    ksi_message_header *header)
{
    if (source == NULL || header == NULL
        || source[0] != (uint8_t)'K' || source[1] != (uint8_t)'S'
        || source[2] != (uint8_t)'I' || source[3] != (uint8_t)'P') {
        return false;
    }

    header->major = ksi_wire_read_u16(source + 4u);
    header->minor = ksi_wire_read_u16(source + 6u);
    header->opcode = ksi_wire_read_u16(source + 8u);
    header->flags = ksi_wire_read_u16(source + 10u);
    header->payload_length = ksi_wire_read_u32(source + 12u);
    header->request_id = ksi_wire_read_u64(source + 16u);
    return true;
}

static inline void ksi_frame_header_encode(
    uint8_t destination[KSI_FRAME_HEADER_SIZE],
    const ksi_message_header *header)
{
    destination[0] = (uint8_t)'K';
    destination[1] = (uint8_t)'S';
    destination[2] = (uint8_t)'I';
    destination[3] = (uint8_t)'P';
    ksi_wire_write_u16(destination + 4u, header->major);
    ksi_wire_write_u16(destination + 6u, header->minor);
    ksi_wire_write_u16(destination + 8u, header->opcode);
    ksi_wire_write_u16(destination + 10u, header->flags);
    ksi_wire_write_u32(destination + 12u, header->payload_length);
    ksi_wire_write_u64(destination + 16u, header->request_id);
}

typedef struct ksi_keyboard_hook_event {
    uint32_t message;
    uint32_t vk_code;
    uint32_t scan_code;
    uint32_t flags;
    uint64_t time_ms;
    uint64_t extra_info;
    uint32_t device_id;
    uint32_t reserved;
} ksi_keyboard_hook_event;

typedef struct ksi_mouse_hook_event {
    uint32_t message;
    int32_t x;
    int32_t y;
    uint32_t mouse_data;
    uint32_t flags;
    uint64_t time_ms;
    uint64_t extra_info;
    uint32_t device_id;
    uint32_t reserved;
    int32_t delta_x;
    int32_t delta_y;
} ksi_mouse_hook_event;

typedef struct ksi_keybdinput {
    uint16_t vk;
    uint16_t scan;
    uint32_t flags;
    uint32_t time;
    uint64_t extra_info;
} ksi_keybdinput;

typedef struct ksi_mouseinput {
    int32_t dx;
    int32_t dy;
    uint32_t mouse_data;
    uint32_t flags;
    uint32_t time;
    uint64_t extra_info;
} ksi_mouseinput;

typedef struct ksi_input {
    uint32_t type;
    uint32_t reserved;
    union {
        ksi_mouseinput mouse;
        ksi_keybdinput keyboard;
    } data;
} ksi_input;

typedef struct ksi_status_payload {
    uint32_t status;
    uint32_t detail;
} ksi_status_payload;

typedef enum ksi_status_detail {
    KSI_DETAIL_NONE = 0u,
    KSI_DETAIL_PAYLOAD_SIZE = 1u,
    KSI_DETAIL_VALUE_RANGE = 2u,
    KSI_DETAIL_RESERVED_NONZERO = 3u,
    KSI_DETAIL_WRONG_ROLE = 4u,
    KSI_DETAIL_WRONG_STATE = 5u,
    KSI_DETAIL_UNKNOWN_SCOPE = 6u,
    KSI_DETAIL_UNKNOWN_OPERATION = 7u,
    KSI_DETAIL_STALE_CALLBACK = 8u,
    KSI_DETAIL_RECURSION_LIMIT = 9u,
    KSI_DETAIL_EXPANDED_INPUT_LIMIT = 10u,
} ksi_status_detail;

typedef struct ksi_client_hello_payload {
    uint16_t role;
    uint16_t authorization_mode;
    uint32_t requested_scopes;
    uint64_t reserved;
} ksi_client_hello_payload;

typedef struct ksi_client_hello_result_payload {
    uint32_t granted_scopes;
    uint32_t reserved;
    uint64_t available_operations;
} ksi_client_hello_result_payload;

typedef struct ksi_authorize_payload {
    uint16_t authorization_mode;
    uint16_t reserved0;
    uint32_t requested_scopes;
    uint64_t reserved1;
} ksi_authorize_payload;

typedef struct ksi_authorize_result_payload {
    uint32_t granted_scopes;
    uint32_t reserved;
} ksi_authorize_result_payload;

typedef struct ksi_hook_quarantined_payload {
    uint32_t hook_type;
    uint32_t reason;
    uint64_t event_id;
    uint32_t generation;
    uint32_t strike_count;
    uint32_t retry_after_ms;
    uint32_t reserved;
} ksi_hook_quarantined_payload;

typedef struct ksi_synthesize_input_payload {
    uint32_t count;
    uint32_t flags;
    ksi_input inputs[];
} ksi_synthesize_input_payload;

typedef struct ksi_hook_subscription_payload {
    uint32_t hook_type;
    uint32_t reserved;
} ksi_hook_subscription_payload;

typedef struct ksi_block_input_payload {
    uint32_t block_mask;
    uint32_t reserved;
} ksi_block_input_payload;

typedef struct ksi_hook_event_payload {
    uint32_t hook_type;
    uint32_t reserved;
    union {
        ksi_keyboard_hook_event keyboard;
        ksi_mouse_hook_event mouse;
    } event;
} ksi_hook_event_payload;

typedef struct ksi_hook_decision_payload {
    uint32_t decision;
    uint32_t input_count;
    ksi_input inputs[];
} ksi_hook_decision_payload;

typedef struct ksi_permissions_revoke_payload {
    uint32_t target_kind;
    uint32_t scopes;
    uint64_t pid;
    uint8_t hash[KSI_PERMISSION_HASH_SIZE];
} ksi_permissions_revoke_payload;

static inline void ksi_status_encode(
    uint8_t destination[KSI_STATUS_PAYLOAD_SIZE],
    uint32_t status,
    uint32_t detail)
{
    ksi_wire_write_u32(destination, status);
    ksi_wire_write_u32(destination + 4u, detail);
}

static inline void ksi_status_decode(
    const uint8_t source[KSI_STATUS_PAYLOAD_SIZE],
    ksi_status_payload *status)
{
    status->status = ksi_wire_read_u32(source);
    status->detail = ksi_wire_read_u32(source + 4u);
}

#endif
