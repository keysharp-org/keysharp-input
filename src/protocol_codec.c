#include "protocol_codec.h"

#include <string.h>

bool ksi_protocol_frame_is_valid(const ksi_message_header *header)
{
    bool response;
    bool event;

    if (header == NULL
        || header->major != KSI_PROTOCOL_MAJOR
        || header->minor != KSI_PROTOCOL_MINOR
        || header->payload_length > KSI_MAX_PAYLOAD_SIZE
        || (header->flags & (uint16_t)~KSI_FRAME_FLAGS_ALL) != 0u) {
        return false;
    }

    response = (header->flags & KSI_FRAME_FLAG_RESPONSE) != 0u;
    event = (header->flags & KSI_FRAME_FLAG_EVENT) != 0u;

    if ((response && event)
        || ((header->flags & KSI_FRAME_FLAG_MORE) != 0u && !response)) {
        return false;
    }
    if (event) {
        return header->request_id == 0u;
    }
    if (response) {
        return header->request_id != 0u;
    }
    if (header->flags != 0u) {
        return false;
    }

    return header->request_id != 0u
        || (header->opcode == KSI_OPCODE_PING
            && header->payload_length == 0u);
}

bool ksi_protocol_decode_hello(const uint8_t *source, size_t size,
                               ksi_client_hello_payload *payload)
{
    if (source == NULL || payload == NULL || size != KSI_HELLO_PAYLOAD_SIZE) {
        return false;
    }

    payload->role = ksi_wire_read_u16(source);
    payload->authorization_mode = ksi_wire_read_u16(source + 2u);
    payload->requested_scopes = ksi_wire_read_u32(source + 4u);
    payload->reserved = ksi_wire_read_u64(source + 8u);
    return true;
}

bool ksi_protocol_decode_authorize(const uint8_t *source, size_t size,
                                   ksi_authorize_payload *payload)
{
    if (source == NULL || payload == NULL
        || size != KSI_AUTHORIZE_PAYLOAD_SIZE) {
        return false;
    }

    payload->authorization_mode = ksi_wire_read_u16(source);
    payload->reserved0 = ksi_wire_read_u16(source + 2u);
    payload->requested_scopes = ksi_wire_read_u32(source + 4u);
    payload->reserved1 = ksi_wire_read_u64(source + 8u);
    return true;
}

bool ksi_protocol_decode_hook_subscription(
    const uint8_t *source, size_t size,
    ksi_hook_subscription_payload *payload)
{
    if (source == NULL || payload == NULL
        || size != KSI_HOOK_SUBSCRIPTION_PAYLOAD_SIZE) {
        return false;
    }

    payload->hook_type = ksi_wire_read_u32(source);
    payload->reserved = ksi_wire_read_u32(source + 4u);
    return true;
}

bool ksi_protocol_decode_block_input(const uint8_t *source, size_t size,
                                     ksi_block_input_payload *payload)
{
    if (source == NULL || payload == NULL
        || size != KSI_BLOCK_INPUT_PAYLOAD_SIZE) {
        return false;
    }

    payload->block_mask = ksi_wire_read_u32(source);
    payload->reserved = ksi_wire_read_u32(source + 4u);
    return true;
}

bool ksi_protocol_decode_permissions_revoke(
    const uint8_t *source, size_t size,
    ksi_permissions_revoke_payload *payload)
{
    if (source == NULL || payload == NULL
        || size != KSI_PERMISSIONS_REVOKE_PAYLOAD_SIZE) {
        return false;
    }

    payload->target_kind = ksi_wire_read_u32(source);
    payload->scopes = ksi_wire_read_u32(source + 4u);
    payload->pid = ksi_wire_read_u64(source + 8u);
    memcpy(payload->hash, source + 16u, KSI_PERMISSION_HASH_SIZE);
    return true;
}

bool ksi_protocol_decode_synthesize_prefix(
    const uint8_t *source, size_t size, uint32_t *count, uint32_t *flags)
{
    if (source == NULL || count == NULL || flags == NULL
        || size < KSI_SYNTHESIZE_PREFIX_SIZE) {
        return false;
    }

    *count = ksi_wire_read_u32(source);
    *flags = ksi_wire_read_u32(source + 4u);
    return true;
}

bool ksi_protocol_decode_hook_decision_prefix(
    const uint8_t *source, size_t size, uint32_t *decision,
    uint32_t *input_count)
{
    if (source == NULL || decision == NULL || input_count == NULL
        || size < KSI_STATUS_PAYLOAD_SIZE + 8u) {
        return false;
    }

    *decision = ksi_wire_read_u32(source + KSI_STATUS_PAYLOAD_SIZE);
    *input_count = ksi_wire_read_u32(source + KSI_STATUS_PAYLOAD_SIZE + 4u);
    return true;
}

bool ksi_protocol_decode_input(const uint8_t source[KSI_INPUT_WIRE_SIZE],
                               ksi_input *input)
{
    uint32_t type;

    if (source == NULL || input == NULL) {
        return false;
    }

    type = ksi_wire_read_u32(source);
    if (ksi_wire_read_u32(source + 4u) != 0u) {
        return false;
    }

    memset(input, 0, sizeof(*input));
    input->type = type;

    if (type == KSI_INPUT_KEYBOARD) {
        if (ksi_wire_read_u32(source + 20u) != 0u
            || ksi_wire_read_u64(source + 32u) != 0u) {
            return false;
        }
        input->data.keyboard.vk = ksi_wire_read_u16(source + 8u);
        input->data.keyboard.scan = ksi_wire_read_u16(source + 10u);
        input->data.keyboard.flags = ksi_wire_read_u32(source + 12u);
        input->data.keyboard.time = ksi_wire_read_u32(source + 16u);
        input->data.keyboard.extra_info = ksi_wire_read_u64(source + 24u);
        return true;
    }
    if (type == KSI_INPUT_MOUSE) {
        if (ksi_wire_read_u32(source + 28u) != 0u) {
            return false;
        }
        input->data.mouse.dx = (int32_t)ksi_wire_read_u32(source + 8u);
        input->data.mouse.dy = (int32_t)ksi_wire_read_u32(source + 12u);
        input->data.mouse.mouse_data = ksi_wire_read_u32(source + 16u);
        input->data.mouse.flags = ksi_wire_read_u32(source + 20u);
        input->data.mouse.time = ksi_wire_read_u32(source + 24u);
        input->data.mouse.extra_info = ksi_wire_read_u64(source + 32u);
        return true;
    }

    return false;
}

void ksi_protocol_encode_input(uint8_t destination[KSI_INPUT_WIRE_SIZE],
                               const ksi_input *input)
{
    memset(destination, 0, KSI_INPUT_WIRE_SIZE);
    ksi_wire_write_u32(destination, input->type);

    if (input->type == KSI_INPUT_KEYBOARD) {
        ksi_wire_write_u16(destination + 8u, input->data.keyboard.vk);
        ksi_wire_write_u16(destination + 10u, input->data.keyboard.scan);
        ksi_wire_write_u32(destination + 12u, input->data.keyboard.flags);
        ksi_wire_write_u32(destination + 16u, input->data.keyboard.time);
        ksi_wire_write_u64(destination + 24u, input->data.keyboard.extra_info);
    } else if (input->type == KSI_INPUT_MOUSE) {
        ksi_wire_write_u32(destination + 8u, (uint32_t)input->data.mouse.dx);
        ksi_wire_write_u32(destination + 12u, (uint32_t)input->data.mouse.dy);
        ksi_wire_write_u32(destination + 16u, input->data.mouse.mouse_data);
        ksi_wire_write_u32(destination + 20u, input->data.mouse.flags);
        ksi_wire_write_u32(destination + 24u, input->data.mouse.time);
        ksi_wire_write_u64(destination + 32u, input->data.mouse.extra_info);
    }
}

size_t ksi_protocol_encode_status(uint8_t *destination,
                                  uint32_t status, uint32_t detail)
{
    ksi_status_encode(destination, status, detail);
    return KSI_STATUS_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_hello_result(
    uint8_t *destination, uint32_t status, uint32_t detail,
    uint32_t granted_scopes, uint64_t available_operations)
{
    size_t size = ksi_protocol_encode_status(destination, status, detail);

    if (status != KSI_STATUS_OK) {
        return size;
    }
    ksi_wire_write_u32(destination + 8u, granted_scopes);
    ksi_wire_write_u32(destination + 12u, 0u);
    ksi_wire_write_u64(destination + 16u, available_operations);
    return KSI_HELLO_RESULT_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_authorize_result(
    uint8_t *destination, uint32_t status, uint32_t detail,
    uint32_t granted_scopes)
{
    size_t size = ksi_protocol_encode_status(destination, status, detail);

    if (status != KSI_STATUS_OK) {
        return size;
    }
    ksi_wire_write_u32(destination + 8u, granted_scopes);
    ksi_wire_write_u32(destination + 12u, 0u);
    return KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_u32_result(uint8_t *destination, uint32_t value)
{
    ksi_status_encode(destination, KSI_STATUS_OK, KSI_DETAIL_NONE);
    ksi_wire_write_u32(destination + 8u, value);
    ksi_wire_write_u32(destination + 12u, 0u);
    return 16u;
}

size_t ksi_protocol_encode_indicator_state(
    uint8_t *destination, const ksi_indicator_state_payload *payload)
{
    destination[0] = payload->caps_lock;
    destination[1] = payload->num_lock;
    destination[2] = payload->scroll_lock;
    destination[3] = 0u;
    return KSI_INDICATOR_STATE_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_pointer_position(
    uint8_t *destination, const ksi_pointer_position_payload *payload)
{
    destination[0] = payload->valid;
    memset(destination + 1u, 0, 3u);
    ksi_wire_write_u32(destination + 4u, (uint32_t)payload->x);
    ksi_wire_write_u32(destination + 8u, (uint32_t)payload->y);
    ksi_wire_write_u32(destination + 12u, (uint32_t)payload->x_min);
    ksi_wire_write_u32(destination + 16u, (uint32_t)payload->x_max);
    ksi_wire_write_u32(destination + 20u, (uint32_t)payload->y_min);
    ksi_wire_write_u32(destination + 24u, (uint32_t)payload->y_max);
    return KSI_POINTER_POSITION_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_key_state(
    uint8_t *destination, const ksi_key_state_payload *payload)
{
    ksi_wire_write_u32(destination, payload->modifiers_lr);
    destination[4] = payload->caps_lock;
    destination[5] = payload->num_lock;
    destination[6] = payload->scroll_lock;
    destination[7] = 0u;
    memcpy(destination + 8u, payload->logical_keys,
        KSI_KEY_STATE_BITMAP_BYTES);
    memcpy(destination + 8u + KSI_KEY_STATE_BITMAP_BYTES,
        payload->physical_keys, KSI_KEY_STATE_BITMAP_BYTES);
    return KSI_KEY_STATE_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_pointer_buttons(
    uint8_t *destination, const ksi_pointer_buttons_payload *payload)
{
    destination[0] = payload->valid;
    memset(destination + 1u, 0, 3u);
    ksi_wire_write_u32(destination + 4u, payload->logical_buttons);
    ksi_wire_write_u32(destination + 8u, payload->physical_buttons);
    return KSI_POINTER_BUTTONS_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_idle_time(
    uint8_t *destination, const ksi_idle_time_payload *payload)
{
    destination[0] = payload->valid;
    memset(destination + 1u, 0, 7u);
    ksi_wire_write_u64(destination + 8u, payload->idle_time_ms);
    return KSI_IDLE_TIME_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_modifier_state(
    uint8_t *destination, const ksi_modifier_state_payload *payload)
{
    ksi_wire_write_u32(destination, payload->logical_modifiers_lr);
    ksi_wire_write_u32(destination + 4u, payload->physical_modifiers_lr);
    destination[8] = payload->caps_lock;
    destination[9] = payload->num_lock;
    destination[10] = payload->scroll_lock;
    destination[11] = 0u;
    return KSI_MODIFIER_STATE_PAYLOAD_SIZE;
}

size_t ksi_protocol_encode_hook_event(
    uint8_t *destination, const ksi_hook_event_payload *payload,
    uint32_t hook_type)
{
    ksi_wire_write_u32(destination, hook_type);
    ksi_wire_write_u32(destination + 4u, 0u);

    if (hook_type == KSI_HOOK_KEYBOARD) {
        const ksi_keyboard_hook_event *event = &payload->event.keyboard;
        ksi_wire_write_u32(destination + 8u, event->message);
        ksi_wire_write_u32(destination + 12u, event->vk_code);
        ksi_wire_write_u32(destination + 16u, event->scan_code);
        ksi_wire_write_u32(destination + 20u, event->flags);
        ksi_wire_write_u64(destination + 24u, event->time_ms);
        ksi_wire_write_u64(destination + 32u, event->extra_info);
        ksi_wire_write_u32(destination + 40u, event->device_id);
        ksi_wire_write_u32(destination + 44u, 0u);
        return KSI_HOOK_EVENT_PREFIX_SIZE + KSI_KEYBOARD_HOOK_EVENT_SIZE;
    }

    if (hook_type == KSI_HOOK_MOUSE) {
        const ksi_mouse_hook_event *event = &payload->event.mouse;
        ksi_wire_write_u32(destination + 8u, event->message);
        ksi_wire_write_u32(destination + 12u, (uint32_t)event->x);
        ksi_wire_write_u32(destination + 16u, (uint32_t)event->y);
        ksi_wire_write_u32(destination + 20u, event->mouse_data);
        ksi_wire_write_u32(destination + 24u, event->flags);
        ksi_wire_write_u64(destination + 28u, event->time_ms);
        ksi_wire_write_u64(destination + 36u, event->extra_info);
        ksi_wire_write_u32(destination + 44u, event->device_id);
        ksi_wire_write_u32(destination + 48u, 0u);
        ksi_wire_write_u32(destination + 52u, (uint32_t)event->delta_x);
        ksi_wire_write_u32(destination + 56u, (uint32_t)event->delta_y);
        return KSI_HOOK_EVENT_PREFIX_SIZE + KSI_MOUSE_HOOK_EVENT_SIZE;
    }

    return 0u;
}

size_t ksi_protocol_encode_hook_quarantined(
    uint8_t *destination, const ksi_hook_quarantined_payload *payload)
{
    ksi_wire_write_u32(destination, payload->hook_type);
    ksi_wire_write_u32(destination + 4u, payload->reason);
    ksi_wire_write_u64(destination + 8u, payload->event_id);
    ksi_wire_write_u32(destination + 16u, payload->generation);
    ksi_wire_write_u32(destination + 20u, payload->strike_count);
    ksi_wire_write_u32(destination + 24u, payload->retry_after_ms);
    ksi_wire_write_u32(destination + 28u, 0u);
    return KSI_HOOK_QUARANTINED_PAYLOAD_SIZE;
}

void ksi_protocol_encode_hash(const char hex[65], uint8_t raw[32])
{
    for (size_t i = 0u; i < 32u; i++) {
        unsigned int high = (unsigned int)(hex[i * 2u] <= '9'
            ? hex[i * 2u] - '0' : hex[i * 2u] - 'a' + 10);
        unsigned int low = (unsigned int)(hex[i * 2u + 1u] <= '9'
            ? hex[i * 2u + 1u] - '0' : hex[i * 2u + 1u] - 'a' + 10);
        raw[i] = (uint8_t)((high << 4u) | low);
    }
}

bool ksi_protocol_decode_hash(const uint8_t raw[32], char hex[65])
{
    static const char digits[] = "0123456789abcdef";

    if (raw == NULL || hex == NULL) {
        return false;
    }
    for (size_t i = 0u; i < 32u; i++) {
        hex[i * 2u] = digits[raw[i] >> 4u];
        hex[i * 2u + 1u] = digits[raw[i] & 0x0fu];
    }
    hex[64] = '\0';
    return true;
}
