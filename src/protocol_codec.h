#ifndef KEYSHARP_INPUT_PROTOCOL_CODEC_H
#define KEYSHARP_INPUT_PROTOCOL_CODEC_H

#include "internal/protocol.h"

#include <stddef.h>

bool ksi_protocol_frame_is_valid(const ksi_message_header *header);

bool ksi_protocol_decode_hello(const uint8_t *source, size_t size,
                               ksi_client_hello_payload *payload);
bool ksi_protocol_decode_authorize(const uint8_t *source, size_t size,
                                   ksi_authorize_payload *payload);
bool ksi_protocol_decode_hook_subscription(
    const uint8_t *source, size_t size,
    ksi_hook_subscription_payload *payload);
bool ksi_protocol_decode_block_input(const uint8_t *source, size_t size,
                                     ksi_block_input_payload *payload);
bool ksi_protocol_decode_permissions_revoke(
    const uint8_t *source, size_t size,
    ksi_permissions_revoke_payload *payload);
bool ksi_protocol_decode_synthesize_prefix(
    const uint8_t *source, size_t size, uint32_t *count, uint32_t *flags);
bool ksi_protocol_decode_hook_decision_prefix(
    const uint8_t *source, size_t size, uint32_t *decision,
    uint32_t *input_count);
bool ksi_protocol_decode_input(const uint8_t source[KSI_INPUT_WIRE_SIZE],
                               ksi_input *input);
void ksi_protocol_encode_input(uint8_t destination[KSI_INPUT_WIRE_SIZE],
                               const ksi_input *input);

size_t ksi_protocol_encode_hello_result(
    uint8_t *destination, uint32_t status, uint32_t detail,
    uint32_t granted_scopes, uint64_t available_operations);
size_t ksi_protocol_encode_authorize_result(
    uint8_t *destination, uint32_t status, uint32_t detail,
    uint32_t granted_scopes);
size_t ksi_protocol_encode_status(uint8_t *destination,
                                  uint32_t status, uint32_t detail);
size_t ksi_protocol_encode_u32_result(uint8_t *destination,
                                      uint32_t value);
size_t ksi_protocol_encode_indicator_state(
    uint8_t *destination, const ksi_indicator_state_payload *payload);
size_t ksi_protocol_encode_pointer_position(
    uint8_t *destination, const ksi_pointer_position_payload *payload);
size_t ksi_protocol_encode_key_state(
    uint8_t *destination, const ksi_key_state_payload *payload);
size_t ksi_protocol_encode_pointer_buttons(
    uint8_t *destination, const ksi_pointer_buttons_payload *payload);
size_t ksi_protocol_encode_idle_time(
    uint8_t *destination, const ksi_idle_time_payload *payload);
size_t ksi_protocol_encode_modifier_state(
    uint8_t *destination, const ksi_modifier_state_payload *payload);
size_t ksi_protocol_encode_hook_event(
    uint8_t *destination, const ksi_hook_event_payload *payload,
    uint32_t hook_type);
size_t ksi_protocol_encode_hook_quarantined(
    uint8_t *destination, const ksi_hook_quarantined_payload *payload);
void ksi_protocol_encode_hash(const char hex[65], uint8_t raw[32]);
bool ksi_protocol_decode_hash(const uint8_t raw[32], char hex[65]);

#endif
