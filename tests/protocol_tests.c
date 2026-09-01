#include "protocol_codec.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    uint8_t raw[KSI_FRAME_HEADER_SIZE];
    ksi_message_header header = {
        .major = KSI_PROTOCOL_MAJOR,
        .minor = KSI_PROTOCOL_MINOR,
        .opcode = KSI_OPCODE_AUTHORIZE,
        .flags = 0u,
        .payload_length = KSI_AUTHORIZE_PAYLOAD_SIZE,
        .request_id = UINT64_C(0x0102030405060708),
    };
    ksi_message_header decoded;
    uint8_t input_wire[KSI_INPUT_WIRE_SIZE];
    ksi_input input = {
        .type = KSI_INPUT_KEYBOARD,
        .data.keyboard = {
            .vk = 0x41u,
            .scan = 30u,
            .flags = KSI_KEY_SCANCODE,
            .time = 42u,
            .extra_info = UINT64_C(0x1122334455667788),
        },
    };
    ksi_input decoded_input;

    ksi_frame_header_encode(raw, &header);
    CHECK(memcmp(raw, "KSIP", 4u) == 0);
    CHECK(raw[4] == 2u && raw[5] == 0u && raw[6] == 0u && raw[7] == 0u);
    CHECK(raw[16] == 0x08u && raw[23] == 0x01u);
    CHECK(ksi_frame_header_decode(raw, &decoded));
    CHECK(decoded.major == header.major);
    CHECK(decoded.minor == header.minor);
    CHECK(decoded.opcode == header.opcode);
    CHECK(decoded.flags == header.flags);
    CHECK(decoded.payload_length == header.payload_length);
    CHECK(decoded.request_id == header.request_id);
    CHECK(ksi_protocol_frame_is_valid(&decoded));

    decoded.flags = KSI_FRAME_FLAG_EVENT;
    decoded.request_id = 0u;
    CHECK(ksi_protocol_frame_is_valid(&decoded));
    decoded.flags = KSI_FRAME_FLAG_RESPONSE | KSI_FRAME_FLAG_EVENT;
    CHECK(!ksi_protocol_frame_is_valid(&decoded));
    decoded.flags = KSI_FRAME_FLAG_MORE;
    CHECK(!ksi_protocol_frame_is_valid(&decoded));
    decoded.flags = 0x8000u;
    CHECK(!ksi_protocol_frame_is_valid(&decoded));
    decoded.flags = 0u;
    decoded.opcode = KSI_OPCODE_PING;
    decoded.payload_length = 0u;
    CHECK(ksi_protocol_frame_is_valid(&decoded));
    decoded.opcode = KSI_OPCODE_AUTHORIZE;
    CHECK(!ksi_protocol_frame_is_valid(&decoded));

    ksi_protocol_encode_input(input_wire, &input);
    CHECK(ksi_protocol_decode_input(input_wire, &decoded_input));
    CHECK(decoded_input.type == KSI_INPUT_KEYBOARD);
    CHECK(decoded_input.data.keyboard.vk == input.data.keyboard.vk);
    CHECK(decoded_input.data.keyboard.scan == input.data.keyboard.scan);
    CHECK(decoded_input.data.keyboard.extra_info
        == input.data.keyboard.extra_info);
    input_wire[4] = 1u;
    CHECK(!ksi_protocol_decode_input(input_wire, &decoded_input));

    return 0;
}
