#ifndef KEYSHARP_INPUT_TERMINAL_CONTRACT_H
#define KEYSHARP_INPUT_TERMINAL_CONTRACT_H

#include <keysharp_input/constants.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool ksi_terminal_utf8_valid(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0u; i < length;) {
        uint32_t value = bytes[i++];
        uint32_t minimum;
        size_t continuation;
        if (value < 0x80u) continue;
        if (value >= 0xc2u && value <= 0xdfu) {
            value &= 0x1fu; minimum = 0x80u; continuation = 1u;
        } else if (value >= 0xe0u && value <= 0xefu) {
            value &= 0x0fu; minimum = 0x800u; continuation = 2u;
        } else if (value >= 0xf0u && value <= 0xf4u) {
            value &= 0x07u; minimum = 0x10000u; continuation = 3u;
        } else return false;
        if (continuation > length - i) return false;
        while (continuation-- != 0u) {
            uint32_t next = bytes[i++];
            if ((next & 0xc0u) != 0x80u) return false;
            value = (value << 6u) | (next & 0x3fu);
        }
        if (value < minimum || value > 0x10ffffu
            || (value >= 0xd800u && value <= 0xdfffu)) return false;
    }
    return true;
}

static inline bool ksi_terminal_request_valid(uint32_t kind, uint32_t id,
    uint32_t flags, const uint8_t *bytes, uint32_t count)
{
    return kind == KSI_TERMINAL_TARGET_LINUX_VT && id >= 1u && id <= 63u
        && (flags & ~(uint32_t)(KSI_TERMINAL_INPUT_REQUIRE_UTF8 | KSI_TERMINAL_INPUT_TEXT)) == 0u
        && count <= KSI_MAX_TERMINAL_INPUT_BYTES && (count == 0u || bytes != NULL)
        && ((flags & KSI_TERMINAL_INPUT_REQUIRE_UTF8) == 0u || ksi_terminal_utf8_valid(bytes, count));
}

#endif
