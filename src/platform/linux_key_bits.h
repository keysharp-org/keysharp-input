#ifndef KEYSHARP_INPUT_LINUX_KEY_BITS_H
#define KEYSHARP_INPUT_LINUX_KEY_BITS_H

#include <linux/input.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define KSI_KEY_BITMAP_BYTES ((KEY_MAX + 8u) / 8u)

static inline bool ksi_key_bit(const uint8_t *keys, uint16_t code)
{
    return (keys[code / 8u] & (uint8_t)(1u << (code % 8u))) != 0u;
}

static inline void ksi_set_key_bit(uint8_t *keys, uint16_t code, bool down)
{
    uint8_t mask = (uint8_t)(1u << (code % 8u));
    keys[code / 8u] = down ? (uint8_t)(keys[code / 8u] | mask) : (uint8_t)(keys[code / 8u] & ~mask);
}

/* EVIOCGKEY fills unsigned longs, which are not a byte bitmap on big-endian
 * hosts. On failure keys reads as all up. */
static inline bool ksi_read_key_bytes(int fd, uint8_t *keys)
{
    unsigned long bits[(KSI_KEY_BITMAP_BYTES + sizeof(long) - 1u) / sizeof(long)] = {0};
    bool ok = ioctl(fd, EVIOCGKEY(sizeof(bits)), bits) >= 0;

    for (size_t i = 0u; i < KSI_KEY_BITMAP_BYTES; i++)
        keys[i] = (uint8_t)(bits[i / sizeof(long)] >> (8u * (i % sizeof(long))));
    return ok;
}

static inline bool ksi_any_key_bit(const uint8_t *keys)
{
    for (size_t i = 0u; i < KSI_KEY_BITMAP_BYTES; i++)
        if (keys[i] != 0u) return true;
    return false;
}

/* The hook ABI names X buttons BTN_SIDE/BTN_EXTRA, while mice may report
 * either member of each pair. */
static inline uint16_t ksi_canonical_button(uint16_t code)
{
    return code == BTN_BACK ? BTN_SIDE : code == BTN_FORWARD ? BTN_EXTRA : code;
}

static inline uint16_t ksi_button_alias(uint16_t code)
{
    return code == BTN_SIDE ? BTN_BACK : code == BTN_EXTRA ? BTN_FORWARD : ksi_canonical_button(code);
}

#endif
