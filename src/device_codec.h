#ifndef KEYSHARP_INPUT_DEVICE_CODEC_H
#define KEYSHARP_INPUT_DEVICE_CODEC_H

#include <keysharp_input/devices.h>
#include "internal/protocol_contract.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static inline void ksi_device_write(uint8_t *out, uint32_t value, size_t count)
{
    for (size_t i = 0; i < count; i++) out[i] = (uint8_t)(value >> (i * 8u));
}

static inline uint32_t ksi_device_read(const uint8_t *in, size_t count)
{
    uint32_t value = 0;
    for (size_t i = 0; i < count; i++) value |= (uint32_t)in[i] << (i * 8u);
    return value;
}

static inline void ksi_device_encode(uint8_t *out, const ksi_device_info *device)
{
    memset(out, 0, KSI_DEVICE_INFO_WIRE_SIZE);
    ksi_device_write(out, device->device_id, 4u);
    ksi_device_write(out + 4u, device->capabilities, 4u);
    ksi_device_write(out + 8u, device->bus_type, 2u);
    ksi_device_write(out + 10u, device->vendor, 2u);
    ksi_device_write(out + 12u, device->product, 2u);
    ksi_device_write(out + 14u, device->version, 2u);
    memcpy(out + 24u, device->name, KSI_DEVICE_NAME_CAPACITY);
    memcpy(out + 280u, device->path, KSI_DEVICE_PATH_CAPACITY);
    memcpy(out + 792u, device->physical, KSI_DEVICE_PHYSICAL_CAPACITY);
    memcpy(out + 1048u, device->unique, KSI_DEVICE_UNIQUE_CAPACITY);
    ksi_device_write(out + 1176u, device->axis_count, 4u);
    for (uint32_t i = 0u; i < device->axis_count && i < KSI_DEVICE_AXIS_CAPACITY; i++) {
        uint8_t *axis = out + 1184u + i * 24u;
        const ksi_device_axis_info *info = &device->axes[i];
        ksi_device_write(axis, info->code, 4u);
        ksi_device_write(axis + 4u, (uint32_t)info->minimum, 4u);
        ksi_device_write(axis + 8u, (uint32_t)info->maximum, 4u);
        ksi_device_write(axis + 12u, (uint32_t)info->fuzz, 4u);
        ksi_device_write(axis + 16u, (uint32_t)info->flat, 4u);
        ksi_device_write(axis + 20u, (uint32_t)info->resolution, 4u);
    }
    ksi_device_write(out + 2720u, device->button_count, 4u);
    for (uint32_t i = 0u; i < device->button_count && i < KSI_DEVICE_BUTTON_CAPACITY; i++)
        ksi_device_write(out + 2728u + i * 2u, device->button_codes[i], 2u);
}

static inline bool ksi_device_decode(const uint8_t *in, size_t size, ksi_device_info *device)
{
    if (size != KSI_DEVICE_INFO_WIRE_SIZE || ksi_device_read(in, 4u) == 0u
        || ksi_device_read(in + 16u, 4u) != 0u || ksi_device_read(in + 20u, 4u) != 0u
        || memchr(in + 24u, 0, KSI_DEVICE_NAME_CAPACITY) == NULL
        || memchr(in + 280u, 0, KSI_DEVICE_PATH_CAPACITY) == NULL
        || memchr(in + 792u, 0, KSI_DEVICE_PHYSICAL_CAPACITY) == NULL
        || memchr(in + 1048u, 0, KSI_DEVICE_UNIQUE_CAPACITY) == NULL) return false;
    uint32_t count = ksi_device_read(in + 1176u, 4u);
    if (count > KSI_DEVICE_AXIS_CAPACITY || ksi_device_read(in + 1180u, 4u) != 0u) return false;
    memset(device, 0, sizeof(*device));
    device->struct_size = sizeof(*device);
    device->device_id = ksi_device_read(in, 4u);
    device->capabilities = ksi_device_read(in + 4u, 4u);
    device->bus_type = (uint16_t)ksi_device_read(in + 8u, 2u);
    device->vendor = (uint16_t)ksi_device_read(in + 10u, 2u);
    device->product = (uint16_t)ksi_device_read(in + 12u, 2u);
    device->version = (uint16_t)ksi_device_read(in + 14u, 2u);
    memcpy(device->name, in + 24u, KSI_DEVICE_NAME_CAPACITY);
    memcpy(device->path, in + 280u, KSI_DEVICE_PATH_CAPACITY);
    memcpy(device->physical, in + 792u, KSI_DEVICE_PHYSICAL_CAPACITY);
    memcpy(device->unique, in + 1048u, KSI_DEVICE_UNIQUE_CAPACITY);
    device->axis_count = count;
    for (uint32_t i = 0u; i < count; i++) {
        const uint8_t *axis = in + 1184u + i * 24u;
        ksi_device_axis_info *info = &device->axes[i];
        info->struct_size = sizeof(*info);
        info->code = ksi_device_read(axis, 4u);
        if (info->code >= KSI_DEVICE_AXIS_CAPACITY || (i != 0u && info->code <= device->axes[i - 1u].code)) return false;
        info->minimum = (int32_t)ksi_device_read(axis + 4u, 4u);
        info->maximum = (int32_t)ksi_device_read(axis + 8u, 4u);
        info->fuzz = (int32_t)ksi_device_read(axis + 12u, 4u);
        info->flat = (int32_t)ksi_device_read(axis + 16u, 4u);
        info->resolution = (int32_t)ksi_device_read(axis + 20u, 4u);
    }
    uint32_t button_count = ksi_device_read(in + 2720u, 4u);
    if (button_count > KSI_DEVICE_BUTTON_CAPACITY || ksi_device_read(in + 2724u, 4u) != 0u) return false;
    device->button_count = button_count;
    /* joydev numbers the joystick and gamepad codes before the lower misc
     * range, so the sequence ascends, descends at most once, and every code
     * after that descent stays below the first. */
    uint32_t first = button_count != 0u ? ksi_device_read(in + 2728u, 2u) : 0u;
    bool descended = false;
    for (uint32_t i = 0u; i < button_count; i++) {
        uint16_t code = (uint16_t)ksi_device_read(in + 2728u + i * 2u, 2u);
        if (code == 0u) return false;
        if (i != 0u && code <= device->button_codes[i - 1u]) {
            if (descended || code >= first) return false;
            descended = true;
        }
        device->button_codes[i] = code;
    }
    return true;
}

static inline size_t ksi_gamepad_state_encode(uint8_t *out, const ksi_gamepad_state *state)
{
    uint32_t axis_count = state->axis_count < KSI_DEVICE_AXIS_CAPACITY
        ? state->axis_count : KSI_DEVICE_AXIS_CAPACITY;
    memset(out, 0, KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE);
    ksi_device_write(out, state->device_id, 4u);
    ksi_device_write(out + 4u, state->button_count, 4u);
    for (size_t i = 0u; i < 8u; i++)
        out[8u + i] = (uint8_t)(state->device_generation >> (i * 8u));
    ksi_device_write(out + 16u, axis_count, 4u);
    memcpy(out + 24u, state->buttons, KSI_DEVICE_BUTTON_BITMAP_BYTES);
    for (uint32_t i = 0u; i < axis_count; i++) {
        uint8_t *axis = out + KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE + i * KSI_GAMEPAD_AXIS_WIRE_SIZE;
        ksi_device_write(axis, state->axes[i].code, 4u);
        ksi_device_write(axis + 4u, (uint32_t)state->axes[i].value, 4u);
    }
    return KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE + (size_t)axis_count * KSI_GAMEPAD_AXIS_WIRE_SIZE;
}

static inline bool ksi_gamepad_state_decode(const uint8_t *in, size_t size, ksi_gamepad_state *state)
{
    if (size < KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE || ksi_device_read(in, 4u) == 0u
        || ksi_device_read(in + 20u, 4u) != 0u) return false;
    uint32_t button_count = ksi_device_read(in + 4u, 4u);
    uint32_t axis_count = ksi_device_read(in + 16u, 4u);
    if (button_count > KSI_DEVICE_BUTTON_CAPACITY || axis_count > KSI_DEVICE_AXIS_CAPACITY
        || size != KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE + (size_t)axis_count * KSI_GAMEPAD_AXIS_WIRE_SIZE)
        return false;
    memset(state, 0, sizeof(*state));
    state->struct_size = sizeof(*state);
    state->device_id = ksi_device_read(in, 4u);
    state->button_count = button_count;
    for (size_t i = 0u; i < 8u; i++)
        state->device_generation |= (uint64_t)in[8u + i] << (i * 8u);
    state->axis_count = axis_count;
    memcpy(state->buttons, in + 24u, KSI_DEVICE_BUTTON_BITMAP_BYTES);
    for (uint32_t i = 0u; i < axis_count; i++) {
        const uint8_t *axis = in + KSI_GAMEPAD_STATE_BODY_PREFIX_SIZE + i * KSI_GAMEPAD_AXIS_WIRE_SIZE;
        ksi_gamepad_axis_state *entry = &state->axes[i];
        entry->struct_size = sizeof(*entry);
        entry->code = ksi_device_read(axis, 4u);
        if (entry->code >= KSI_DEVICE_AXIS_CAPACITY
            || (i != 0u && entry->code <= state->axes[i - 1u].code)) return false;
        entry->value = (int32_t)ksi_device_read(axis + 4u, 4u);
    }
    /* Buttons the device does not have must not be reported as pressed. */
    for (uint32_t bit = button_count; bit < KSI_DEVICE_BUTTON_CAPACITY; bit++)
        if ((state->buttons[bit >> 3] & (uint8_t)(1u << (bit & 7u))) != 0u) return false;
    return true;
}

#endif
