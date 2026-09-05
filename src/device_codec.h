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
    return true;
}

#endif
