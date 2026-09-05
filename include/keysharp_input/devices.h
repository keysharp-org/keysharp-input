#ifndef KEYSHARP_INPUT_DEVICES_H
#define KEYSHARP_INPUT_DEVICES_H

#include <stdint.h>

#define KSI_DEVICE_NAME_CAPACITY 256u
#define KSI_DEVICE_PATH_CAPACITY 512u
#define KSI_DEVICE_PHYSICAL_CAPACITY 256u
#define KSI_DEVICE_UNIQUE_CAPACITY 128u
#define KSI_DEVICE_AXIS_CAPACITY 64u

enum {
    KSI_OBSERVER_INPUT = 1u,
    KSI_OBSERVER_DEVICE_ADDED = 2u,
    KSI_OBSERVER_DEVICE_REMOVED = 3u,
    KSI_OBSERVER_DEVICE_CHANGED = 4u,
    KSI_OBSERVER_OVERFLOW = 5u,
    KSI_OBSERVER_SESSION_REVOKED = 6u,
    KSI_OBSERVER_RAW_INPUT = 7u,
};

enum {
    KSI_DEVICE_KEYBOARD = 0x0001u,
    KSI_DEVICE_MOUSE = 0x0002u,
    KSI_DEVICE_TOUCHPAD = 0x0004u,
    KSI_DEVICE_TABLET = 0x0008u,
    KSI_DEVICE_RELATIVE = 0x0010u,
    KSI_DEVICE_ABSOLUTE = 0x0020u,
    KSI_DEVICE_HIGH_RESOLUTION_WHEEL = 0x0040u,
    KSI_DEVICE_HIGH_RESOLUTION_HORIZONTAL_WHEEL = 0x0080u,
    KSI_DEVICE_CAN_INTERCEPT_KEYBOARD = 0x0100u,
    KSI_DEVICE_CAN_INTERCEPT_MOUSE = 0x0200u,
    KSI_DEVICE_RAW_OBSERVATION = 0x0400u,
};

typedef struct ksi_device_axis_info {
    uint32_t struct_size;
    uint32_t code;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
    uint32_t reserved;
} ksi_device_axis_info;

enum {
    KSI_RAW_INPUT_SYNCHRONIZED = 1u,
    KSI_RAW_INPUT_MONOTONIC_TIME = 2u,
};

typedef struct ksi_raw_input_event {
    uint32_t struct_size;
    uint32_t device_id;
    uint64_t time_ms;
    uint16_t type;
    uint16_t code;
    int32_t value;
    uint32_t flags;
    uint32_t reserved0;
    uint64_t reserved[2];
} ksi_raw_input_event;

typedef struct ksi_device_info {
    uint32_t struct_size;
    uint32_t device_id;
    uint32_t capabilities;
    uint16_t bus_type;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
    uint32_t reserved0;
    char name[KSI_DEVICE_NAME_CAPACITY];
    char path[KSI_DEVICE_PATH_CAPACITY];
    char physical[KSI_DEVICE_PHYSICAL_CAPACITY];
    char unique[KSI_DEVICE_UNIQUE_CAPACITY];
    uint32_t axis_count;
    uint32_t reserved1;
    ksi_device_axis_info axes[KSI_DEVICE_AXIS_CAPACITY];
    uint64_t reserved[4];
} ksi_device_info;

#endif
