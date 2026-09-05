#include "keysharp_input/client.h"
#include "internal/protocol_contract.h"
#include "device_codec.h"

#include <keysharp_permissions/permissions.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define KSI_CLIENT_MAX_RECURSION 32u
#define KSI_CLIENT_NOTIFICATION_CAPACITY 16u
#define KSI_CLIENT_HOOK_HEARTBEAT_MS 5000u

_Static_assert((uint32_t)KSI_SCOPE_INPUT_MONITORING
        == (uint32_t)KSP_SCOPE_INPUT_MONITORING,
    "public input-monitoring scope drifted from the permission store");
_Static_assert((uint32_t)KSI_SCOPE_INPUT_CONTROL
        == (uint32_t)KSP_SCOPE_INPUT_CONTROL,
    "public input-control scope drifted from the permission store");

typedef struct ksi_wire_header {
    uint16_t opcode;
    uint16_t flags;
    uint32_t payload_size;
    uint64_t request_id;
} ksi_wire_header;

struct ksi_connection {
    int fd;
    uint32_t role;
    uint32_t default_timeout_ms;
    uint32_t granted_scopes;
    uint32_t pending_revoked_scopes;
    uint64_t available_operations;
    uint64_t next_request_id;
    uint64_t outstanding_hook_request;
    uint32_t recursion_depth;
    ksi_nested_hook_handler nested_handler;
    void *nested_context;
    ksi_hook_message notifications[KSI_CLIENT_NOTIFICATION_CAPACITY];
    uint32_t notification_head;
    uint32_t notification_count;
    ksi_observer_message observer_notifications[KSI_CLIENT_NOTIFICATION_CAPACITY];
    uint32_t observer_head;
    uint32_t observer_count;
    uint64_t observer_dropped;
    uint8_t rx[KSI_MAX_PAYLOAD_SIZE];
    uint8_t tx[KSI_MAX_PAYLOAD_SIZE];
};

static uint16_t read_u16(const uint8_t *source)
{
    return (uint16_t)((uint16_t)source[0]
        | ((uint16_t)source[1] << 8u));
}

static uint32_t read_u32(const uint8_t *source)
{
    return (uint32_t)source[0]
        | ((uint32_t)source[1] << 8u)
        | ((uint32_t)source[2] << 16u)
        | ((uint32_t)source[3] << 24u);
}

static uint64_t read_u64(const uint8_t *source)
{
    return (uint64_t)read_u32(source)
        | ((uint64_t)read_u32(source + 4u) << 32u);
}

static void write_u16(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8u);
}

static void write_u32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8u);
    destination[2] = (uint8_t)(value >> 16u);
    destination[3] = (uint8_t)(value >> 24u);
}

static void write_u64(uint8_t *destination, uint64_t value)
{
    write_u32(destination, (uint32_t)value);
    write_u32(destination + 4u, (uint32_t)(value >> 32u));
}

static size_t writable_error_size(const ksi_error *error)
{
    if (error == NULL || error->struct_size < offsetof(ksi_error, message)) {
        return 0u;
    }
    return error->struct_size < sizeof(*error)
        ? error->struct_size : sizeof(*error);
}

static void clear_error(ksi_error *error)
{
    size_t size = writable_error_size(error);

    if (size != 0u) {
        memset(error, 0, size);
        error->struct_size = (uint32_t)size;
    }
}

static void set_error(
    ksi_error *error,
    uint32_t detail,
    int system_error,
    const char *format,
    ...)
{
    size_t size = writable_error_size(error);

    if (size == 0u) {
        return;
    }
    memset(error, 0, size);
    error->struct_size = (uint32_t)size;
    error->detail = detail;
    error->system_error = system_error;
    if (format != NULL && size > offsetof(ksi_error, message)) {
        va_list arguments;
        size_t capacity = size - offsetof(ksi_error, message);

        if (capacity > sizeof(error->message)) {
            capacity = sizeof(error->message);
        }
        va_start(arguments, format);
        (void)vsnprintf(error->message, capacity, format, arguments);
        va_end(arguments);
    }
}

static bool reserved_is_zero(const uint64_t *values, size_t count)
{
    for (size_t i = 0u; i < count; i++) {
        if (values[i] != 0u) {
            return false;
        }
    }
    return true;
}

static bool bytes_are_zero(const void *value, size_t size)
{
    const uint8_t *bytes = value;

    for (size_t i = 0u; i < size; i++) {
        if (bytes[i] != 0u) {
            return false;
        }
    }
    return true;
}

static bool sized_output_is_valid(const void *value, size_t required_size)
{
    return value != NULL && *(const uint32_t *)value >= required_size;
}

static ksi_status invalid_output(ksi_error *error, const char *name)
{
    set_error(error, 0u, EINVAL, "%s output is not initialized", name);
    return KSI_STATUS_INVALID_REQUEST;
}

static ksi_status invalid_result(ksi_error *error, const char *name)
{
    set_error(error, 0u, 0, "service returned invalid %s data", name);
    return KSI_STATUS_INTERNAL;
}

static void init_sized(void *value, size_t size)
{
    if (value != NULL) {
        memset(value, 0, size);
        *(uint32_t *)value = (uint32_t)size;
    }
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0u;
    }
    return (uint64_t)now.tv_sec * 1000u
        + (uint64_t)now.tv_nsec / 1000000u;
}

static int remaining_timeout(uint64_t deadline, uint32_t timeout_ms)
{
    uint64_t now;
    uint64_t remaining;

    if (timeout_ms == UINT32_MAX) {
        return -1;
    }
    now = monotonic_ms();
    if (now >= deadline) {
        return 0;
    }
    remaining = deadline - now;
    return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static ksi_status wait_fd(
    int fd,
    short events,
    uint64_t deadline,
    uint32_t timeout_ms,
    ksi_error *error)
{
    struct pollfd descriptor = { .fd = fd, .events = events };

    for (;;) {
        int wait = remaining_timeout(deadline, timeout_ms);
        int result = poll(&descriptor, 1u, wait);

        if (result > 0) {
            if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0
                && (descriptor.revents & events) == 0) {
                set_error(error, 0u, 0, "service connection closed");
                return KSI_STATUS_UNAVAILABLE;
            }
            if ((descriptor.revents & events) != 0) {
                return KSI_STATUS_OK;
            }
            continue;
        }
        if (result == 0) {
            set_error(error, 0u, 0, "operation timed out");
            return KSI_STATUS_TIMEOUT;
        }
        if (errno != EINTR) {
            int saved = errno;
            set_error(error, 0u, saved, "poll: %s", strerror(saved));
            return KSI_STATUS_UNAVAILABLE;
        }
    }
}

static ksi_status write_all(
    ksi_connection *connection,
    const uint8_t *bytes,
    size_t size,
    uint64_t deadline,
    uint32_t timeout_ms,
    ksi_error *error)
{
    size_t offset = 0u;

    while (offset < size) {
        ssize_t written = write(connection->fd, bytes + offset, size - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ksi_status status = wait_fd(connection->fd, POLLOUT,
                deadline, timeout_ms, error);
            if (status != KSI_STATUS_OK) {
                return status;
            }
            continue;
        }
        {
            int saved = written < 0 ? errno : EPIPE;
            set_error(error, 0u, saved, "write: %s", strerror(saved));
            return KSI_STATUS_UNAVAILABLE;
        }
    }
    return KSI_STATUS_OK;
}

static ksi_status read_all(
    ksi_connection *connection,
    uint8_t *bytes,
    size_t size,
    uint64_t deadline,
    uint32_t timeout_ms,
    ksi_error *error)
{
    size_t offset = 0u;

    while (offset < size) {
        ssize_t received = read(connection->fd, bytes + offset, size - offset);

        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ksi_status status = wait_fd(connection->fd, POLLIN,
                deadline, timeout_ms, error);
            if (status != KSI_STATUS_OK) {
                return status;
            }
            continue;
        }
        if (received == 0) {
            set_error(error, 0u, 0, "service connection closed");
            return KSI_STATUS_UNAVAILABLE;
        }
        {
            int saved = errno;
            set_error(error, 0u, saved, "read: %s", strerror(saved));
            return KSI_STATUS_UNAVAILABLE;
        }
    }
    return KSI_STATUS_OK;
}

static ksi_status send_frame(
    ksi_connection *connection,
    uint16_t opcode,
    uint16_t flags,
    uint64_t request_id,
    const void *payload,
    size_t payload_size,
    uint32_t timeout_ms,
    ksi_error *error)
{
    uint8_t header[KSI_FRAME_HEADER_SIZE];
    uint64_t deadline = timeout_ms == UINT32_MAX
        ? 0u : monotonic_ms() + timeout_ms;
    ksi_status status;

    if (connection == NULL || payload_size > KSI_MAX_PAYLOAD_SIZE
        || (payload_size != 0u && payload == NULL)) {
        set_error(error, 0u, EINVAL, "invalid frame");
        return KSI_STATUS_INVALID_REQUEST;
    }
    header[0] = (uint8_t)'K';
    header[1] = (uint8_t)'S';
    header[2] = (uint8_t)'I';
    header[3] = (uint8_t)'P';
    write_u16(header + 4u, KSI_PROTOCOL_MAJOR);
    write_u16(header + 6u, KSI_PROTOCOL_MINOR);
    write_u16(header + 8u, opcode);
    write_u16(header + 10u, flags);
    write_u32(header + 12u, (uint32_t)payload_size);
    write_u64(header + 16u, request_id);
    status = write_all(connection, header, sizeof(header),
        deadline, timeout_ms, error);
    if (status == KSI_STATUS_OK && payload_size != 0u) {
        status = write_all(connection, payload, payload_size,
            deadline, timeout_ms, error);
    }
    return status;
}

static bool wire_header_is_valid(const ksi_wire_header *header)
{
    bool response = (header->flags & KSI_FRAME_FLAG_RESPONSE) != 0u;
    bool event = (header->flags & KSI_FRAME_FLAG_EVENT) != 0u;

    if ((header->flags & (uint16_t)~KSI_FRAME_FLAGS_ALL) != 0u
        || (response && event)
        || ((header->flags & KSI_FRAME_FLAG_MORE) != 0u && !response)) {
        return false;
    }
    if (event) {
        return header->request_id == 0u;
    }
    if (response) {
        return header->request_id != 0u;
    }
    return header->flags == 0u && header->request_id != 0u;
}

static ksi_status receive_frame(
    ksi_connection *connection,
    ksi_wire_header *header,
    uint32_t timeout_ms,
    ksi_error *error)
{
    uint8_t raw[KSI_FRAME_HEADER_SIZE];
    uint64_t deadline = timeout_ms == UINT32_MAX
        ? 0u : monotonic_ms() + timeout_ms;
    ksi_status status = read_all(connection, raw, sizeof(raw),
        deadline, timeout_ms, error);

    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (memcmp(raw, "KSIP", 4u) != 0
        || read_u16(raw + 4u) != KSI_PROTOCOL_MAJOR
        || read_u16(raw + 6u) != KSI_PROTOCOL_MINOR) {
        set_error(error, 0u, 0, "invalid service protocol header");
        return KSI_STATUS_UNSUPPORTED;
    }
    header->opcode = read_u16(raw + 8u);
    header->flags = read_u16(raw + 10u);
    header->payload_size = read_u32(raw + 12u);
    header->request_id = read_u64(raw + 16u);
    if (header->payload_size > KSI_MAX_PAYLOAD_SIZE
        || !wire_header_is_valid(header)) {
        set_error(error, 0u, 0, "invalid service frame");
        return KSI_STATUS_INTERNAL;
    }
    if (header->payload_size != 0u) {
        status = read_all(connection, connection->rx, header->payload_size,
            deadline, timeout_ms, error);
    }
    return status;
}

static ksi_status decode_status(
    const uint8_t *payload,
    size_t payload_size,
    size_t success_size,
    ksi_error *error)
{
    uint32_t status;
    uint32_t detail;

    if (payload_size < KSI_STATUS_PAYLOAD_SIZE) {
        set_error(error, 0u, 0, "service returned a truncated status");
        return KSI_STATUS_INTERNAL;
    }
    status = read_u32(payload);
    detail = read_u32(payload + 4u);
    if (status == KSI_STATUS_OK) {
        if (payload_size != success_size) {
            set_error(error, detail, 0, "service returned an invalid result size");
            return KSI_STATUS_INTERNAL;
        }
        clear_error(error);
        return KSI_STATUS_OK;
    }
    if (payload_size == KSI_STATUS_PAYLOAD_SIZE) {
        set_error(error, detail, 0, "service request failed");
    } else if (payload_size >= KSI_STATUS_PAYLOAD_SIZE + 4u) {
        uint32_t length = read_u32(payload + KSI_STATUS_PAYLOAD_SIZE);
        if ((size_t)length != payload_size - KSI_STATUS_PAYLOAD_SIZE - 4u) {
            set_error(error, detail, 0, "service returned an invalid diagnostic");
            return KSI_STATUS_INTERNAL;
        }
        set_error(error, detail, 0, "%.*s", (int)(length > 255u ? 255u : length),
            (const char *)(payload + KSI_STATUS_PAYLOAD_SIZE + 4u));
    } else {
        set_error(error, detail, 0, "service returned an invalid diagnostic");
        return KSI_STATUS_INTERNAL;
    }
    return status <= KSI_STATUS_REVOKED || status == KSI_STATUS_INTERNAL
        ? status : KSI_STATUS_INTERNAL;
}

static uint64_t next_request_id(ksi_connection *connection)
{
    uint64_t value = connection->next_request_id++;

    if (value == 0u) {
        value = connection->next_request_id++;
    }
    return value;
}

static bool decode_hook_event(
    const uint8_t *payload,
    size_t size,
    uint64_t request_id,
    ksi_hook_event *event)
{
    uint32_t hook_type;

    if (payload == NULL || event == NULL || size < KSI_HOOK_EVENT_PREFIX_SIZE
        || read_u32(payload + 4u) != 0u) {
        return false;
    }
    hook_type = read_u32(payload);
    ksi_hook_event_init(event);
    event->hook_type = hook_type;
    event->request_id = request_id;
    if (hook_type == KSI_HOOK_KEYBOARD
        && size == KSI_HOOK_EVENT_PREFIX_SIZE + KSI_KEYBOARD_HOOK_EVENT_SIZE) {
        const uint8_t *source = payload + KSI_HOOK_EVENT_PREFIX_SIZE;
        event->event.keyboard.message = read_u32(source);
        event->event.keyboard.vk_code = read_u32(source + 4u);
        event->event.keyboard.scan_code = read_u32(source + 8u);
        event->event.keyboard.flags = read_u32(source + 12u);
        event->event.keyboard.time_ms = read_u64(source + 16u);
        event->event.keyboard.extra_info = read_u64(source + 24u);
        event->event.keyboard.device_id = read_u32(source + 32u);
        return read_u32(source + 36u) == 0u;
    }
    if (hook_type == KSI_HOOK_MOUSE
        && size == KSI_HOOK_EVENT_PREFIX_SIZE + KSI_MOUSE_HOOK_EVENT_SIZE) {
        const uint8_t *source = payload + KSI_HOOK_EVENT_PREFIX_SIZE;
        event->event.mouse.message = read_u32(source);
        event->event.mouse.x = (int32_t)read_u32(source + 4u);
        event->event.mouse.y = (int32_t)read_u32(source + 8u);
        event->event.mouse.mouse_data = read_u32(source + 12u);
        event->event.mouse.flags = read_u32(source + 16u);
        event->event.mouse.time_ms = read_u64(source + 20u);
        event->event.mouse.extra_info = read_u64(source + 28u);
        event->event.mouse.device_id = read_u32(source + 36u);
        event->event.mouse.delta_x = (int32_t)read_u32(source + 44u);
        event->event.mouse.delta_y = (int32_t)read_u32(source + 48u);
        return read_u32(source + 40u) == 0u;
    }
    return false;
}

static bool encode_input(uint8_t destination[KSI_INPUT_WIRE_SIZE],
                         const ksi_input *input)
{
    if (input == NULL
        || input->struct_size < sizeof(*input)
        || !reserved_is_zero(input->reserved, 2u)
        || (input->type != KSI_INPUT_KEYBOARD
            && input->type != KSI_INPUT_MOUSE)) {
        return false;
    }
    memset(destination, 0, KSI_INPUT_WIRE_SIZE);
    write_u32(destination, input->type);
    if (input->type == KSI_INPUT_KEYBOARD) {
        if (input->data.keyboard.reserved0 != 0u
            || !reserved_is_zero(input->data.keyboard.reserved, 2u)) {
            return false;
        }
        write_u16(destination + 8u, input->data.keyboard.vk);
        write_u16(destination + 10u, input->data.keyboard.scan);
        write_u32(destination + 12u, input->data.keyboard.flags);
        write_u32(destination + 16u, input->data.keyboard.time);
        write_u64(destination + 24u, input->data.keyboard.extra_info);
    } else {
        if (input->data.mouse.reserved0 != 0u
            || !reserved_is_zero(input->data.mouse.reserved, 2u)) {
            return false;
        }
        write_u32(destination + 8u, (uint32_t)input->data.mouse.dx);
        write_u32(destination + 12u, (uint32_t)input->data.mouse.dy);
        write_u32(destination + 16u, input->data.mouse.mouse_data);
        write_u32(destination + 20u, input->data.mouse.flags);
        write_u32(destination + 24u, input->data.mouse.time);
        write_u64(destination + 32u, input->data.mouse.extra_info);
    }
    return true;
}

static ksi_status send_hook_response(
    ksi_connection *connection,
    uint64_t request_id,
    ksi_status callback_status,
    const ksi_hook_reply *reply,
    const ksi_error *callback_error,
    ksi_error *error)
{
    size_t size = KSI_STATUS_PAYLOAD_SIZE;

    if (request_id == 0u) {
        set_error(error, 0u, EINVAL, "hook event has no request id");
        return KSI_STATUS_INVALID_REQUEST;
    }
    write_u32(connection->tx, callback_status);
    write_u32(connection->tx + 4u,
        callback_error == NULL ? 0u : callback_error->detail);
    if (callback_status == KSI_STATUS_OK) {
        uint32_t decision = reply == NULL ? KSI_HOOK_PASS : reply->decision;
        uint32_t count = reply == NULL ? 0u : reply->input_count;

        if ((reply != NULL && (reply->struct_size < sizeof(*reply)
                || reply->reserved0 != 0u
                || !reserved_is_zero(reply->reserved, 4u)))
            || (decision != KSI_HOOK_PASS && decision != KSI_HOOK_BLOCK
                && decision != KSI_HOOK_MODIFY)
            || ((decision == KSI_HOOK_MODIFY) != (count != 0u))
            || count > KSI_MAX_HOOK_REPLACEMENTS
            || (count != 0u && (reply == NULL || reply->inputs == NULL))) {
            set_error(error, 0u, EINVAL, "invalid hook reply");
            return KSI_STATUS_INVALID_REQUEST;
        }
        write_u32(connection->tx + 8u, decision);
        write_u32(connection->tx + 12u, count);
        size = KSI_HOOK_DECISION_PREFIX_SIZE
            + (size_t)count * KSI_INPUT_WIRE_SIZE;
        for (uint32_t i = 0u; i < count; i++) {
            if (!encode_input(connection->tx + KSI_HOOK_DECISION_PREFIX_SIZE
                    + (size_t)i * KSI_INPUT_WIRE_SIZE, &reply->inputs[i])) {
                set_error(error, 0u, EINVAL, "invalid hook replacement input");
                return KSI_STATUS_INVALID_REQUEST;
            }
        }
    }
    return send_frame(connection, KSI_OPCODE_HOOK_EVENT, KSI_FRAME_FLAG_RESPONSE,
        request_id, connection->tx, size, connection->default_timeout_ms, error);
}

static uint32_t apply_revocation(ksi_connection *connection,
                                 const uint8_t *payload, size_t payload_size)
{
    if (payload_size == KSI_SESSION_REVOKED_PAYLOAD_SIZE
        && read_u32(payload + 4u) == 0u) {
        uint32_t revoked = read_u32(payload);

        if (revoked == 0u) {
            return 0u;
        }
        connection->granted_scopes &= ~revoked;
        connection->pending_revoked_scopes |= revoked;
        return revoked;
    }
    return 0u;
}

static bool decode_quarantine(
    const uint8_t *payload,
    size_t payload_size,
    ksi_hook_quarantined *event)
{
    if (payload == NULL
        || payload_size != KSI_HOOK_QUARANTINED_PAYLOAD_SIZE || event == NULL
        || read_u32(payload + 28u) != 0u) {
        return false;
    }
    ksi_hook_quarantined_init(event);
    event->hook_type = read_u32(payload);
    event->reason = read_u32(payload + 4u);
    event->event_id = read_u64(payload + 8u);
    event->generation = read_u32(payload + 16u);
    event->strike_count = read_u32(payload + 20u);
    event->retry_after_ms = read_u32(payload + 24u);
    return true;
}

static bool queue_notification(
    ksi_connection *connection,
    const ksi_hook_message *message)
{
    uint32_t index;

    if (connection->notification_count == KSI_CLIENT_NOTIFICATION_CAPACITY) {
        return false;
    }
    index = (connection->notification_head + connection->notification_count)
        % KSI_CLIENT_NOTIFICATION_CAPACITY;
    connection->notifications[index] = *message;
    connection->notification_count++;
    return true;
}

static bool pop_notification(
    ksi_connection *connection,
    ksi_hook_message *message)
{
    if (connection->notification_count == 0u) {
        return false;
    }
    *message = connection->notifications[connection->notification_head];
    connection->notification_head = (connection->notification_head + 1u)
        % KSI_CLIENT_NOTIFICATION_CAPACITY;
    connection->notification_count--;
    return true;
}

static bool decode_observer(const ksi_wire_header *header, const uint8_t *payload,
    ksi_observer_message *message)
{
    if (header->payload_size < KSI_OBSERVER_PREFIX_SIZE || read_u32(payload + 4u) != 0u) return false;
    ksi_observer_message_init(message);
    message->kind = read_u32(payload);
    message->device_generation = read_u64(payload + 8u);
    message->dropped_events = read_u64(payload + 16u);
    const uint8_t *body = payload + KSI_OBSERVER_PREFIX_SIZE;
    size_t size = header->payload_size - KSI_OBSERVER_PREFIX_SIZE;
    if (message->kind == KSI_OBSERVER_INPUT)
        return decode_hook_event(body, size, header->request_id, &message->data.input);
    if (message->kind >= KSI_OBSERVER_DEVICE_ADDED && message->kind <= KSI_OBSERVER_DEVICE_CHANGED)
        return ksi_device_decode(body, size, &message->data.device);
    if (message->kind == KSI_OBSERVER_RAW_INPUT) {
        if (size != KSI_RAW_INPUT_WIRE_SIZE || read_u32(body) == 0u || read_u32(body + 28u) != 0u) return false;
        ksi_raw_input_event *event = &message->data.raw_input;
        ksi_raw_input_event_init(event);
        event->device_id = read_u32(body);
        event->time_ms = read_u64(body + 8u);
        event->type = (uint16_t)ksi_device_read(body + 16u, 2u);
        event->code = (uint16_t)ksi_device_read(body + 18u, 2u);
        event->value = (int32_t)read_u32(body + 20u);
        event->flags = read_u32(body + 24u);
        return read_u32(body + 4u) == 0u;
    }
    return message->kind == KSI_OBSERVER_OVERFLOW && size == 0u && message->dropped_events != 0u;
}

static bool queue_service_event(
    ksi_connection *connection,
    const ksi_wire_header *header)
{
    ksi_hook_message message;

    ksi_hook_message_init(&message);
    if (header->opcode == KSI_OPCODE_OBSERVER_EVENT && connection->role == KSI_ROLE_OBSERVER_STREAM) {
        ksi_observer_message observation;
        if (!decode_observer(header, connection->rx, &observation)) return false;
        if (connection->observer_count == KSI_CLIENT_NOTIFICATION_CAPACITY) {
            if (connection->observer_dropped != UINT64_MAX) connection->observer_dropped++;
        } else {
            uint32_t index = (connection->observer_head + connection->observer_count)
                % KSI_CLIENT_NOTIFICATION_CAPACITY;
            connection->observer_notifications[index] = observation;
            connection->observer_count++;
        }
        return true;
    }
    if (header->opcode == KSI_OPCODE_SESSION_REVOKED) {
        uint32_t revoked = apply_revocation(connection, connection->rx,
            header->payload_size);
        if (revoked == 0u) {
            return false;
        }
        if (connection->role == KSI_ROLE_OBSERVER_STREAM
            && (revoked & KSI_SCOPE_INPUT_MONITORING) != 0u) {
            connection->observer_count = 0u;
            connection->observer_dropped = 0u;
        }
        if (connection->role == KSI_ROLE_CALLBACK_STREAM) {
            message.kind = KSI_HOOK_MESSAGE_SESSION_REVOKED;
            message.data.revoked_scopes = revoked;
            return queue_notification(connection, &message);
        }
        return true;
    }
    if (header->opcode == KSI_OPCODE_HOOK_QUARANTINED
        && connection->role == KSI_ROLE_CALLBACK_STREAM
        && decode_quarantine(connection->rx, header->payload_size,
            &message.data.quarantined)) {
        message.kind = KSI_HOOK_MESSAGE_QUARANTINED;
        return queue_notification(connection, &message);
    }
    return false;
}

static ksi_status handle_nested_hook(
    ksi_connection *connection,
    const ksi_wire_header *header,
    ksi_error *error)
{
    ksi_hook_event event;
    ksi_hook_reply reply;
    ksi_error callback_error;
    ksi_status callback_status = KSI_STATUS_OK;

    if (!decode_hook_event(connection->rx, header->payload_size,
            header->request_id, &event)) {
        set_error(error, 0u, 0, "service returned an invalid hook event");
        return KSI_STATUS_INTERNAL;
    }
    memset(&reply, 0, sizeof(reply));
    reply.struct_size = sizeof(reply);
    reply.decision = KSI_HOOK_PASS;
    ksi_error_init(&callback_error);
    if (connection->nested_handler != NULL) {
        if (connection->recursion_depth >= KSI_CLIENT_MAX_RECURSION) {
            callback_status = KSI_STATUS_RESOURCE_EXHAUSTED;
        } else {
            connection->recursion_depth++;
            callback_status = connection->nested_handler(connection, &event,
                &reply, connection->nested_context, &callback_error);
            connection->recursion_depth--;
            if (callback_status > KSI_STATUS_REVOKED
                && callback_status != KSI_STATUS_INTERNAL) {
                callback_status = KSI_STATUS_INTERNAL;
            }
        }
    }
    return send_hook_response(connection, header->request_id, callback_status,
        &reply, &callback_error, error);
}

static ksi_status wait_response(
    ksi_connection *connection,
    uint16_t opcode,
    uint64_t request_id,
    uint32_t timeout_ms,
    ksi_wire_header *response,
    ksi_error *error)
{
    for (;;) {
        ksi_wire_header header;
        ksi_status status = receive_frame(connection, &header,
            timeout_ms, error);

        if (status != KSI_STATUS_OK) {
            return status;
        }
        if (header.flags == KSI_FRAME_FLAG_EVENT
            && queue_service_event(connection, &header)) {
            continue;
        }
        if (header.flags == 0u && header.opcode == KSI_OPCODE_HOOK_EVENT) {
            status = handle_nested_hook(connection, &header, error);
            if (status != KSI_STATUS_OK) {
                return status;
            }
            continue;
        }
        if ((header.flags & KSI_FRAME_FLAG_RESPONSE) == 0u
            || header.opcode != opcode || header.request_id != request_id) {
            set_error(error, 0u, 0, "service returned an unexpected frame");
            return KSI_STATUS_INTERNAL;
        }
        *response = header;
        return KSI_STATUS_OK;
    }
}

static ksi_status request(
    ksi_connection *connection,
    uint16_t opcode,
    const void *payload,
    size_t payload_size,
    uint32_t timeout_ms,
    ksi_wire_header *response,
    ksi_error *error)
{
    uint64_t request_id;
    ksi_status status;

    if (connection == NULL || response == NULL) {
        set_error(error, 0u, EINVAL, "invalid connection");
        return KSI_STATUS_INVALID_REQUEST;
    }
    request_id = next_request_id(connection);
    status = send_frame(connection, opcode, 0u, request_id,
        payload, payload_size, timeout_ms, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    return wait_response(connection, opcode, request_id,
        timeout_ms, response, error);
}

static ksi_status simple_request(
    ksi_connection *connection,
    uint16_t opcode,
    const void *payload,
    size_t payload_size,
    size_t success_size,
    ksi_wire_header *response,
    ksi_error *error)
{
    ksi_status status = request(connection, opcode, payload, payload_size,
        connection == NULL ? KSI_DEFAULT_REQUEST_TIMEOUT_MS
            : connection->default_timeout_ms,
        response, error);

    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (response->flags != KSI_FRAME_FLAG_RESPONSE) {
        set_error(error, 0u, 0, "service returned an invalid response flag");
        return KSI_STATUS_INTERNAL;
    }
    return decode_status(connection->rx, response->payload_size,
        success_size, error);
}

uint32_t ksi_client_abi_major(void)
{
    return KSI_CLIENT_ABI_MAJOR;
}

uint32_t ksi_client_abi_minor(void)
{
    return KSI_CLIENT_ABI_MINOR;
}

const char *ksi_client_product_name(void)
{
    return "keysharp-input";
}

const char *ksi_client_product_version(void)
{
    return KSI_PRODUCT_VERSION;
}

const char *ksi_status_name(ksi_status status)
{
    switch (status) {
        case KSI_STATUS_OK: return "ok";
        case KSI_STATUS_DENIED: return "denied";
        case KSI_STATUS_UNSUPPORTED: return "unsupported";
        case KSI_STATUS_INVALID_REQUEST: return "invalid-request";
        case KSI_STATUS_UNAVAILABLE: return "unavailable";
        case KSI_STATUS_BUSY: return "busy";
        case KSI_STATUS_NOT_FOUND: return "not-found";
        case KSI_STATUS_RESOURCE_EXHAUSTED: return "resource-exhausted";
        case KSI_STATUS_TIMEOUT: return "timeout";
        case KSI_STATUS_CANCELLED: return "cancelled";
        case KSI_STATUS_REVOKED: return "revoked";
        case KSI_STATUS_INTERNAL: return "internal";
        default: return "unknown";
    }
}

const char *ksi_scope_name(ksi_permission_scopes scope)
{
    switch (scope) {
        case KSI_SCOPE_INPUT_MONITORING: return "input-monitoring";
        case KSI_SCOPE_INPUT_CONTROL: return "input-control";
        default: return NULL;
    }
}

void ksi_connect_options_init(ksi_connect_options *options)
{
    if (options == NULL) {
        return;
    }
    memset(options, 0, sizeof(*options));
    options->struct_size = sizeof(*options);
    options->role = KSI_ROLE_RPC;
    options->authorization_mode = KSI_AUTH_CHECK;
    options->timeout_ms = KSI_DEFAULT_REQUEST_TIMEOUT_MS;
}

void ksi_error_init(ksi_error *error)
{
    init_sized(error, sizeof(*error));
}

void ksi_service_info_init(ksi_service_info *service_info)
{
    init_sized(service_info, sizeof(*service_info));
}

void ksi_permission_entry_init(ksi_permission_entry *entry)
{
    init_sized(entry, sizeof(*entry));
}

void ksi_permission_revoke_init(ksi_permission_revoke *request)
{
    init_sized(request, sizeof(*request));
}

void ksi_input_init(ksi_input *input)
{
    init_sized(input, sizeof(*input));
}

void ksi_hook_event_init(ksi_hook_event *event)
{
    init_sized(event, sizeof(*event));
}

void ksi_hook_reply_init(ksi_hook_reply *reply)
{
    init_sized(reply, sizeof(*reply));
    if (reply != NULL) {
        reply->decision = KSI_HOOK_PASS;
    }
}

void ksi_hook_quarantined_init(ksi_hook_quarantined *event)
{
    init_sized(event, sizeof(*event));
}

void ksi_hook_message_init(ksi_hook_message *message)
{
    init_sized(message, sizeof(*message));
}

void ksi_indicator_state_init(ksi_indicator_state *state)
{
    init_sized(state, sizeof(*state));
}

void ksi_pointer_position_init(ksi_pointer_position *position)
{
    init_sized(position, sizeof(*position));
}

void ksi_key_state_init(ksi_key_state *state)
{
    init_sized(state, sizeof(*state));
}

void ksi_pointer_buttons_init(ksi_pointer_buttons *buttons)
{
    init_sized(buttons, sizeof(*buttons));
}

void ksi_idle_time_init(ksi_idle_time *idle_time)
{
    init_sized(idle_time, sizeof(*idle_time));
}

void ksi_modifier_state_init(ksi_modifier_state *state)
{
    init_sized(state, sizeof(*state));
}

ksi_status ksi_connect(
    const ksi_connect_options *options,
    ksi_connection **connection,
    ksi_service_info *service_info,
    ksi_error *error)
{
    struct sockaddr_un address;
    ksi_connection *created;
    ksi_wire_header response;
    const char *socket_path;
    uint32_t timeout_ms;
    uint8_t hello[KSI_HELLO_PAYLOAD_SIZE] = { 0 };
    ksi_status status;
    int fd;

    clear_error(error);
    if (connection == NULL || options == NULL
        || options->struct_size < sizeof(*options)
        || options->flags != 0u
        || !reserved_is_zero(options->reserved, 4u)
        || options->role > KSI_ROLE_OBSERVER_STREAM
        || options->authorization_mode > KSI_AUTH_REQUEST
        || (options->requested_scopes & ~(uint32_t)KSI_SCOPE_ALL) != 0u) {
        set_error(error, 0u, EINVAL, "invalid connection options");
        return KSI_STATUS_INVALID_REQUEST;
    }
    *connection = NULL;
    socket_path = options->socket_path;
    if (socket_path == NULL || socket_path[0] == '\0') {
        socket_path = getenv(KSI_SOCKET_ENV);
    }
    if (socket_path == NULL || socket_path[0] == '\0') {
        socket_path = KSI_DEFAULT_SOCKET_PATH;
    }
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        set_error(error, 0u, ENAMETOOLONG, "socket path is too long");
        return KSI_STATUS_INVALID_REQUEST;
    }
    timeout_ms = options->timeout_ms == 0u
        ? KSI_DEFAULT_REQUEST_TIMEOUT_MS : options->timeout_ms;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        int saved = errno;
        set_error(error, 0u, saved, "socket: %s", strerror(saved));
        return KSI_STATUS_UNAVAILABLE;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (errno == EINPROGRESS) {
            uint64_t deadline = timeout_ms == UINT32_MAX
                ? 0u : monotonic_ms() + timeout_ms;
            status = wait_fd(fd, POLLOUT, deadline, timeout_ms, error);
            if (status == KSI_STATUS_OK) {
                int socket_error = 0;
                socklen_t length = sizeof(socket_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                        &socket_error, &length) != 0 || socket_error != 0) {
                    int saved = socket_error != 0 ? socket_error : errno;
                    set_error(error, 0u, saved, "connect %s: %s",
                        socket_path, strerror(saved));
                    status = KSI_STATUS_UNAVAILABLE;
                }
            }
            if (status != KSI_STATUS_OK) {
                (void)close(fd);
                return status;
            }
        } else {
            int saved = errno;
            set_error(error, 0u, saved, "connect %s: %s",
                socket_path, strerror(saved));
            (void)close(fd);
            return KSI_STATUS_UNAVAILABLE;
        }
    }
    created = calloc(1u, sizeof(*created));
    if (created == NULL) {
        int saved = errno;
        set_error(error, 0u, saved, "allocate connection: %s", strerror(saved));
        (void)close(fd);
        return KSI_STATUS_RESOURCE_EXHAUSTED;
    }
    created->fd = fd;
    created->role = options->role;
    created->default_timeout_ms = timeout_ms;
    created->next_request_id = 1u;
    write_u16(hello, (uint16_t)options->role);
    write_u16(hello + 2u, (uint16_t)options->authorization_mode);
    write_u32(hello + 4u, options->requested_scopes);
    status = request(created, KSI_OPCODE_HELLO, hello, sizeof(hello),
        timeout_ms, &response, error);
    if (status == KSI_STATUS_OK) {
        status = decode_status(created->rx, response.payload_size,
            KSI_HELLO_RESULT_PAYLOAD_SIZE, error);
    }
    if (status == KSI_STATUS_OK && response.flags != KSI_FRAME_FLAG_RESPONSE) {
        set_error(error, 0u, 0, "service returned an invalid HELLO response");
        status = KSI_STATUS_INTERNAL;
    }
    if (status != KSI_STATUS_OK) {
        ksi_disconnect(created);
        return status;
    }
    created->granted_scopes = read_u32(created->rx + 8u)
        & (uint32_t)KSI_SCOPE_ALL;
    created->available_operations = read_u64(created->rx + 16u);
    if (read_u32(created->rx + 12u) != 0u) {
        set_error(error, 0u, 0, "service returned invalid authorization data");
        ksi_disconnect(created);
        return KSI_STATUS_INTERNAL;
    }
    if (service_info != NULL) {
        size_t size = service_info->struct_size == 0u
            ? sizeof(*service_info) : service_info->struct_size;
        if (size < offsetof(ksi_service_info, reserved)) {
            set_error(error, 0u, EINVAL, "service-info structure is too small");
            ksi_disconnect(created);
            return KSI_STATUS_INVALID_REQUEST;
        }
        if (size > sizeof(*service_info)) {
            size = sizeof(*service_info);
        }
        memset(service_info, 0, size);
        service_info->struct_size = (uint32_t)size;
        service_info->abi_major = KSI_CLIENT_ABI_MAJOR;
        service_info->abi_minor = KSI_CLIENT_ABI_MINOR;
        service_info->granted_scopes = created->granted_scopes;
        service_info->available_operations = created->available_operations;
    }
    *connection = created;
    return KSI_STATUS_OK;
}

void ksi_disconnect(ksi_connection *connection)
{
    if (connection == NULL) {
        return;
    }
    if (connection->fd >= 0) {
        (void)close(connection->fd);
        connection->fd = -1;
    }
    memset(connection, 0, sizeof(*connection));
    free(connection);
}

ksi_status ksi_authorize(
    ksi_connection *connection,
    ksi_authorization_mode authorization_mode,
    ksi_permission_scopes requested_scopes,
    ksi_permission_scopes *granted_scopes,
    ksi_error *error)
{
    uint8_t payload[KSI_AUTHORIZE_PAYLOAD_SIZE] = { 0 };
    ksi_wire_header response;
    ksi_status status;

    if (connection == NULL || authorization_mode > KSI_AUTH_REQUEST
        || requested_scopes == 0u
        || (requested_scopes & ~(ksi_permission_scopes)KSI_SCOPE_ALL) != 0u) {
        set_error(error, 0u, EINVAL, "invalid authorization request");
        return KSI_STATUS_INVALID_REQUEST;
    }
    write_u16(payload, (uint16_t)authorization_mode);
    write_u32(payload + 4u, requested_scopes);
    status = simple_request(connection, KSI_OPCODE_AUTHORIZE,
        payload, sizeof(payload), KSI_AUTHORIZE_RESULT_PAYLOAD_SIZE,
        &response, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (read_u32(connection->rx + 12u) != 0u) {
        set_error(error, 0u, 0, "service returned invalid authorization data");
        return KSI_STATUS_INTERNAL;
    }
    connection->granted_scopes |= read_u32(connection->rx + 8u)
        & (uint32_t)KSI_SCOPE_ALL;
    if (granted_scopes != NULL) {
        *granted_scopes = connection->granted_scopes;
    }
    return KSI_STATUS_OK;
}

ksi_status ksi_ping(ksi_connection *connection, ksi_error *error)
{
    ksi_wire_header response;
    return simple_request(connection, KSI_OPCODE_PING, NULL, 0u,
        KSI_STATUS_PAYLOAD_SIZE, &response, error);
}

ksi_permission_scopes ksi_connection_granted_scopes(
    const ksi_connection *connection)
{
    return connection == NULL ? 0u : connection->granted_scopes;
}

ksi_operations ksi_connection_available_operations(
    const ksi_connection *connection)
{
    return connection == NULL ? 0u : connection->available_operations;
}

ksi_status ksi_permissions_list(
    ksi_connection *connection,
    ksi_permission_visitor visitor,
    void *context,
    ksi_error *error)
{
    ksi_wire_header response;
    uint64_t request_id;
    ksi_status status;
    bool cancelled = false;

    if (connection == NULL || visitor == NULL
        || connection->role != KSI_ROLE_RPC) {
        set_error(error, 0u, EINVAL, "invalid permissions-list request");
        return KSI_STATUS_INVALID_REQUEST;
    }
    request_id = next_request_id(connection);
    status = send_frame(connection, KSI_OPCODE_PERMISSIONS_LIST, 0u,
        request_id, NULL, 0u, connection->default_timeout_ms, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    for (;;) {
        status = wait_response(connection, KSI_OPCODE_PERMISSIONS_LIST,
            request_id, connection->default_timeout_ms, &response, error);
        if (status != KSI_STATUS_OK) {
            return status;
        }
        if (response.flags == KSI_FRAME_FLAG_RESPONSE) {
            status = decode_status(connection->rx, response.payload_size,
                KSI_STATUS_PAYLOAD_SIZE, error);
            return status == KSI_STATUS_OK && cancelled
                ? KSI_STATUS_CANCELLED : status;
        }
        if (response.flags != (KSI_FRAME_FLAG_RESPONSE | KSI_FRAME_FLAG_MORE)
            || response.payload_size < KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE) {
            set_error(error, 0u, 0, "service returned an invalid permission entry");
            return KSI_STATUS_INTERNAL;
        }
        status = decode_status(connection->rx, response.payload_size,
            response.payload_size, error);
        if (status != KSI_STATUS_OK) {
            return status;
        }
        {
            uint32_t path_length = read_u32(connection->rx + 12u);
            ksi_permission_entry entry;
            static const char digits[] = "0123456789abcdef";

            if ((size_t)path_length
                    != response.payload_size - KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE
                || path_length >= KSI_EXECUTABLE_PATH_SIZE) {
                set_error(error, 0u, 0, "service returned an invalid permission entry");
                return KSI_STATUS_INTERNAL;
            }
            if (!cancelled) {
                ksi_permission_entry_init(&entry);
                entry.scopes = read_u32(connection->rx + 8u);
                entry.granted_at_utc = read_u64(connection->rx + 16u);
            for (size_t i = 0u; i < KSI_PERMISSION_HASH_SIZE; i++) {
                    uint8_t value = connection->rx[24u + i];
                    entry.hash[i * 2u] = digits[value >> 4u];
                    entry.hash[i * 2u + 1u] = digits[value & 0x0fu];
                }
                memcpy(entry.executable,
                    connection->rx + KSI_PERMISSIONS_LIST_ENTRY_FIXED_SIZE,
                    path_length);
                if (!visitor(&entry, context)) {
                    cancelled = true;
                }
            }
        }
    }
}

static bool decode_hex_hash(
    const char *hash, uint8_t destination[KSI_PERMISSION_HASH_SIZE])
{
    if (hash == NULL || strnlen(hash, KSI_PERMISSION_HASH_HEX_SIZE) != 64u) {
        return false;
    }
    for (size_t i = 0u; i < KSI_PERMISSION_HASH_SIZE; i++) {
        unsigned int high;
        unsigned int low;
        char a = hash[i * 2u];
        char b = hash[i * 2u + 1u];
        if ((a < '0' || a > '9') && (a < 'a' || a > 'f')) {
            return false;
        }
        if ((b < '0' || b > '9') && (b < 'a' || b > 'f')) {
            return false;
        }
        high = (unsigned int)(a <= '9' ? a - '0' : a - 'a' + 10);
        low = (unsigned int)(b <= '9' ? b - '0' : b - 'a' + 10);
        destination[i] = (uint8_t)((high << 4u) | low);
    }
    return true;
}

ksi_status ksi_permissions_revoke(
    ksi_connection *connection,
    const ksi_permission_revoke *request,
    ksi_error *error)
{
    uint8_t payload[KSI_PERMISSIONS_REVOKE_PAYLOAD_SIZE] = { 0 };
    ksi_wire_header response;

    if (connection == NULL || request == NULL
        || connection->role != KSI_ROLE_RPC
        || request->struct_size < sizeof(*request)
        || request->scopes == 0u
        || (request->scopes & ~(uint32_t)KSI_SCOPE_ALL) != 0u
        || request->reserved0 != 0u
        || !bytes_are_zero(request->reserved1, sizeof(request->reserved1))
        || !reserved_is_zero(request->reserved, 4u)
        || (request->target_kind != KSI_PERMISSION_TARGET_HASH
            && request->target_kind != KSI_PERMISSION_TARGET_PID
            && request->target_kind != KSI_PERMISSION_TARGET_ALL)
        || (request->target_kind == KSI_PERMISSION_TARGET_HASH
            && (request->pid != 0u
                || !decode_hex_hash(request->hash, payload + 16u)))
        || (request->target_kind == KSI_PERMISSION_TARGET_PID
            && (request->pid == 0u || request->pid > (uint64_t)INT_MAX
                || !bytes_are_zero(request->hash, sizeof(request->hash))))
        || (request->target_kind == KSI_PERMISSION_TARGET_ALL
            && (request->pid != 0u
                || !bytes_are_zero(request->hash, sizeof(request->hash))))) {
        set_error(error, 0u, EINVAL, "invalid permissions-revoke request");
        return KSI_STATUS_INVALID_REQUEST;
    }
    write_u32(payload, request->target_kind);
    write_u32(payload + 4u, request->scopes);
    write_u64(payload + 8u, request->pid);
    return simple_request(connection, KSI_OPCODE_PERMISSIONS_REVOKE,
        payload, sizeof(payload), KSI_STATUS_PAYLOAD_SIZE, &response, error);
}

ksi_permission_scopes ksi_lease_granted_scopes(
    const ksi_connection *connection)
{
    return connection != NULL
            && connection->role == KSI_ROLE_AUTHORIZATION_LEASE
        ? connection->granted_scopes : 0u;
}

ksi_status ksi_lease_next(
    ksi_connection *connection,
    uint32_t timeout_ms,
    ksi_permission_scopes *revoked_scopes,
    ksi_error *error)
{
    if (connection == NULL || revoked_scopes == NULL
        || connection->role != KSI_ROLE_AUTHORIZATION_LEASE) {
        set_error(error, 0u, EINVAL, "connection is not an authorization lease");
        return KSI_STATUS_INVALID_REQUEST;
    }
    for (;;) {
        ksi_wire_header header;
        ksi_status status;

        if (connection->pending_revoked_scopes != 0u) {
            *revoked_scopes = connection->pending_revoked_scopes;
            connection->pending_revoked_scopes = 0u;
            clear_error(error);
            return KSI_STATUS_OK;
        }
        status = receive_frame(connection, &header, timeout_ms, error);
        if (status != KSI_STATUS_OK) {
            return status;
        }
        if (header.flags == KSI_FRAME_FLAG_EVENT
            && header.opcode == KSI_OPCODE_SESSION_REVOKED) {
            apply_revocation(connection, connection->rx, header.payload_size);
            if (connection->pending_revoked_scopes == 0u) {
                set_error(error, 0u, 0, "service returned an invalid revocation");
                return KSI_STATUS_INTERNAL;
            }
            continue;
        }
        set_error(error, 0u, 0, "service returned an unexpected lease frame");
        return KSI_STATUS_INTERNAL;
    }
}

ksi_status ksi_set_nested_hook_handler(
    ksi_connection *connection,
    ksi_nested_hook_handler handler,
    void *context,
    ksi_error *error)
{
    if (connection == NULL || connection->role != KSI_ROLE_CALLBACK_STREAM) {
        set_error(error, 0u, EINVAL, "connection is not a callback stream");
        return KSI_STATUS_INVALID_REQUEST;
    }
    connection->nested_handler = handler;
    connection->nested_context = context;
    clear_error(error);
    return KSI_STATUS_OK;
}

void ksi_device_info_init(ksi_device_info *device)
{
    init_sized(device, sizeof(*device));
}

void ksi_device_axis_info_init(ksi_device_axis_info *axis)
{
    init_sized(axis, sizeof(*axis));
}

void ksi_raw_input_event_init(ksi_raw_input_event *event)
{
    init_sized(event, sizeof(*event));
}

void ksi_observer_message_init(ksi_observer_message *message)
{
    init_sized(message, sizeof(*message));
}

ksi_status ksi_devices_list(ksi_connection *connection,
    ksi_device_visitor visitor, void *context, uint64_t *snapshot_generation, ksi_error *error)
{
    if (snapshot_generation != NULL) *snapshot_generation = 0u;
    if (connection == NULL || visitor == NULL) {
        set_error(error, 0u, EINVAL, "invalid device visitor");
        return KSI_STATUS_INVALID_REQUEST;
    }
    uint32_t offset = 0u;
    uint64_t generation = 0u;
    do {
        uint8_t payload[KSI_DEVICE_LIST_REQUEST_SIZE] = { 0 };
        ksi_wire_header response;
        write_u32(payload, offset);
        write_u64(payload + 8u, generation);
        ksi_status status = request(connection, KSI_OPCODE_DEVICES_LIST,
            payload, sizeof(payload), connection->default_timeout_ms, &response, error);
        if (status != KSI_STATUS_OK) return status;
        status = decode_status(connection->rx, response.payload_size, response.payload_size, error);
        if (status != KSI_STATUS_OK) return status;
        if (response.flags != KSI_FRAME_FLAG_RESPONSE || response.payload_size < KSI_DEVICE_LIST_PREFIX_SIZE)
            return invalid_result(error, "device list");
        uint32_t count = read_u32(connection->rx + 20u);
        uint32_t next = read_u32(connection->rx + 16u);
        uint64_t returned_generation = read_u64(connection->rx + 8u);
        if (count > KSI_DEVICE_LIST_PAGE_SIZE
            || response.payload_size != KSI_DEVICE_LIST_PREFIX_SIZE + count * KSI_DEVICE_INFO_WIRE_SIZE
            || (next != 0u && next <= offset)
            || (generation != 0u && returned_generation != generation))
            return invalid_result(error, "device list");
        generation = returned_generation;
        for (uint32_t i = 0u; i < count; i++) {
            ksi_device_info device;
            if (!ksi_device_decode(connection->rx + KSI_DEVICE_LIST_PREFIX_SIZE
                    + (size_t)i * KSI_DEVICE_INFO_WIRE_SIZE, KSI_DEVICE_INFO_WIRE_SIZE, &device))
                return invalid_result(error, "device");
            if (!visitor(&device, context)) return KSI_STATUS_CANCELLED;
        }
        offset = next;
    } while (offset != 0u);
    if (snapshot_generation != NULL) *snapshot_generation = generation;
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_observer_next(ksi_connection *connection,
    uint32_t timeout_ms, ksi_observer_message *message, ksi_error *error)
{
    if (connection == NULL || connection->role != KSI_ROLE_OBSERVER_STREAM
        || !sized_output_is_valid(message, sizeof(*message)))
        return invalid_output(error, "observer message");
    uint64_t deadline = timeout_ms == UINT32_MAX ? 0u : monotonic_ms() + timeout_ms;
    for (;;) {
        if (connection->pending_revoked_scopes != 0u) {
            ksi_observer_message_init(message);
            message->kind = KSI_OBSERVER_SESSION_REVOKED;
            message->data.revoked_scopes = connection->pending_revoked_scopes;
            connection->pending_revoked_scopes = 0u;
            clear_error(error);
            return KSI_STATUS_OK;
        }
        if (connection->observer_count != 0u) {
            *message = connection->observer_notifications[connection->observer_head];
            connection->observer_head = (connection->observer_head + 1u) % KSI_CLIENT_NOTIFICATION_CAPACITY;
            connection->observer_count--;
            clear_error(error);
            return KSI_STATUS_OK;
        }
        if (connection->observer_dropped != 0u) {
            ksi_observer_message_init(message);
            message->kind = KSI_OBSERVER_OVERFLOW;
            message->dropped_events = connection->observer_dropped;
            connection->observer_dropped = 0u;
            clear_error(error);
            return KSI_STATUS_OK;
        }
        ksi_wire_header header;
        uint32_t wait = timeout_ms == UINT32_MAX ? UINT32_MAX
            : (uint32_t)remaining_timeout(deadline, timeout_ms);
        ksi_status status = receive_frame(connection, &header, wait, error);
        if (status != KSI_STATUS_OK) return status;
        if (header.flags == KSI_FRAME_FLAG_EVENT && queue_service_event(connection, &header)) continue;
        return invalid_result(error, "observer frame");
    }
}

static ksi_status hook_subscription(
    ksi_connection *connection,
    uint16_t opcode,
    ksi_hook_type hook_type,
    ksi_operations *active_operations,
    ksi_error *error)
{
    uint8_t payload[KSI_HOOK_SUBSCRIPTION_PAYLOAD_SIZE] = { 0 };
    ksi_wire_header response;
    ksi_status status;

    if (connection == NULL || (connection->role != KSI_ROLE_CALLBACK_STREAM
            && connection->role != KSI_ROLE_OBSERVER_STREAM)
        || (hook_type != KSI_HOOK_KEYBOARD && hook_type != KSI_HOOK_MOUSE)) {
        set_error(error, 0u, EINVAL, "invalid hook subscription");
        return KSI_STATUS_INVALID_REQUEST;
    }
    write_u32(payload, hook_type);
    status = simple_request(connection, opcode, payload, sizeof(payload),
        KSI_HOOK_SUBSCRIPTION_RESULT_PAYLOAD_SIZE, &response, error);
    if (status == KSI_STATUS_OK && read_u32(connection->rx + 12u) != 0u) {
        set_error(error, 0u, 0, "service returned invalid hook state");
        return KSI_STATUS_INTERNAL;
    }
    if (status == KSI_STATUS_OK && active_operations != NULL) {
        *active_operations = (ksi_operations)read_u32(connection->rx + 8u);
    }
    return status;
}

ksi_status ksi_hook_subscribe(
    ksi_connection *connection,
    ksi_hook_type hook_type,
    ksi_operations *active_operations,
    ksi_error *error)
{
    return hook_subscription(connection, KSI_OPCODE_SUBSCRIBE_HOOK,
        hook_type, active_operations, error);
}

ksi_status ksi_hook_unsubscribe(
    ksi_connection *connection,
    ksi_hook_type hook_type,
    ksi_operations *active_operations,
    ksi_error *error)
{
    return hook_subscription(connection, KSI_OPCODE_UNSUBSCRIBE_HOOK,
        hook_type, active_operations, error);
}

ksi_status ksi_hook_next(
    ksi_connection *connection,
    uint32_t timeout_ms,
    ksi_hook_message *message,
    ksi_error *error)
{
    uint64_t deadline;

    if (connection == NULL || message == NULL
        || message->struct_size < sizeof(*message)
        || connection->role != KSI_ROLE_CALLBACK_STREAM) {
        set_error(error, 0u, EINVAL, "invalid callback stream");
        return KSI_STATUS_INVALID_REQUEST;
    }
    if (connection->outstanding_hook_request != 0u) {
        set_error(error, 0u, 0, "the previous hook event needs a reply");
        return KSI_STATUS_BUSY;
    }
    if (pop_notification(connection, message)) {
        clear_error(error);
        return KSI_STATUS_OK;
    }
    deadline = timeout_ms == UINT32_MAX
        ? 0u : monotonic_ms() + timeout_ms;
    for (;;) {
        ksi_wire_header header;
        uint32_t wait_ms = KSI_CLIENT_HOOK_HEARTBEAT_MS;
        ksi_status status;

        if (timeout_ms != UINT32_MAX) {
            int remaining = remaining_timeout(deadline, timeout_ms);
            wait_ms = remaining < (int)KSI_CLIENT_HOOK_HEARTBEAT_MS
                ? (uint32_t)remaining : KSI_CLIENT_HOOK_HEARTBEAT_MS;
        }
        status = receive_frame(connection, &header, wait_ms, error);

        if (status == KSI_STATUS_TIMEOUT) {
            status = send_frame(connection, KSI_OPCODE_PING, 0u, 0u,
                NULL, 0u, 0u, error);
            if (status != KSI_STATUS_OK) {
                return status;
            }
            if (timeout_ms != UINT32_MAX
                && remaining_timeout(deadline, timeout_ms) == 0) {
                set_error(error, 0u, 0, "operation timed out");
                return KSI_STATUS_TIMEOUT;
            }
            clear_error(error);
            continue;
        }
        if (status != KSI_STATUS_OK) {
            return status;
        }
        if (header.flags == KSI_FRAME_FLAG_EVENT
            && queue_service_event(connection, &header)) {
            if (pop_notification(connection, message)) {
                clear_error(error);
                return KSI_STATUS_OK;
            }
            continue;
        }
        if (header.flags != 0u || header.opcode != KSI_OPCODE_HOOK_EVENT
            || !decode_hook_event(connection->rx, header.payload_size,
                header.request_id, &message->data.event)) {
            set_error(error, 0u, 0, "service returned an invalid hook frame");
            return KSI_STATUS_INTERNAL;
        }
        message->struct_size = sizeof(*message);
        message->kind = KSI_HOOK_MESSAGE_EVENT;
        connection->outstanding_hook_request = header.request_id;
        clear_error(error);
        return KSI_STATUS_OK;
    }
}

ksi_status ksi_hook_reply_event(
    ksi_connection *connection,
    const ksi_hook_event *event,
    const ksi_hook_reply *reply,
    ksi_error *error)
{
    ksi_status status;

    if (connection == NULL || event == NULL || reply == NULL
        || event->request_id == 0u
        || event->request_id != connection->outstanding_hook_request) {
        set_error(error, 0u, EINVAL, "hook reply does not match the pending event");
        return KSI_STATUS_INVALID_REQUEST;
    }
    status = send_hook_response(connection, event->request_id,
        KSI_STATUS_OK, reply, NULL, error);
    if (status == KSI_STATUS_OK) {
        connection->outstanding_hook_request = 0u;
    }
    return status;
}

ksi_status ksi_synthesize(
    ksi_connection *connection,
    const ksi_input *inputs,
    uint32_t input_count,
    uint32_t flags,
    ksi_error *error)
{
    ksi_wire_header response;
    size_t size;

    if (connection == NULL || input_count > KSI_MAX_SYNTH_INPUTS
        || (input_count != 0u && inputs == NULL)
        || (flags & ~(uint32_t)KSI_SYNTH_BYPASS_HOOK) != 0u) {
        set_error(error, 0u, EINVAL, "invalid synthesis request");
        return KSI_STATUS_INVALID_REQUEST;
    }
    size = KSI_SYNTHESIZE_PREFIX_SIZE
        + (size_t)input_count * KSI_INPUT_WIRE_SIZE;
    write_u32(connection->tx, input_count);
    write_u32(connection->tx + 4u, flags);
    for (uint32_t i = 0u; i < input_count; i++) {
        if (!encode_input(connection->tx + KSI_SYNTHESIZE_PREFIX_SIZE
                + (size_t)i * KSI_INPUT_WIRE_SIZE, &inputs[i])) {
            set_error(error, 0u, EINVAL, "invalid synthesis input");
            return KSI_STATUS_INVALID_REQUEST;
        }
    }
    return simple_request(connection, KSI_OPCODE_SYNTHESIZE_INPUT,
        connection->tx, size, KSI_STATUS_PAYLOAD_SIZE, &response, error);
}

ksi_status ksi_set_block_input(
    ksi_connection *connection,
    uint32_t block_mask,
    uint32_t *effective_mask,
    ksi_error *error)
{
    uint8_t payload[KSI_BLOCK_INPUT_PAYLOAD_SIZE] = { 0 };
    ksi_wire_header response;
    ksi_status status;

    if ((block_mask & ~3u) != 0u) {
        set_error(error, 0u, EINVAL, "invalid block-input mask");
        return KSI_STATUS_INVALID_REQUEST;
    }
    write_u32(payload, block_mask);
    status = simple_request(connection, KSI_OPCODE_SET_BLOCK_INPUT,
        payload, sizeof(payload), KSI_BLOCK_INPUT_RESULT_PAYLOAD_SIZE,
        &response, error);
    if (status == KSI_STATUS_OK && read_u32(connection->rx + 12u) != 0u) {
        set_error(error, 0u, 0, "service returned invalid block-input state");
        return KSI_STATUS_INTERNAL;
    }
    if (status == KSI_STATUS_OK && effective_mask != NULL) {
        *effective_mask = read_u32(connection->rx + 8u);
    }
    return status;
}

static ksi_status query(
    ksi_connection *connection,
    uint16_t opcode,
    size_t wire_size,
    ksi_error *error)
{
    ksi_wire_header response;
    return simple_request(connection, opcode, NULL, 0u,
        KSI_STATUS_PAYLOAD_SIZE + wire_size, &response, error);
}

ksi_status ksi_get_indicator_state(
    ksi_connection *connection,
    ksi_indicator_state *state,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(state, sizeof(*state))) {
        return invalid_output(error, "indicator-state");
    }
    status = query(connection, KSI_OPCODE_GET_INDICATOR_STATE,
        KSI_INDICATOR_STATE_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[8u] > 1u || connection->rx[9u] > 1u
        || connection->rx[10u] > 1u || connection->rx[11u] != 0u) {
        return invalid_result(error, "indicator-state");
    }
    memset(state, 0, sizeof(*state));
    state->struct_size = sizeof(*state);
    state->caps_lock = connection->rx[8u];
    state->num_lock = connection->rx[9u];
    state->scroll_lock = connection->rx[10u];
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_get_pointer_position(
    ksi_connection *connection,
    ksi_pointer_position *position,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(position, sizeof(*position))) {
        return invalid_output(error, "pointer-position");
    }
    status = query(connection, KSI_OPCODE_GET_POINTER_POSITION,
        KSI_POINTER_POSITION_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[8u] > 1u
        || !bytes_are_zero(connection->rx + 9u, 3u)) {
        return invalid_result(error, "pointer-position");
    }
    memset(position, 0, sizeof(*position));
    position->struct_size = sizeof(*position);
    position->valid = connection->rx[8u];
    position->x = (int32_t)read_u32(connection->rx + 12u);
    position->y = (int32_t)read_u32(connection->rx + 16u);
    position->x_min = (int32_t)read_u32(connection->rx + 20u);
    position->x_max = (int32_t)read_u32(connection->rx + 24u);
    position->y_min = (int32_t)read_u32(connection->rx + 28u);
    position->y_max = (int32_t)read_u32(connection->rx + 32u);
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_get_key_state(
    ksi_connection *connection,
    ksi_key_state *state,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(state, sizeof(*state))) {
        return invalid_output(error, "key-state");
    }
    status = query(connection, KSI_OPCODE_GET_KEY_STATE,
        KSI_KEY_STATE_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[12u] > 1u || connection->rx[13u] > 1u
        || connection->rx[14u] > 1u || connection->rx[15u] != 0u) {
        return invalid_result(error, "key-state");
    }
    memset(state, 0, sizeof(*state));
    state->struct_size = sizeof(*state);
    state->modifiers_lr = read_u32(connection->rx + 8u);
    state->caps_lock = connection->rx[12u];
    state->num_lock = connection->rx[13u];
    state->scroll_lock = connection->rx[14u];
    memcpy(state->logical_keys, connection->rx + 16u, KSI_KEY_STATE_BITMAP_BYTES);
    memcpy(state->physical_keys, connection->rx + 16u + KSI_KEY_STATE_BITMAP_BYTES,
        KSI_KEY_STATE_BITMAP_BYTES);
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_get_pointer_buttons(
    ksi_connection *connection,
    ksi_pointer_buttons *buttons,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(buttons, sizeof(*buttons))) {
        return invalid_output(error, "pointer-buttons");
    }
    status = query(connection, KSI_OPCODE_GET_POINTER_BUTTONS,
        KSI_POINTER_BUTTONS_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[8u] > 1u
        || !bytes_are_zero(connection->rx + 9u, 3u)) {
        return invalid_result(error, "pointer-buttons");
    }
    memset(buttons, 0, sizeof(*buttons));
    buttons->struct_size = sizeof(*buttons);
    buttons->valid = connection->rx[8u];
    buttons->logical_buttons = read_u32(connection->rx + 12u);
    buttons->physical_buttons = read_u32(connection->rx + 16u);
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_get_idle_time(
    ksi_connection *connection,
    ksi_idle_time *idle_time,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(idle_time, sizeof(*idle_time))) {
        return invalid_output(error, "idle-time");
    }
    status = query(connection, KSI_OPCODE_GET_IDLE_TIME,
        KSI_IDLE_TIME_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[8u] > 1u
        || !bytes_are_zero(connection->rx + 9u, 7u)) {
        return invalid_result(error, "idle-time");
    }
    memset(idle_time, 0, sizeof(*idle_time));
    idle_time->struct_size = sizeof(*idle_time);
    idle_time->valid = connection->rx[8u];
    idle_time->idle_time_ms = read_u64(connection->rx + 16u);
    clear_error(error);
    return KSI_STATUS_OK;
}

ksi_status ksi_get_modifier_state(
    ksi_connection *connection,
    ksi_modifier_state *state,
    ksi_error *error)
{
    ksi_status status;

    if (!sized_output_is_valid(state, sizeof(*state))) {
        return invalid_output(error, "modifier-state");
    }
    status = query(connection, KSI_OPCODE_GET_MODIFIER_STATE,
        KSI_MODIFIER_STATE_PAYLOAD_SIZE, error);
    if (status != KSI_STATUS_OK) {
        return status;
    }
    if (connection->rx[16u] > 1u || connection->rx[17u] > 1u
        || connection->rx[18u] > 1u || connection->rx[19u] != 0u) {
        return invalid_result(error, "modifier-state");
    }
    memset(state, 0, sizeof(*state));
    state->struct_size = sizeof(*state);
    state->logical_modifiers_lr = read_u32(connection->rx + 8u);
    state->physical_modifiers_lr = read_u32(connection->rx + 12u);
    state->caps_lock = connection->rx[16u];
    state->num_lock = connection->rx[17u];
    state->scroll_lock = connection->rx[18u];
    clear_error(error);
    return KSI_STATUS_OK;
}
