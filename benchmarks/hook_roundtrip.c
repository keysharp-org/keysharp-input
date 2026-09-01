#include "keysharp_input/client.h"
#include "internal/protocol_contract.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define HEADER_SIZE 24u
#define RESPONSE_FLAG 0x0001u
#define HELLO_OPCODE 0x0001u
#define HOOK_EVENT_OPCODE 0x1002u
#define WARMUP_ITERATIONS 1000u
#define MEASURED_ITERATIONS 20000u
#define TRIAL_COUNT 5u

typedef struct benchmark_server {
    int listener;
    uint64_t elapsed_ns;
    bool failed;
} benchmark_server;

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

static bool transfer_all(int descriptor, void *buffer, size_t size, bool writing)
{
    size_t offset = 0u;

    while (offset < size) {
        ssize_t count = writing
            ? write(descriptor, (const uint8_t *)buffer + offset, size - offset)
            : read(descriptor, (uint8_t *)buffer + offset, size - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static bool send_frame(
    int descriptor,
    uint16_t opcode,
    uint16_t flags,
    uint64_t request_id,
    const uint8_t *payload,
    uint32_t payload_size)
{
    uint8_t header[HEADER_SIZE] = { 'K', 'S', 'I', 'P' };

    write_u16(header + 4u, KSI_PROTOCOL_MAJOR);
    write_u16(header + 6u, KSI_PROTOCOL_MINOR);
    write_u16(header + 8u, opcode);
    write_u16(header + 10u, flags);
    write_u32(header + 12u, payload_size);
    write_u64(header + 16u, request_id);
    return transfer_all(descriptor, header, sizeof(header), true)
        && (payload_size == 0u
            || transfer_all(descriptor, (void *)payload, payload_size, true));
}

static bool receive_frame(
    int descriptor,
    uint16_t *opcode,
    uint16_t *flags,
    uint64_t *request_id,
    uint8_t *payload,
    size_t capacity,
    uint32_t *payload_size)
{
    uint8_t header[HEADER_SIZE];

    if (!transfer_all(descriptor, header, sizeof(header), false)
        || memcmp(header, "KSIP", 4u) != 0
        || read_u16(header + 4u) != KSI_PROTOCOL_MAJOR
        || read_u16(header + 6u) != KSI_PROTOCOL_MINOR) {
        return false;
    }
    *opcode = read_u16(header + 8u);
    *flags = read_u16(header + 10u);
    *payload_size = read_u32(header + 12u);
    *request_id = read_u64(header + 16u);
    return *payload_size <= capacity
        && (*payload_size == 0u
            || transfer_all(descriptor, payload, *payload_size, false));
}

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end)
{
    uint64_t seconds = (uint64_t)(end->tv_sec - start->tv_sec);
    int64_t nanoseconds = end->tv_nsec - start->tv_nsec;

    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += INT64_C(1000000000);
    }
    return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
}

static bool exchange_hook_events(int descriptor, uint64_t *duration_ns)
{
    uint8_t event[48] = { 0 };
    uint8_t reply[32];
    struct timespec start;
    struct timespec end;
    uint32_t total = WARMUP_ITERATIONS + MEASURED_ITERATIONS;

    write_u32(event, KSI_HOOK_KEYBOARD);
    write_u32(event + 8u, KSI_MESSAGE_KEY_DOWN);
    write_u32(event + 12u, 0x41u);
    for (uint32_t index = 0u; index < total; index++) {
        uint16_t opcode;
        uint16_t flags;
        uint64_t request_id;
        uint32_t reply_size;

        if (index == WARMUP_ITERATIONS
            && clock_gettime(CLOCK_MONOTONIC_RAW, &start) != 0) {
            return false;
        }
        request_id = (uint64_t)index + 1u;
        if (!send_frame(descriptor, HOOK_EVENT_OPCODE, 0u,
                request_id, event, sizeof(event))
            || !receive_frame(descriptor, &opcode, &flags, &request_id,
                reply, sizeof(reply), &reply_size)
            || opcode != HOOK_EVENT_OPCODE
            || flags != RESPONSE_FLAG
            || request_id != (uint64_t)index + 1u
            || reply_size != 16u
            || read_u32(reply) != KSI_STATUS_OK
            || read_u32(reply + 4u) != 0u
            || read_u32(reply + 8u) != KSI_HOOK_PASS
            || read_u32(reply + 12u) != 0u) {
            return false;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) != 0) {
        return false;
    }
    *duration_ns = elapsed_ns(&start, &end);
    return true;
}

static void *server_main(void *argument)
{
    benchmark_server *server = argument;
    uint8_t payload[32];
    uint16_t opcode;
    uint16_t flags;
    uint64_t request_id;
    uint32_t payload_size;
    int descriptor = accept(server->listener, NULL, NULL);

    if (descriptor < 0
        || !receive_frame(descriptor, &opcode, &flags, &request_id,
            payload, sizeof(payload), &payload_size)
        || opcode != HELLO_OPCODE || flags != 0u || request_id == 0u
        || payload_size != 16u
        || read_u16(payload) != KSI_ROLE_CALLBACK_STREAM) {
        server->failed = true;
        if (descriptor >= 0) close(descriptor);
        return NULL;
    }
    memset(payload, 0, 24u);
    write_u32(payload, KSI_STATUS_OK);
    write_u32(payload + 8u, KSI_SCOPE_INPUT_MONITORING);
    write_u64(payload + 16u, KSI_OPERATION_HOOK_KEYBOARD);
    server->failed = !send_frame(descriptor, HELLO_OPCODE, RESPONSE_FLAG,
            request_id, payload, 24u)
        || !exchange_hook_events(descriptor, &server->elapsed_ns);
    close(descriptor);
    return NULL;
}

static int connect_raw(const char *socket_path)
{
    struct sockaddr_un address;
    uint8_t payload[24] = { 0 };
    uint16_t opcode;
    uint16_t flags;
    uint64_t request_id;
    uint32_t payload_size;
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);

    if (descriptor < 0 || strlen(socket_path) >= sizeof(address.sun_path)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return -1;
    }
    write_u16(payload, KSI_ROLE_CALLBACK_STREAM);
    write_u32(payload + 4u, KSI_SCOPE_INPUT_MONITORING);
    if (!send_frame(descriptor, HELLO_OPCODE, 0u, 1u, payload, 16u)
        || !receive_frame(descriptor, &opcode, &flags, &request_id,
            payload, sizeof(payload), &payload_size)
        || opcode != HELLO_OPCODE || flags != RESPONSE_FLAG
        || request_id != 1u || payload_size != 24u
        || read_u32(payload) != KSI_STATUS_OK) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static bool run_raw_client(const char *socket_path)
{
    uint8_t event[64];
    uint8_t reply[16] = { 0 };
    uint32_t total = WARMUP_ITERATIONS + MEASURED_ITERATIONS;
    int descriptor = connect_raw(socket_path);

    if (descriptor < 0) return false;
    for (uint32_t index = 0u; index < total; index++) {
        uint16_t opcode;
        uint16_t flags;
        uint64_t request_id;
        uint32_t payload_size;

        if (!receive_frame(descriptor, &opcode, &flags, &request_id,
                event, sizeof(event), &payload_size)
            || opcode != HOOK_EVENT_OPCODE || flags != 0u
            || request_id != (uint64_t)index + 1u || payload_size != 48u
            || !send_frame(descriptor, HOOK_EVENT_OPCODE, RESPONSE_FLAG,
                request_id, reply, sizeof(reply))) {
            close(descriptor);
            return false;
        }
    }
    close(descriptor);
    return true;
}

static bool run_wrapper_client(const char *socket_path)
{
    ksi_connect_options options;
    ksi_service_info service_info;
    ksi_error error;
    ksi_connection *connection = NULL;
    uint32_t total = WARMUP_ITERATIONS + MEASURED_ITERATIONS;
    bool success = false;

    ksi_connect_options_init(&options);
    options.socket_path = socket_path;
    options.role = KSI_ROLE_CALLBACK_STREAM;
    options.requested_scopes = KSI_SCOPE_INPUT_MONITORING;
    ksi_service_info_init(&service_info);
    ksi_error_init(&error);
    if (ksi_connect(&options, &connection, &service_info, &error)
            != KSI_STATUS_OK) {
        return false;
    }
    for (uint32_t index = 0u; index < total; index++) {
        ksi_hook_message message;
        ksi_hook_reply reply;

        ksi_hook_message_init(&message);
        if (ksi_hook_next(connection, KSI_DEFAULT_REQUEST_TIMEOUT_MS,
                &message, &error) != KSI_STATUS_OK
            || message.kind != KSI_HOOK_MESSAGE_EVENT
            || message.data.event.request_id != (uint64_t)index + 1u) {
            goto done;
        }
        ksi_hook_reply_init(&reply);
        if (ksi_hook_reply_event(connection, &message.data.event,
                &reply, &error) != KSI_STATUS_OK) {
            goto done;
        }
    }
    success = true;
done:
    ksi_disconnect(connection);
    return success;
}

static bool run_trial(const char *socket_path, bool wrapper, uint64_t *elapsed)
{
    struct sockaddr_un address;
    benchmark_server server = { .listener = -1 };
    pthread_t thread;
    bool client_ok;

    server.listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server.listener < 0 || strlen(socket_path) >= sizeof(address.sun_path)) {
        return false;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
    unlink(socket_path);
    if (bind(server.listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server.listener, 1) != 0
        || pthread_create(&thread, NULL, server_main, &server) != 0) {
        close(server.listener);
        unlink(socket_path);
        return false;
    }
    client_ok = wrapper
        ? run_wrapper_client(socket_path)
        : run_raw_client(socket_path);
    pthread_join(thread, NULL);
    close(server.listener);
    unlink(socket_path);
    *elapsed = server.elapsed_ns;
    return client_ok && !server.failed;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

int main(void)
{
    char directory[] = "/tmp/keysharp-input-benchmark-XXXXXX";
    char socket_path[108];
    uint64_t wrapper[TRIAL_COUNT];
    uint64_t raw[TRIAL_COUNT];
    uint64_t wrapper_ns;
    uint64_t raw_ns;
    double overhead_percent;

    if (mkdtemp(directory) == NULL
        || snprintf(socket_path, sizeof(socket_path), "%s/socket", directory)
            < 0) {
        return 1;
    }
    for (uint32_t trial = 0u; trial < TRIAL_COUNT; trial++) {
        bool wrapper_first = (trial & 1u) == 0u;

        if (!(wrapper_first
                ? run_trial(socket_path, true, &wrapper[trial])
                    && run_trial(socket_path, false, &raw[trial])
                : run_trial(socket_path, false, &raw[trial])
                    && run_trial(socket_path, true, &wrapper[trial]))) {
            fprintf(stderr, "hook benchmark failed in trial %" PRIu32 "\n", trial);
            rmdir(directory);
            return 1;
        }
    }
    rmdir(directory);
    qsort(wrapper, TRIAL_COUNT, sizeof(wrapper[0]), compare_u64);
    qsort(raw, TRIAL_COUNT, sizeof(raw[0]), compare_u64);
    wrapper_ns = wrapper[TRIAL_COUNT / 2u] / MEASURED_ITERATIONS;
    raw_ns = raw[TRIAL_COUNT / 2u] / MEASURED_ITERATIONS;
    overhead_percent = raw_ns == 0u ? 0.0
        : 100.0 * ((double)wrapper_ns - (double)raw_ns) / (double)raw_ns;

    printf("iterations_per_trial=%u\n", MEASURED_ITERATIONS);
    printf("trials=%u\n", TRIAL_COUNT);
    printf("wrapper_ns_per_round_trip=%" PRIu64 "\n", wrapper_ns);
    printf("raw_ns_per_round_trip=%" PRIu64 "\n", raw_ns);
    printf("wrapper_overhead_ns=%" PRId64 "\n",
        (int64_t)wrapper_ns - (int64_t)raw_ns);
    printf("wrapper_overhead_percent=%.2f\n", overhead_percent);
    return 0;
}
