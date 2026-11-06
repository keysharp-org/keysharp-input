#include "keysharp_input/client.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define HEADER_SIZE 24u
#define RESPONSE 1u
#define HELLO 1u
#define PING 3u
#define TERMINAL_INPUT 0x1013u

_Static_assert(sizeof(ksi_terminal_input_options) == 48u, "terminal options ABI size changed");
_Static_assert(sizeof(ksi_terminal_input_result) == 40u, "terminal result ABI size changed");

typedef enum test_mode {
    RESULTS, RAW_BYTES, LOCAL_VALIDATION, OLD_SERVICE, DISCONNECTED, TIMED_OUT, WRITE_FAILED,
    BAD_COUNT, BAD_STATUS, BAD_DETAIL, BAD_ERRNO, SHORT_SUCCESS, MODE_COUNT
} test_mode;

typedef struct server_state {
    int listener;
    test_mode mode;
    int failed;
    unsigned int requests;
} server_state;

static const uint8_t text_bytes[] = { 'A', 0, 0xc3, 0xa9, '\b', '\r' };
static const uint8_t raw_bytes[] = { 0xff, 0x00, 0x1b, '[', 'A' };

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u)
        | ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static uint64_t read_u64(const uint8_t *p)
{
    return (uint64_t)read_u32(p) | ((uint64_t)read_u32(p + 4u) << 32u);
}

static void write_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8u);
}

static void write_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8u);
    p[2] = (uint8_t)(value >> 16u); p[3] = (uint8_t)(value >> 24u);
}

static void write_u64(uint8_t *p, uint64_t value)
{
    write_u32(p, (uint32_t)value); write_u32(p + 4u, (uint32_t)(value >> 32u));
}

static bool transfer(int fd, void *buffer, size_t size, bool writing)
{
    size_t offset = 0u;
    while (offset < size) {
        struct pollfd wait = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
        if (poll(&wait, 1u, 2000) <= 0) return false;
        ssize_t count = writing
            ? send(fd, (const uint8_t *)buffer + offset, size - offset, MSG_NOSIGNAL)
            : read(fd, (uint8_t *)buffer + offset, size - offset);
        if (count > 0) { offset += (size_t)count; continue; }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

static bool receive_frame(int fd, uint16_t expected_opcode, uint64_t *id,
    uint8_t *payload, size_t capacity, size_t *size)
{
    uint8_t header[HEADER_SIZE];
    if (!transfer(fd, header, sizeof(header), false)
        || memcmp(header, "KSIP", 4u) != 0 || read_u16(header + 4u) != 3u
        || read_u16(header + 8u) != expected_opcode || read_u16(header + 10u) != 0u)
        return false;
    *id = read_u64(header + 16u); *size = read_u32(header + 12u);
    return *id != 0u && *size <= capacity && transfer(fd, payload, *size, false);
}

static bool send_frame(int fd, uint16_t opcode, uint64_t id,
    const uint8_t *payload, size_t size)
{
    uint8_t header[HEADER_SIZE] = { 'K', 'S', 'I', 'P' };
    write_u16(header + 4u, 3u); write_u16(header + 8u, opcode);
    write_u16(header + 10u, RESPONSE); write_u32(header + 12u, (uint32_t)size);
    write_u64(header + 16u, id);
    return transfer(fd, header, sizeof(header), true)
        && transfer(fd, (void *)payload, size, true);
}

static bool expect_closed(int fd)
{
    struct pollfd wait = { .fd = fd, .events = POLLIN };
    uint8_t byte;
    return poll(&wait, 1u, 2000) == 1 && read(fd, &byte, 1u) == 0;
}

static bool reply_ping(int fd)
{
    uint8_t payload[16] = { 0 };
    uint64_t id;
    size_t size;
    return receive_frame(fd, PING, &id, payload, sizeof(payload), &size)
        && size == 0u && send_frame(fd, PING, id, payload, 8u);
}

static void *server_main(void *context)
{
    server_state *state = context;
    struct pollfd wait = { .fd = state->listener, .events = POLLIN };
    uint8_t payload[2048];
    uint64_t id;
    size_t size;
    int fd = -1;
    if (poll(&wait, 1u, 2000) != 1 || (fd = accept(state->listener, NULL, NULL)) < 0)
        goto failed;
    if (!receive_frame(fd, HELLO, &id, payload, sizeof(payload), &size)
        || size != 16u || read_u16(payload) != KSI_ROLE_RPC
        || read_u16(payload + 2u) != KSI_AUTH_CHECK
        || read_u32(payload + 4u) != KSI_SCOPE_INPUT_CONTROL) goto failed;
    memset(payload, 0, 32u);
    write_u32(payload + 8u, KSI_SCOPE_INPUT_CONTROL);
    write_u64(payload + 16u, state->mode == OLD_SERVICE ? 0u : KSI_OPERATION_TERMINAL_INPUT);
    if (!send_frame(fd, HELLO, id, payload, 32u)) goto failed;

    if (state->mode == WRITE_FAILED) {
        if (shutdown(fd, SHUT_RDWR) != 0) goto failed;
        goto done;
    }
    if (state->mode == LOCAL_VALIDATION || state->mode == OLD_SERVICE) {
        if (!reply_ping(fd) || !expect_closed(fd)) goto failed;
        goto done;
    }

    unsigned int calls = state->mode == RESULTS ? 3u : 1u;
    const uint8_t *expected_bytes = state->mode == RAW_BYTES ? raw_bytes : text_bytes;
    uint32_t expected_count = state->mode == RAW_BYTES ? sizeof(raw_bytes) : sizeof(text_bytes);
    uint32_t expected_flags = state->mode == RAW_BYTES ? 0u
        : KSI_TERMINAL_INPUT_REQUIRE_UTF8 | KSI_TERMINAL_INPUT_TEXT;
    for (unsigned int i = 0u; i < calls; i++) {
        if (!receive_frame(fd, TERMINAL_INPUT, &id, payload, sizeof(payload), &size)
            || size != 16u + expected_count
            || read_u32(payload) != KSI_TERMINAL_TARGET_LINUX_VT
            || read_u32(payload + 4u) != 3u
            || read_u32(payload + 8u) != expected_flags
            || read_u32(payload + 12u) != expected_count
            || memcmp(payload + 16u, expected_bytes, expected_count) != 0) goto failed;
        state->requests++;
        if (state->mode == DISCONNECTED) goto done;
        if (state->mode == TIMED_OUT) {
            if (!expect_closed(fd)) goto failed;
            goto done;
        }

        memset(payload, 0, 16u);
        write_u32(payload + 8u, expected_count);
        size = 16u;
        if (state->mode == RESULTS && i == 1u) {
            write_u32(payload, KSI_STATUS_REVOKED);
            write_u32(payload + 8u, 2u);
            write_u32(payload + 12u, ECANCELED);
        } else if (state->mode == RESULTS && i == 2u) {
            write_u32(payload, KSI_STATUS_DENIED);
            size = 8u;
        } else if (state->mode == BAD_COUNT) write_u32(payload + 8u, sizeof(text_bytes) + 1u);
        else if (state->mode == BAD_STATUS) write_u32(payload, 42u);
        else if (state->mode == BAD_DETAIL) write_u32(payload + 4u, 1u);
        else if (state->mode == BAD_ERRNO) write_u32(payload + 12u, EIO);
        else if (state->mode == SHORT_SUCCESS) size = 8u;
        if (!send_frame(fd, TERMINAL_INPUT, id, payload, size)) goto failed;
    }
    if ((state->mode == RESULTS || state->mode == RAW_BYTES) && !reply_ping(fd)) goto failed;
    if (!expect_closed(fd)) goto failed;
    goto done;
failed:
    state->failed = 1;
done:
    if (fd >= 0) close(fd);
    return NULL;
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return false; \
    } \
} while (0)

static bool local_validation(ksi_connection *connection, ksi_terminal_input_options *options,
    ksi_terminal_input_result *result, ksi_error *error)
{
    ksi_terminal_input_options valid = *options;
    static const uint8_t invalid_utf8[][4] = {
        { 0xc0, 0x80, 0, 0 }, { 0xed, 0xa0, 0x80, 0 }, { 0xf4, 0x90, 0x80, 0x80 },
        { 0x80, 0, 0, 0 }, { 0xf0, 0x9f, 0, 0 }
    };
    for (unsigned int i = 0u; i < 8u; i++) {
        *options = valid;
        switch (i) {
            case 0u: options->target_id = 0u; break;
            case 1u: options->target_id = 64u; break;
            case 2u: options->target_kind = 2u; break;
            case 3u: options->flags = 4u; break;
            case 4u: options->reserved[0] = 1u; break;
            case 5u: options->struct_size = sizeof(*options) - 1u; break;
            case 6u: result->struct_size = sizeof(*result) - 1u; break;
            default: break;
        }
        CHECK(ksi_terminal_input(connection, i == 7u ? NULL : options,
            text_bytes, sizeof(text_bytes), result, error) == KSI_STATUS_INVALID_REQUEST);
        ksi_terminal_input_result_init(result);
    }
    *options = valid;
    CHECK(ksi_terminal_input(connection, options, NULL, 1u, result, error) == KSI_STATUS_INVALID_REQUEST);
    uint8_t oversized[KSI_MAX_TERMINAL_INPUT_BYTES + 1u] = { 0 };
    CHECK(ksi_terminal_input(connection, options, oversized, sizeof(oversized), result, error)
        == KSI_STATUS_INVALID_REQUEST);
    for (size_t i = 0u; i < sizeof(invalid_utf8) / sizeof(invalid_utf8[0]); i++)
        CHECK(ksi_terminal_input(connection, options, invalid_utf8[i], sizeof(invalid_utf8[i]), result, error)
            == KSI_STATUS_INVALID_REQUEST);
    CHECK(ksi_ping(connection, error) == KSI_STATUS_OK);
    return true;
}

static bool exercise_client(test_mode mode, ksi_connection *connection)
{
    ksi_terminal_input_options options;
    ksi_terminal_input_result result;
    ksi_error error;
    memset(&options, 0xff, sizeof(options));
    memset(&result, 0xff, sizeof(result));
    ksi_terminal_input_options_init(&options);
    ksi_terminal_input_result_init(&result);
    ksi_error_init(&error);
    CHECK(options.struct_size == sizeof(options) && result.struct_size == sizeof(result));
    CHECK(options.target_kind == KSI_TERMINAL_TARGET_LINUX_VT && options.flags == 0u
        && options.target_id == 0u && result.bytes_accepted == 0u);
    for (size_t i = 0u; i < 4u; i++) CHECK(options.reserved[i] == 0u && result.reserved[i] == 0u);
    options.target_id = 3u;
    options.flags = KSI_TERMINAL_INPUT_REQUIRE_UTF8 | KSI_TERMINAL_INPUT_TEXT;
    if (mode == WRITE_FAILED) {
        struct pollfd wait = { .fd = ksi_connection_fd(connection), .events = POLLIN };
        CHECK(poll(&wait, 1u, 2000) == 1);
        CHECK(ksi_terminal_input(connection, &options, text_bytes, sizeof(text_bytes), &result, &error)
            == KSI_STATUS_UNAVAILABLE);
        CHECK(error.system_error == EPIPE && error.detail == 0u);
        CHECK(strstr(error.message, "unknown") != NULL && strstr(error.message, "retry") != NULL);
        CHECK(strstr(error.message, strerror(EPIPE)) != NULL);
        CHECK(result.bytes_accepted == 0u);
        return true;
    }
    if (mode == LOCAL_VALIDATION) return local_validation(connection, &options, &result, &error);
    if (mode == RAW_BYTES) {
        options.flags = 0u;
        CHECK(ksi_terminal_input(connection, &options, raw_bytes, sizeof(raw_bytes), &result, &error)
            == KSI_STATUS_OK);
        CHECK(result.bytes_accepted == sizeof(raw_bytes));
        CHECK(ksi_ping(connection, &error) == KSI_STATUS_OK);
        return true;
    }

    ksi_status status = ksi_terminal_input(connection, &options, text_bytes, sizeof(text_bytes), &result, &error);
    if (mode == RESULTS) {
        CHECK(status == KSI_STATUS_OK && result.bytes_accepted == sizeof(text_bytes));
        CHECK(error.system_error == 0 && error.message[0] == '\0');
        CHECK(ksi_terminal_input(connection, &options, text_bytes, sizeof(text_bytes), &result, &error)
            == KSI_STATUS_REVOKED);
        CHECK(result.bytes_accepted == 2u && error.system_error == ECANCELED);
        CHECK(strstr(error.message, "2 of 6") != NULL);
        CHECK(ksi_terminal_input(connection, &options, text_bytes, sizeof(text_bytes), &result, &error)
            == KSI_STATUS_DENIED);
        CHECK(result.bytes_accepted == 0u);
        CHECK(ksi_ping(connection, &error) == KSI_STATUS_OK);
    } else if (mode == OLD_SERVICE) {
        CHECK(status == KSI_STATUS_UNSUPPORTED && result.bytes_accepted == 0u);
        CHECK(ksi_ping(connection, &error) == KSI_STATUS_OK);
    } else if (mode == DISCONNECTED || mode == TIMED_OUT) {
        CHECK(status == (mode == TIMED_OUT ? KSI_STATUS_TIMEOUT : KSI_STATUS_UNAVAILABLE));
        CHECK(result.bytes_accepted == 0u);
        CHECK(strstr(error.message, "unknown") != NULL && strstr(error.message, "retry") != NULL);
        CHECK(ksi_ping(connection, &error) == KSI_STATUS_UNAVAILABLE);
    } else {
        CHECK(status == KSI_STATUS_INTERNAL && result.bytes_accepted == 0u);
        CHECK(ksi_ping(connection, &error) == KSI_STATUS_UNAVAILABLE);
    }
    return true;
}

static bool run_test(test_mode mode)
{
    char directory[] = "/tmp/keysharp-input-terminal-XXXXXX";
    char path[108] = { 0 };
    server_state server = { .listener = -1, .mode = mode };
    pthread_t thread;
    bool started = false, passed = false;
    ksi_connection *connection = NULL;
    if (mkdtemp(directory) == NULL) return false;
    (void)snprintf(path, sizeof(path), "%s/socket", directory);
    server.listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server.listener < 0) goto done;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, path, strlen(path) + 1u);
    if (bind(server.listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server.listener, 1) != 0
        || pthread_create(&thread, NULL, server_main, &server) != 0) goto done;
    started = true;
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connect_options_init(&options); ksi_service_info_init(&info); ksi_error_init(&error);
    options.socket_path = path;
    options.role = KSI_ROLE_RPC;
    options.authorization_mode = KSI_AUTH_CHECK;
    options.requested_scopes = KSI_SCOPE_INPUT_CONTROL;
    options.timeout_ms = mode == TIMED_OUT ? 200u : 1500u;
    if (ksi_connect(&options, &connection, &info, &error) != KSI_STATUS_OK) goto done;
    passed = exercise_client(mode, connection);
done:
    ksi_disconnect(connection);
    if (started) pthread_join(thread, NULL);
    if (server.failed) passed = false;
    if (passed) {
        unsigned int expected = mode == LOCAL_VALIDATION || mode == OLD_SERVICE || mode == WRITE_FAILED ? 0u
            : mode == RESULTS ? 3u : 1u;
        struct pollfd wait = { .fd = server.listener, .events = POLLIN };
        passed = server.requests == expected && poll(&wait, 1u, 0) == 0;
    }
    if (server.listener >= 0) close(server.listener);
    unlink(path); rmdir(directory);
    if (!passed) fprintf(stderr, "terminal client scenario %d failed\n", (int)mode);
    return passed;
}

int main(void)
{
    for (test_mode mode = RESULTS; mode < MODE_COUNT; mode++)
        if (!run_test(mode)) return 1;
    return 0;
}
