#include "keysharp_inputd/auth.h"

#include "keysharp_inputd/protocol.h"
#include "shared_permissions.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef KSI_PKCHECK_PATH
#define KSI_PKCHECK_PATH "/usr/bin/pkcheck"
#endif

#define KSI_AUTH_ACTION_ID "org.keysharp.input.grant"
#define KSI_PKCHECK_TIMEOUT_SECONDS 120u

struct ksi_auth_store {
    char *shared_directory;
    char *runtime_directory;
};

typedef struct ksi_sha256_ctx {
    int alg_fd;
    int op_fd;
} ksi_sha256_ctx;

static atomic_int g_auth_cancelled = 0;

static bool valid_hash(const char *text);

static bool root_owned_and_protected(const struct stat *info)
{
    return info->st_uid == 0 && (info->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

bool ksi_auth_is_protected_executable(int exe_fd, const char *absolute_path)
{
    struct stat exe_info;
    struct stat info;
    char *copy;
    char *separator;
    bool protected = false;

    if (absolute_path == NULL || absolute_path[0] != '/'
        || fstat(exe_fd, &exe_info) != 0
        || !S_ISREG(exe_info.st_mode)
        || !root_owned_and_protected(&exe_info)
        || lstat("/", &info) != 0
        || !S_ISDIR(info.st_mode)
        || !root_owned_and_protected(&info)) {
        return false;
    }

    copy = strdup(absolute_path);

    if (copy == NULL) {
        return false;
    }

    separator = strrchr(copy, '/');

    if (separator == NULL) {
        goto cleanup;
    }

    *separator = '\0';

    for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }

        *cursor = '\0';

        if (lstat(copy, &info) != 0 || !S_ISDIR(info.st_mode)
            || !root_owned_and_protected(&info)) {
            goto cleanup;
        }

        *cursor = '/';
    }

    if (copy[0] != '\0'
        && (lstat(copy, &info) != 0 || !S_ISDIR(info.st_mode)
            || !root_owned_and_protected(&info))) {
        goto cleanup;
    }

    if (stat(absolute_path, &info) != 0
        || info.st_dev != exe_info.st_dev
        || info.st_ino != exe_info.st_ino) {
        goto cleanup;
    }

    protected = true;

cleanup:
    free(copy);
    return protected;
}

static int sha256_init(ksi_sha256_ctx *ctx)
{
    static const struct sockaddr_alg address = {
        .salg_family = AF_ALG,
        .salg_type = "hash",
        .salg_name = "sha256",
    };

    ctx->alg_fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    ctx->op_fd = -1;

    if (ctx->alg_fd < 0
        || bind(ctx->alg_fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        if (ctx->alg_fd >= 0) {
            close(ctx->alg_fd);
        }

        ctx->alg_fd = -1;
        return -1;
    }

    ctx->op_fd = accept4(ctx->alg_fd, NULL, NULL, SOCK_CLOEXEC);

    if (ctx->op_fd < 0) {
        close(ctx->alg_fd);
        ctx->alg_fd = -1;
        return -1;
    }

    return 0;
}

static int sha256_update(ksi_sha256_ctx *ctx, const void *data, size_t length)
{
    const uint8_t *cursor = data;

    while (length > 0u) {
        ssize_t written = send(ctx->op_fd, cursor, length, MSG_MORE);

        if (written > 0) {
            cursor += (size_t)written;
            length -= (size_t)written;
            continue;
        }

        if (written < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

static int sha256_finish(
    ksi_sha256_ctx *ctx,
    char output[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    size_t used = 0u;

    while (used < sizeof(digest)) {
        ssize_t count = read(ctx->op_fd, digest + used, sizeof(digest) - used);

        if (count > 0) {
            used += (size_t)count;
            continue;
        }

        if (count < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }

    for (size_t i = 0u; i < sizeof(digest); i++) {
        output[i * 2u] = hex[digest[i] >> 4u];
        output[(i * 2u) + 1u] = hex[digest[i] & 0x0fu];
    }

    output[KSI_AUTH_HASH_HEX_LENGTH] = '\0';
    return 0;
}

static void sha256_cleanup(ksi_sha256_ctx *ctx)
{
    if (ctx->op_fd >= 0) {
        close(ctx->op_fd);
        ctx->op_fd = -1;
    }

    if (ctx->alg_fd >= 0) {
        close(ctx->alg_fd);
        ctx->alg_fd = -1;
    }
}

static int hash_file(int fd, char output[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    uint8_t buffer[8192];
    ksi_sha256_ctx ctx;
    ssize_t count;
    int result = -1;

    if (lseek(fd, 0, SEEK_SET) < 0 || sha256_init(&ctx) != 0) {
        return -1;
    }

    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        if (sha256_update(&ctx, buffer, (size_t)count) != 0) {
            goto cleanup;
        }
    }

    if (count == 0) {
        result = sha256_finish(&ctx, output);
    }

cleanup:
    sha256_cleanup(&ctx);
    return result;
}

static int hash_app_identity(
    const char *kind,
    const void *identity,
    size_t identity_length,
    char output[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    static const uint8_t separator = 0u;
    ksi_sha256_ctx ctx;
    int result = -1;

    if (sha256_init(&ctx) != 0) {
        return -1;
    }

    if (sha256_update(&ctx, KSI_AUTH_IDENTITY_DOMAIN,
            strlen(KSI_AUTH_IDENTITY_DOMAIN)) == 0
        && sha256_update(&ctx, &separator, sizeof(separator)) == 0
        && sha256_update(&ctx, kind, strlen(kind)) == 0
        && sha256_update(&ctx, &separator, sizeof(separator)) == 0
        && sha256_update(&ctx, identity, identity_length) == 0) {
        result = sha256_finish(&ctx, output);
    }

    sha256_cleanup(&ctx);
    return result;
}

int ksi_auth_hash_path_identity(
    const char *absolute_path,
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    if (absolute_path == NULL || absolute_path[0] != '/' || app_hash == NULL) {
        return -1;
    }

    return hash_app_identity(KSI_AUTH_IDENTITY_KIND_PATH,
        absolute_path, strlen(absolute_path), app_hash);
}

int ksi_auth_hash_content_identity(
    const char executable_sha256[KSI_AUTH_HASH_HEX_LENGTH + 1u],
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    if (!valid_hash(executable_sha256) || app_hash == NULL) {
        return -1;
    }

    return hash_app_identity(KSI_AUTH_IDENTITY_KIND_SHA256,
        executable_sha256, KSI_AUTH_HASH_HEX_LENGTH, app_hash);
}

int ksi_auth_identify_process(
    pid_t pid,
    char *path_buffer,
    size_t path_buffer_size,
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u])
{
    char proc_path[64];
    char file_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    ssize_t path_length;
    int fd;
    int result;

    if (pid <= 0 || path_buffer == NULL || path_buffer_size < 2u
        || app_hash == NULL) {
        return -1;
    }

    path_buffer[0] = '\0';
    app_hash[0] = '\0';
    (void)snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe", (long)pid);
    fd = open(proc_path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        if (fd >= 0) {
            close(fd);
        }

        return -1;
    }

    path_length = readlink(proc_path, path_buffer, path_buffer_size - 1u);

    if (path_length < 0 || (size_t)path_length >= path_buffer_size - 1u) {
        close(fd);
        return -1;
    }

    path_buffer[path_length] = '\0';
    if (ksi_auth_is_protected_executable(fd, path_buffer)) {
        result = ksi_auth_hash_path_identity(path_buffer, app_hash);
    } else if (hash_file(fd, file_hash) == 0) {
        result = ksi_auth_hash_content_identity(file_hash, app_hash);
    } else {
        result = -1;
    }

    close(fd);
    return result;
}

uint64_t ksi_auth_get_process_start_time(pid_t pid)
{
    char path[64];
    char buffer[1024];
    char *cursor;
    char *end;
    unsigned long long value;
    int fd;
    ssize_t count;

    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        return 0u;
    }

    count = read(fd, buffer, sizeof(buffer) - 1u);
    close(fd);

    if (count <= 0) {
        return 0u;
    }

    buffer[count] = '\0';
    cursor = strrchr(buffer, ')');

    if (cursor == NULL || cursor[1] != ' ') {
        return 0u;
    }

    cursor += 2;

    for (int field = 3; field < 22; field++) {
        cursor = strchr(cursor, ' ');

        if (cursor == NULL) {
            return 0u;
        }

        cursor++;
    }

    errno = 0;
    value = strtoull(cursor, &end, 10);
    return errno == 0 && end != cursor ? (uint64_t)value : 0u;
}

static bool valid_hash(const char *text)
{
    if (text == NULL || strlen(text) != KSI_AUTH_HASH_HEX_LENGTH) {
        return false;
    }

    for (size_t i = 0u; i < KSI_AUTH_HASH_HEX_LENGTH; i++) {
        if (!isxdigit((unsigned char)text[i])) {
            return false;
        }
    }

    return true;
}


static int create_store_with_paths(
    ksi_auth_store **out_store,
    const char *shared_directory,
    const char *runtime_directory)
{
    ksi_auth_store *store;

    if (out_store == NULL
        || shared_directory == NULL || shared_directory[0] != '/'
        || runtime_directory == NULL || runtime_directory[0] != '/') {
        return -1;
    }

    *out_store = NULL;

    store = calloc(1, sizeof(*store));

    if (store == NULL) {
        return -1;
    }

    store->shared_directory = strdup(shared_directory);
    store->runtime_directory = strdup(runtime_directory);

    if (store->shared_directory == NULL
        || store->runtime_directory == NULL
        || ksi_shared_permissions_prepare(store->shared_directory) != 0
        || ksi_shared_permissions_prepare_runtime(store->runtime_directory) != 0) {
        ksi_auth_store_destroy(store);
        return -1;
    }

    *out_store = store;
    return 0;
}

int ksi_auth_store_create_at(ksi_auth_store **out_store, const char *path)
{
    char shared[KSI_AUTH_MAX_PATH];
    char runtime[KSI_AUTH_MAX_PATH];

    if (path == NULL
        || snprintf(shared, sizeof(shared), "%s.shared-v1", path) <= 0
        || snprintf(runtime, sizeof(runtime), "%s.runtime", path) <= 0) {
        return -1;
    }

    return create_store_with_paths(out_store, shared, runtime);
}

int ksi_auth_store_create(ksi_auth_store **store)
{
    return create_store_with_paths(store,
        KSP_GRANT_DIRECTORY, KSP_RUNTIME_DIRECTORY);
}

void ksi_auth_store_destroy(ksi_auth_store *store)
{
    if (store == NULL) {
        return;
    }

    free(store->shared_directory);
    free(store->runtime_directory);
    free(store);
}

const char *ksi_auth_store_runtime_directory(const ksi_auth_store *store)
{
    return store == NULL ? NULL : store->runtime_directory;
}

int ksi_auth_prompt_lock_acquire(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash)
{
    char path[KSI_AUTH_MAX_PATH];
    struct stat info;
    struct timespec retry = { .tv_sec = 0, .tv_nsec = 100000000L };
    int length;
    int descriptor;

    if (store == NULL || atomic_load(&g_auth_cancelled) != 0
        || !valid_hash(app_hash)
        || ksi_shared_permissions_prepare_runtime(store->runtime_directory) != 0)
        return -1;
    length = snprintf(path, sizeof(path), "%s/.prompt-%lu-%s.lock",
        store->runtime_directory, (unsigned long)uid, app_hash);
    if (length <= 0 || (size_t)length >= sizeof(path))
        return -1;
    descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || fchmod(descriptor, 0600) != 0
        || fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != geteuid()
        || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }

    while (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            close(descriptor);
            return -1;
        }
        if (atomic_load(&g_auth_cancelled) != 0) {
            close(descriptor);
            errno = ECANCELED;
            return -1;
        }
        while (nanosleep(&retry, &retry) != 0 && errno == EINTR) {
        }
        retry.tv_sec = 0;
        retry.tv_nsec = 100000000L;
    }

    if (atomic_load(&g_auth_cancelled) != 0) {
        close(descriptor);
        errno = ECANCELED;
        return -1;
    }

    return descriptor;
}

uint32_t ksi_auth_store_get_allowed(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash)
{
    uint32_t allowed = 0u;

    if (store == NULL || app_hash == NULL) {
        return 0u;
    }

    return ksi_shared_permissions_get(store->shared_directory, uid, app_hash,
        KSP_INPUT_SCOPES, &allowed) == 0 ? allowed : 0u;
}

int ksi_auth_store_get_allowed_at_generation(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    uint32_t *allowed,
    uint64_t *generation)
{
    if (store == NULL || allowed == NULL || generation == NULL
        || !valid_hash(app_hash)) {
        return -1;
    }

    return ksi_shared_permissions_get_at_generation(
        store->shared_directory, store->runtime_directory, uid, app_hash,
        KSP_INPUT_SCOPES, allowed, generation);
}

int ksi_auth_store_grant(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    const char *exe_path,
    uint32_t scopes)
{
    scopes &= KSP_INPUT_SCOPES;

    if (store == NULL || !valid_hash(app_hash) || scopes == 0u) {
        return -1;
    }

    return ksi_shared_permissions_grant(store->shared_directory, uid,
        app_hash, exe_path, scopes);
}

int ksi_auth_store_grant_if_generation(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    const char *exe_path,
    uint32_t scopes,
    uint64_t expected_generation)
{
    scopes &= KSP_INPUT_SCOPES;

    if (store == NULL || !valid_hash(app_hash) || scopes == 0u) {
        return -1;
    }

    return ksi_shared_permissions_grant_if_generation(
        store->shared_directory, store->runtime_directory, uid, app_hash,
        exe_path, scopes, expected_generation);
}

int ksi_auth_store_revoke(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    uint32_t scopes)
{
    scopes &= KSP_INPUT_SCOPES;

    if (store == NULL || !valid_hash(app_hash) || scopes == 0u) {
        return -1;
    }

    return ksi_shared_permissions_revoke(store->shared_directory,
        store->runtime_directory, uid, app_hash,
        scopes);
}

int ksi_auth_store_get_generation(
    const ksi_auth_store *store,
    uid_t uid,
    uint64_t *generation)
{
    if (store == NULL) {
        return -1;
    }

    return ksi_shared_permissions_generation_read(
        store->runtime_directory, uid, generation);
}

typedef struct shared_visit_context {
    ksi_auth_visit_fn visit;
    void *user_data;
} shared_visit_context;

static bool visit_shared_permission(
    const ksi_shared_permission_entry *shared,
    void *user_data)
{
    shared_visit_context *context = user_data;
    ksi_auth_entry entry;

    memset(&entry, 0, sizeof(entry));
    entry.uid = shared->uid;
    (void)snprintf(entry.app_hash, sizeof(entry.app_hash), "%s",
        shared->app_hash);
    entry.exe_path = shared->executable;
    entry.allowed_scopes =
        shared->scopes & KSP_INPUT_SCOPES;
    entry.granted_at_utc = shared->granted_at_utc;
    return context->visit(&entry, context->user_data);
}

void ksi_auth_store_for_each(
    const ksi_auth_store *store,
    uid_t uid_filter,
    ksi_auth_visit_fn visit,
    void *user_data)
{
    shared_visit_context context = {
        .visit = visit,
        .user_data = user_data,
    };

    if (store == NULL || visit == NULL) {
        return;
    }

    ksi_shared_permissions_for_each(store->shared_directory, uid_filter,
        KSP_INPUT_SCOPES, visit_shared_permission, &context);
}

ksi_auth_result ksi_auth_request_polkit(
    pid_t pid,
    uid_t uid,
    uint64_t start_time,
    const char *exe_path,
    const char *app_hash,
    uint32_t scopes)
{
    char subject[128];
    char permission_text[48];
    char polkit_message[KSI_AUTH_MAX_PATH + 128u];
    char display_path[KSI_AUTH_MAX_PATH];
    char *const arguments[] = {
        (char *)KSI_PKCHECK_PATH,
        (char *)"--action-id", (char *)KSI_AUTH_ACTION_ID,
        (char *)"--process", subject,
        (char *)"--allow-user-interaction",
        (char *)"--detail", (char *)"app.path", display_path,
        (char *)"--detail", (char *)"input.permissions", permission_text,
        (char *)"--detail", (char *)"polkit.message", polkit_message,
        NULL,
    };
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    unsigned int elapsed = 0u;
    int status;
    pid_t child;

    if (pid <= 0 || start_time == 0u
        || ksi_auth_get_process_start_time(pid) != start_time) {
        return KSI_AUTH_DENIED;
    }

    ksi_auth_sanitize_display_text(exe_path, display_path,
                                   sizeof(display_path));

    scopes &= KSP_INPUT_SCOPES;

    if (scopes == KSP_SCOPE_INPUT_MONITORING) {
        (void)snprintf(permission_text, sizeof(permission_text),
            "input-monitoring");
    } else if (scopes == KSP_SCOPE_INPUT_CONTROL) {
        (void)snprintf(permission_text, sizeof(permission_text),
            "input-control");
    } else if (scopes == KSP_INPUT_SCOPES) {
        (void)snprintf(permission_text, sizeof(permission_text),
            "input-monitoring,input-control");
    } else {
        return KSI_AUTH_DENIED;
    }
    if (ksi_auth_format_polkit_message(exe_path, scopes,
            polkit_message, sizeof(polkit_message)) != 0) {
        return KSI_AUTH_UNAVAILABLE;
    }

    (void)snprintf(subject, sizeof(subject), "%ld,%llu,%lu",
        (long)pid, (unsigned long long)start_time, (unsigned long)uid);
    child = fork();

    if (child < 0) {
        return KSI_AUTH_UNAVAILABLE;
    }

    if (child == 0) {
        if (clearenv() != 0
            || setenv("PATH", "/usr/bin:/bin", 1) != 0
            || setenv("LANG", "C.UTF-8", 1) != 0) {
            _exit(127);
        }
        execv(KSI_PKCHECK_PATH, arguments);
        _exit(127);
    }

    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);

        if (waited == child) {
            break;
        }

        if (waited < 0 && errno != EINTR) {
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            return KSI_AUTH_UNAVAILABLE;
        }

        if (atomic_load(&g_auth_cancelled) != 0
            || elapsed >= KSI_PKCHECK_TIMEOUT_SECONDS * 10u) {
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            return KSI_AUTH_UNAVAILABLE;
        }

        (void)nanosleep(&delay, NULL);
        elapsed++;
    }

    if (!WIFEXITED(status)) {
        return KSI_AUTH_UNAVAILABLE;
    }

    ksi_auth_result authorization = ksi_auth_result_from_pkcheck_exit(WEXITSTATUS(status));

    if (authorization != KSI_AUTH_GRANTED) {
        return authorization;
    }

    if (ksi_auth_get_process_start_time(pid) != start_time || !valid_hash(app_hash)) {
        return KSI_AUTH_DENIED;
    }

    char verified_path[KSI_AUTH_MAX_PATH];
    char verified_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];

    if (ksi_auth_identify_process(pid,
            verified_path, sizeof(verified_path), verified_hash) != 0
        || strcmp(verified_hash, app_hash) != 0) {
        return KSI_AUTH_DENIED;
    }

    return KSI_AUTH_GRANTED;
}

void ksi_auth_sanitize_display_text(const char *source, char *destination,
                                    size_t capacity)
{
    size_t index = 0u;

    if (destination == NULL || capacity == 0u) {
        return;
    }
    if (source != NULL) {
        while (source[index] != '\0' && index + 1u < capacity) {
            unsigned char value = (unsigned char)source[index];
            destination[index] = value < 0x20u || value == 0x7fu
                ? '?'
                : (char)value;
            index++;
        }
    }
    destination[index] = '\0';
}

int ksi_auth_format_polkit_message(
    const char *exe_path,
    uint32_t permission_scopes,
    char *message,
    size_t capacity)
{
    char display_path[KSI_AUTH_MAX_PATH];
    const char *permissions;
    int written;

    if (message == NULL || capacity == 0u
        || (permission_scopes & (uint32_t)~KSP_INPUT_SCOPES) != 0u) {
        return -1;
    }
    if (permission_scopes == KSP_SCOPE_INPUT_MONITORING) {
        permissions = "Input Monitoring";
    } else if (permission_scopes == KSP_SCOPE_INPUT_CONTROL) {
        permissions = "Input Control";
    } else if (permission_scopes == KSP_INPUT_SCOPES) {
        permissions = "Input Monitoring and Input Control";
    } else {
        return -1;
    }

    ksi_auth_sanitize_display_text(exe_path, display_path,
        sizeof(display_path));
    written = snprintf(message, capacity,
        "Authentication is required to permanently grant %s to %s",
        permissions, display_path[0] != '\0' ? display_path : "this application");
    return written >= 0 && (size_t)written < capacity ? 0 : -1;
}

ksi_auth_result ksi_auth_result_from_pkcheck_exit(int exit_code)
{
    if (exit_code == 0) {
        return KSI_AUTH_GRANTED;
    }

    return exit_code == 1 || exit_code == 3
        ? KSI_AUTH_DENIED
        : KSI_AUTH_UNAVAILABLE;
}

void ksi_auth_cancel(void)
{
    atomic_store(&g_auth_cancelled, 1);
}
