#include "keysharp_inputd/auth.h"
#include "keysharp_inputd/protocol.h"
#include "shared_permissions.h"

#include <stdbool.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct visit_result {
    size_t count;
    uint32_t scopes;
    uint64_t granted_at;
    char path[KSI_AUTH_MAX_PATH];
} visit_result;

static bool collect_entry(const ksi_auth_entry *entry, void *user_data)
{
    visit_result *result = user_data;
    result->count++;
    result->scopes = entry->allowed_scopes;
    result->granted_at = entry->granted_at_utc;
    (void)snprintf(result->path, sizeof(result->path), "%s", entry->exe_path);
    return true;
}

static bool write_marker_text(const char *path, const char *contents)
{
    size_t length = strlen(contents);
    int descriptor = open(path,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    ssize_t written;

    if (descriptor < 0 || fchmod(descriptor, 0600) != 0) {
        if (descriptor >= 0)
            close(descriptor);
        return false;
    }
    written = write(descriptor, contents, length);
    return close(descriptor) == 0 && written == (ssize_t)length;
}


int main(void)
{
    char display_text[32];
    char polkit_message[256];
    static const char hash[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char directory[] = "/tmp/keysharp-input-auth-XXXXXX";
    char store_path[KSI_AUTH_MAX_PATH];
    char shared_directory[KSI_AUTH_MAX_PATH];
    char runtime_directory[KSI_AUTH_MAX_PATH];
    char cleanup_path[KSI_AUTH_MAX_PATH];
    char exe_path[KSI_AUTH_MAX_PATH];
    char first_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    char second_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    char vector_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    char marker_name[192];
    char parsed_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    char marker_text[KSI_AUTH_MAX_PATH + 256u];
    ksi_auth_store *store = NULL;
    visit_result visited = { 0 };
    uid_t uid = getuid();
    uid_t parsed_uid = (uid_t)-1;
    uint32_t parsed_scope = 0u;
    int prompt_lock;
    int protected_fd;

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/grants.tsv", directory)
        < (int)sizeof(store_path));
    CHECK(snprintf(shared_directory, sizeof(shared_directory), "%s.shared-v1",
        store_path) < (int)sizeof(shared_directory));
    CHECK(snprintf(runtime_directory, sizeof(runtime_directory), "%s.runtime",
        store_path) < (int)sizeof(runtime_directory));
    CHECK(KSI_INPUT_CAPABILITIES == 0x0000001Fu);
    CHECK(KSP_INPUT_SCOPES == 0x00000180u);
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-%lu-%s-%08x.grant", (unsigned long)uid, hash,
        KSP_SCOPE_INPUT_MONITORING) < (int)sizeof(marker_name));
    CHECK(ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(parsed_uid == uid);
    CHECK(strcmp(parsed_hash, hash) == 0);
    CHECK(parsed_scope == KSP_SCOPE_INPUT_MONITORING);
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-0%lu-%s-%08x.grant", (unsigned long)uid, hash,
        KSP_SCOPE_INPUT_MONITORING) < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-+%lu-%s-%08x.grant", (unsigned long)uid, hash,
        KSP_SCOPE_INPUT_MONITORING) < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-184467440737095516160-%s-%08x.grant", hash,
        KSP_SCOPE_INPUT_MONITORING) < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-%lu-%s-0000080.grant", (unsigned long)uid, hash)
        < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-%lu-%s-000000080.grant", (unsigned long)uid, hash)
        < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    CHECK(snprintf(marker_name, sizeof(marker_name),
        "grant-%lu-%s-+0000080.grant", (unsigned long)uid, hash)
        < (int)sizeof(marker_name));
    CHECK(!ksi_shared_permissions_parse_marker_name(marker_name, &parsed_uid,
        parsed_hash, &parsed_scope));
    ksi_auth_sanitize_display_text("/tmp/line\nname\177", display_text,
                                   sizeof(display_text));
    CHECK(strcmp(display_text, "/tmp/line?name?") == 0);
    CHECK(ksi_auth_format_polkit_message("/usr/bin/example-client",
        KSP_SCOPE_INPUT_MONITORING,
        polkit_message, sizeof(polkit_message)) == 0);
    CHECK(strcmp(polkit_message,
        "Authentication is required to permanently grant Input Monitoring to /usr/bin/example-client") == 0);
    CHECK(ksi_auth_format_polkit_message("/tmp/control\nclient",
        KSP_SCOPE_INPUT_CONTROL,
        polkit_message, sizeof(polkit_message)) == 0);
    CHECK(strcmp(polkit_message,
        "Authentication is required to permanently grant Input Control to /tmp/control?client") == 0);
    CHECK(ksi_auth_format_polkit_message("/usr/bin/example-client",
        KSP_INPUT_SCOPES,
        polkit_message, sizeof(polkit_message)) == 0);
    CHECK(strstr(polkit_message,
        "Input Monitoring and Input Control") != NULL);
    CHECK(ksi_auth_format_polkit_message("/usr/bin/example-client", 0u,
        polkit_message, sizeof(polkit_message)) != 0);
    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(ksi_auth_store_get_allowed(store, uid, hash) == 0u);
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
        "%s/grant-%lu-%s-%08x.grant", shared_directory,
        (unsigned long)uid, hash, KSP_SCOPE_INPUT_MONITORING)
        < (int)sizeof(cleanup_path));
    CHECK(snprintf(marker_text, sizeof(marker_text),
        "keysharp-permission-v1\n%lu\t%s\t%08x\t1\n",
        (unsigned long)uid, hash, KSP_SCOPE_INPUT_MONITORING)
        < (int)sizeof(marker_text));
    CHECK(write_marker_text(cleanup_path, marker_text));
    uint32_t malformed_allowed = 0u;
    CHECK(ksi_shared_permissions_get(shared_directory, uid, hash,
        KSP_SCOPE_INPUT_MONITORING, &malformed_allowed) != 0);
    CHECK(unlink(cleanup_path) == 0);
    CHECK(snprintf(marker_text, sizeof(marker_text),
        "keysharp-permission-v1\n%lu\t%s\t%08x\t1\t\n",
        (unsigned long)uid, hash, KSP_SCOPE_INPUT_MONITORING)
        < (int)sizeof(marker_text));
    CHECK(write_marker_text(cleanup_path, marker_text));
    CHECK(ksi_shared_permissions_get(shared_directory, uid, hash,
        KSP_SCOPE_INPUT_MONITORING, &malformed_allowed) != 0);
    CHECK(unlink(cleanup_path) == 0);
    CHECK(snprintf(marker_text, sizeof(marker_text),
        "keysharp-permission-v1\n%lu\t%s\t%08x\t1\t/usr/bin/example-client\nextra\n",
        (unsigned long)uid, hash, KSP_SCOPE_INPUT_MONITORING)
        < (int)sizeof(marker_text));
    CHECK(write_marker_text(cleanup_path, marker_text));
    CHECK(ksi_shared_permissions_get(shared_directory, uid, hash,
        KSP_SCOPE_INPUT_MONITORING, &malformed_allowed) != 0);
    CHECK(unlink(cleanup_path) == 0);
    CHECK(snprintf(marker_text, sizeof(marker_text),
        "keysharp-permission-v1\n%lu\t%s\t%08x\t1\t/usr/bin/example-client",
        (unsigned long)uid, hash, KSP_SCOPE_INPUT_MONITORING)
        < (int)sizeof(marker_text));
    CHECK(write_marker_text(cleanup_path, marker_text));
    CHECK(ksi_shared_permissions_get(shared_directory, uid, hash,
        KSP_SCOPE_INPUT_MONITORING, &malformed_allowed) != 0);
    CHECK(unlink(cleanup_path) == 0);
    CHECK(ksi_auth_store_grant(store, uid, hash, "/usr/bin/example-client",
        KSP_INPUT_SCOPES) == 0);
    CHECK(ksi_auth_store_get_allowed(store, uid, hash)
        == KSP_INPUT_SCOPES);
    uint32_t allowed_at_generation = 0u;
    uint64_t checked_generation = UINT64_MAX;
    CHECK(ksi_auth_store_get_allowed_at_generation(store, uid, hash,
        &allowed_at_generation, &checked_generation) == 0);
    CHECK(allowed_at_generation
        == KSP_INPUT_SCOPES);
    CHECK(checked_generation == 0u);

    prompt_lock = ksi_auth_prompt_lock_acquire(store, uid, hash);
    CHECK(prompt_lock >= 0);
    struct stat prompt_lock_info;
    CHECK(fstat(prompt_lock, &prompt_lock_info) == 0);
    CHECK(S_ISREG(prompt_lock_info.st_mode));
    CHECK(prompt_lock_info.st_uid == geteuid());
    CHECK((prompt_lock_info.st_mode & 0777) == 0600);
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
        "%s/.prompt-%lu-%s.lock", runtime_directory,
        (unsigned long)uid, hash) < (int)sizeof(cleanup_path));

    int lock_pipe[2];
    CHECK(pipe(lock_pipe) == 0);
    pid_t lock_child = fork();
    CHECK(lock_child >= 0);
    if (lock_child == 0) {
        char ready = 'x';
        close(lock_pipe[0]);
        close(prompt_lock);
        int child_lock = ksi_auth_prompt_lock_acquire(store, uid, hash);
        if (child_lock < 0 || write(lock_pipe[1], &ready, 1u) != 1) {
            _exit(1);
        }
        close(child_lock);
        close(lock_pipe[1]);
        _exit(0);
    }
    close(lock_pipe[1]);
    struct pollfd lock_wait = { .fd = lock_pipe[0], .events = POLLIN };
    CHECK(poll(&lock_wait, 1u, 100) == 0);
    close(prompt_lock);
    CHECK(poll(&lock_wait, 1u, 2000) == 1);
    char ready;
    CHECK(read(lock_pipe[0], &ready, 1u) == 1);
    CHECK(ready == 'x');
    close(lock_pipe[0]);
    int lock_status;
    CHECK(waitpid(lock_child, &lock_status, 0) == lock_child);
    CHECK(WIFEXITED(lock_status) && WEXITSTATUS(lock_status) == 0);

    ksi_auth_store_for_each(store, uid, collect_entry, &visited);
    CHECK(visited.count == 1u);
    CHECK(visited.scopes
        == KSP_INPUT_SCOPES);
    CHECK(visited.granted_at > 0u);
    CHECK(strcmp(visited.path, "/usr/bin/example-client") == 0);
    ksi_auth_store_destroy(store);
    store = NULL;

    CHECK(ksi_auth_store_create_at(&store, store_path) == 0);
    CHECK(ksi_auth_store_get_allowed(store, uid, hash)
        == KSP_INPUT_SCOPES);
    CHECK(ksi_auth_store_revoke(store, uid, hash,
        KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksi_auth_store_get_allowed(store, uid, hash)
        == KSP_SCOPE_INPUT_CONTROL);
    CHECK(ksi_auth_store_revoke(store, uid, hash,
        KSP_SCOPE_INPUT_CONTROL) == 0);
    CHECK(ksi_auth_store_get_allowed(store, uid, hash) == 0u);

    uint64_t generation;
    CHECK(ksi_auth_store_get_generation(store, uid, &generation) == 0);
    CHECK(generation == 4u);
    CHECK(ksi_auth_store_grant(store, uid, hash, "/usr/bin/example-client",
        KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksi_auth_store_revoke(store, uid, hash,
        KSP_SCOPE_INPUT_MONITORING) == 0);
    CHECK(ksi_auth_store_grant_if_generation(store, uid, hash,
        "/usr/bin/example-client", KSP_SCOPE_INPUT_MONITORING, generation) == 1);
    ksi_auth_store_destroy(store);

    CHECK(ksi_auth_get_process_start_time(getpid()) > 0u);
    CHECK(ksi_auth_identify_process(
        getpid(), exe_path, sizeof(exe_path), first_hash) == 0);
    CHECK(ksi_auth_identify_process(
        getpid(), exe_path, sizeof(exe_path), second_hash) == 0);
    CHECK(strlen(first_hash) == KSI_AUTH_HASH_HEX_LENGTH);
    CHECK(strcmp(first_hash, second_hash) == 0);
    CHECK(ksi_auth_hash_path_identity("/usr/bin/example-client", vector_hash) == 0);
    CHECK(strcmp(vector_hash,
        "4109d2117781adb1d57931e66ffad58fa3f88a0a6bb7584714f8699225933e1b") == 0);
    CHECK(ksi_auth_hash_content_identity(
        "0000000000000000000000000000000000000000000000000000000000000000",
        vector_hash) == 0);
    CHECK(strcmp(vector_hash,
        "73cd7ab5e10d259a782b6e021af8326514447477af0358481ee31fc5fee7d434") == 0);
    CHECK(ksi_auth_result_from_pkcheck_exit(0) == KSI_AUTH_GRANTED);
    CHECK(ksi_auth_result_from_pkcheck_exit(1) == KSI_AUTH_DENIED);
    CHECK(ksi_auth_result_from_pkcheck_exit(3) == KSI_AUTH_DENIED);
    CHECK(ksi_auth_result_from_pkcheck_exit(2) == KSI_AUTH_UNAVAILABLE);
    CHECK(ksi_auth_result_from_pkcheck_exit(126) == KSI_AUTH_UNAVAILABLE);
    CHECK(ksi_auth_result_from_pkcheck_exit(127) == KSI_AUTH_UNAVAILABLE);

    protected_fd = open("/usr/bin/env", O_RDONLY | O_CLOEXEC);
    CHECK(protected_fd >= 0);
    CHECK(ksi_auth_is_protected_executable(protected_fd, "/usr/bin/env"));
    CHECK(!ksi_auth_is_protected_executable(protected_fd, "/tmp/env"));
    close(protected_fd);

    for (uint32_t bit = 1u; bit <= KSP_SCOPE_INPUT_CONTROL; bit <<= 1u) {
        CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
            "%s/grant-%lu-%s-%08x.grant", shared_directory,
            (unsigned long)uid, hash, bit) < (int)sizeof(cleanup_path));
        (void)unlink(cleanup_path);
    }
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path), "%s/.lock",
        shared_directory) < (int)sizeof(cleanup_path));
    (void)unlink(cleanup_path);
    CHECK(rmdir(shared_directory) == 0);
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
        "%s/revoke-%lu.generation", runtime_directory,
        (unsigned long)uid) < (int)sizeof(cleanup_path));
    (void)unlink(cleanup_path);
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
        "%s/.revoke-%lu.lock", runtime_directory,
        (unsigned long)uid) < (int)sizeof(cleanup_path));
    (void)unlink(cleanup_path);
    CHECK(snprintf(cleanup_path, sizeof(cleanup_path),
        "%s/.prompt-%lu-%s.lock", runtime_directory,
        (unsigned long)uid, hash) < (int)sizeof(cleanup_path));
    (void)unlink(cleanup_path);
    CHECK(rmdir(runtime_directory) == 0);
    (void)unlink(store_path);
    CHECK(rmdir(directory) == 0);
    puts("auth tests passed");
    return 0;
}
