#ifndef KEYSHARP_INPUTD_AUTH_H
#define KEYSHARP_INPUTD_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KSI_AUTH_HASH_HEX_LENGTH 64u
#define KSI_AUTH_MAX_PATH 4096u
#define KSI_AUTH_IDENTITY_DOMAIN "org.keysharp.app-identity-v1"
#define KSI_AUTH_IDENTITY_KIND_PATH "path"
#define KSI_AUTH_IDENTITY_KIND_SHA256 "sha256"

typedef struct ksi_auth_store ksi_auth_store;

typedef enum ksi_auth_result {
    KSI_AUTH_DENIED = 0,
    KSI_AUTH_GRANTED = 1,
    KSI_AUTH_UNAVAILABLE = 2,
} ksi_auth_result;

typedef struct ksi_auth_entry {
    uid_t uid;
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    const char *exe_path;
    uint32_t allowed_scopes;
    uint64_t granted_at_utc;
} ksi_auth_entry;

typedef bool (*ksi_auth_visit_fn)(const ksi_auth_entry *entry, void *user_data);

int ksi_auth_store_create(ksi_auth_store **store);
int ksi_auth_store_create_at(ksi_auth_store **store, const char *path);
void ksi_auth_store_destroy(ksi_auth_store *store);
const char *ksi_auth_store_runtime_directory(const ksi_auth_store *store);
/* Returns a locked descriptor. Closing it releases the cross-broker prompt
 * lock. No permission-store lock is held while this descriptor is retained. */
int ksi_auth_prompt_lock_acquire(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash);

int ksi_auth_identify_process(
    pid_t pid,
    char *path_buffer,
    size_t path_buffer_size,
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u]);
int ksi_auth_hash_path_identity(
    const char *absolute_path,
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u]);
int ksi_auth_hash_content_identity(
    const char executable_sha256[KSI_AUTH_HASH_HEX_LENGTH + 1u],
    char app_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u]);
bool ksi_auth_is_protected_executable(int exe_fd, const char *absolute_path);
void ksi_auth_sanitize_display_text(const char *source, char *destination,
                                    size_t capacity);
int ksi_auth_format_polkit_message(
    const char *exe_path,
    uint32_t permission_scopes,
    char *message,
    size_t capacity);

uint64_t ksi_auth_get_process_start_time(pid_t pid);
uint32_t ksi_auth_store_get_allowed(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash);
int ksi_auth_store_get_allowed_at_generation(
    const ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    uint32_t *allowed,
    uint64_t *generation);
int ksi_auth_store_grant(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    const char *exe_path,
    uint32_t scopes);
/* Returns 1 if a shared revoke raced the authorization, -1 on error, and 0
 * when the grant was persisted. */
int ksi_auth_store_grant_if_generation(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    const char *exe_path,
    uint32_t scopes,
    uint64_t expected_generation);
int ksi_auth_store_revoke(
    ksi_auth_store *store,
    uid_t uid,
    const char *app_hash,
    uint32_t scopes);
int ksi_auth_store_get_generation(
    const ksi_auth_store *store,
    uid_t uid,
    uint64_t *generation);
void ksi_auth_store_for_each(
    const ksi_auth_store *store,
    uid_t uid_filter,
    ksi_auth_visit_fn visit,
    void *user_data);

ksi_auth_result ksi_auth_request_polkit(
    pid_t pid,
    uid_t uid,
    uint64_t start_time,
    const char *exe_path,
    const char *app_hash,
    uint32_t scopes);
ksi_auth_result ksi_auth_result_from_pkcheck_exit(int exit_code);
void ksi_auth_cancel(void);

#endif
