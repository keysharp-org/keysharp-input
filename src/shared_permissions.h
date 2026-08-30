#ifndef KEYSHARP_INPUTD_SHARED_PERMISSIONS_H
#define KEYSHARP_INPUTD_SHARED_PERMISSIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KSP_GRANT_DIRECTORY "/var/lib/keysharp-permissions/v1"
#define KSP_RUNTIME_DIRECTORY "/run/keysharp-permissions"

typedef struct ksi_shared_permission_entry {
    uid_t uid;
    char app_hash[65];
    char executable[4096];
    uint32_t scopes;
    uint64_t granted_at_utc;
} ksi_shared_permission_entry;

typedef bool (*ksi_shared_permission_visit_fn)(
    const ksi_shared_permission_entry *entry, void *user_data);

int ksi_shared_permissions_prepare(const char *directory);
int ksi_shared_permissions_prepare_runtime(const char *directory);
int ksi_shared_permissions_get(const char *directory, uid_t uid,
                               const char *app_hash, uint32_t scopes,
                               uint32_t *allowed);
int ksi_shared_permissions_get_at_generation(
    const char *directory, const char *runtime_directory, uid_t uid,
    const char *app_hash, uint32_t scopes, uint32_t *allowed,
    uint64_t *generation);
int ksi_shared_permissions_grant(const char *directory, uid_t uid,
                                 const char *app_hash, const char *executable,
                                 uint32_t scopes);
/* Returns 1 if the generation changed, -1 on error, and 0 on success. */
int ksi_shared_permissions_grant_if_generation(
    const char *directory, const char *runtime_directory, uid_t uid,
    const char *app_hash, const char *executable, uint32_t scopes,
    uint64_t expected_generation);
int ksi_shared_permissions_revoke(const char *directory,
                                  const char *runtime_directory, uid_t uid,
                                  const char *app_hash, uint32_t scopes);
int ksi_shared_permissions_generation_read(const char *runtime_directory,
                                           uid_t uid, uint64_t *generation);
bool ksi_shared_permissions_parse_marker_name(const char *name, uid_t *uid,
                                              char hash[65], uint32_t *scope);
void ksi_shared_permissions_for_each(const char *directory, uid_t uid_filter,
                                     uint32_t scopes,
                                     ksi_shared_permission_visit_fn visit,
                                     void *user_data);

#endif
