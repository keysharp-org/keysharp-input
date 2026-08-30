#include "shared_permissions.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define KSP_GRANT_VERSION "keysharp-permission-v1"
#define KSP_MARKER_SUFFIX ".grant"
#define KSP_MAX_ENTRIES 2048u

static bool write_all(int descriptor, const void *data, size_t length)
{
    const unsigned char *cursor = data;

    while (length != 0u) {
        ssize_t written = write(descriptor, cursor, length);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static bool valid_hash(const char *value)
{
    if (value == NULL || strlen(value) != 64u)
        return false;
    for (size_t index = 0u; index < 64u; index++)
        if (!((value[index] >= '0' && value[index] <= '9')
              || (value[index] >= 'a' && value[index] <= 'f')))
            return false;
    return true;
}

static int make_parent_directories(const char *path, mode_t mode)
{
    char copy[4096];

    if (path == NULL || strlen(path) >= sizeof(copy))
        return -1;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/')
            continue;
        *cursor = '\0';
        if (mkdir(copy, mode) != 0 && errno != EEXIST)
            return -1;
        *cursor = '/';
    }
    return 0;
}

int ksi_shared_permissions_prepare(const char *directory)
{
    char child[4096];
    struct stat info;
    int length;

    if (directory == NULL)
        return -1;
    length = snprintf(child, sizeof(child), "%s/x", directory);
    if (length <= 0 || (size_t)length >= sizeof(child)
        || make_parent_directories(child, 0700) != 0
        || lstat(directory, &info) != 0 || !S_ISDIR(info.st_mode)
        || info.st_uid != geteuid()
        || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || chmod(directory, 0700) != 0)
        return -1;
    return 0;
}

int ksi_shared_permissions_prepare_runtime(const char *directory)
{
    char child[4096];
    struct stat info;
    int length;

    if (directory == NULL)
        return -1;
    length = snprintf(child, sizeof(child), "%s/x", directory);
    if (length <= 0 || (size_t)length >= sizeof(child)
        || make_parent_directories(child, 0755) != 0
        || lstat(directory, &info) != 0 || !S_ISDIR(info.st_mode)
        || info.st_uid != geteuid()
        || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || chmod(directory, 0755) != 0)
        return -1;
    return 0;
}

static int lock_store(const char *directory, int operation)
{
    char path[4096];
    int descriptor;
    int length;

    if (ksi_shared_permissions_prepare(directory) != 0)
        return -1;
    length = snprintf(path, sizeof(path), "%s/.lock", directory);
    if (length <= 0 || (size_t)length >= sizeof(path))
        return -1;
    descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || fchmod(descriptor, 0600) != 0) {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    if (flock(descriptor, operation) != 0) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int marker_path(const char *directory, uid_t uid, const char *hash,
                       uint32_t scope, char *path, size_t capacity)
{
    int length;

    if (directory == NULL || !valid_hash(hash) || scope == 0u
        || (scope & (scope - 1u)) != 0u)
        return -1;
    length = snprintf(path, capacity, "%s/grant-%lu-%s-%08x" KSP_MARKER_SUFFIX,
                      directory, (unsigned long)uid, hash, scope);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

static int read_marker(const char *directory, uid_t uid, const char *hash,
                       uint32_t scope,
                       ksi_shared_permission_entry *entry)
{
    char path[4224];
    char line[4352];
    char version[64];
    char record_hash[65];
    char executable[4096] = "";
    unsigned long record_uid;
    unsigned int record_scope;
    unsigned long long granted_at;
    struct stat info;
    FILE *file;
    int descriptor;
    int fields;
    int executable_offset = -1;
    bool no_trailing_data;

    if (marker_path(directory, uid, hash, scope, path, sizeof(path)) != 0)
        return -1;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != geteuid()
        || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(descriptor);
        errno = EACCES;
        return -1;
    }
    file = fdopen(descriptor, "r");
    if (file == NULL) {
        close(descriptor);
        return -1;
    }
    if (fgets(version, sizeof(version), file) == NULL
        || strcmp(version, KSP_GRANT_VERSION "\n") != 0
        || fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        errno = EPROTO;
        return -1;
    }
    fields = sscanf(line, "%lu\t%64[a-f0-9]\t%x\t%llu%n",
                    &record_uid, record_hash, &record_scope,
                    &granted_at, &executable_offset);
    no_trailing_data = fgetc(file) == EOF && feof(file);
    if (fclose(file) != 0)
        return -1;
    if (fields != 4 || record_uid != (unsigned long)uid
        || strcmp(record_hash, hash) != 0 || record_scope != scope
        || executable_offset < 0 || line[executable_offset] != '\t') {
        errno = EPROTO;
        return -1;
    }
    const char *record_executable = line + executable_offset + 1;
    size_t executable_length = strcspn(record_executable, "\n");
    if (executable_length == 0u
        || record_executable[executable_length] != '\n'
        || record_executable[executable_length + 1u] != '\0'
        || executable_length >= sizeof(executable)
        || !no_trailing_data) {
        errno = EPROTO;
        return -1;
    }
    for (size_t index = 0u; index < executable_length; index++) {
        unsigned char value = (unsigned char)record_executable[index];
        if (value < 0x20u || value == 0x7fu) {
            errno = EPROTO;
            return -1;
        }
    }
    memcpy(executable, record_executable, executable_length);
    executable[executable_length] = '\0';
    if (entry != NULL) {
        memset(entry, 0, sizeof(*entry));
        entry->uid = uid;
        (void)snprintf(entry->app_hash, sizeof(entry->app_hash), "%s", hash);
        (void)snprintf(entry->executable, sizeof(entry->executable), "%s",
                       executable);
        entry->scopes = scope;
        entry->granted_at_utc = (uint64_t)granted_at;
    }
    return 1;
}

static int fsync_directory(const char *directory)
{
    int descriptor = open(directory,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int result;

    if (descriptor < 0)
        return -1;
    result = fsync(descriptor);
    close(descriptor);
    return result;
}

static int write_marker_locked(const char *directory, uid_t uid,
                               const char *hash, const char *path_text,
                               uint32_t scope)
{
    char path[4224];
    char temporary[4224];
    char executable[4096];
    FILE *file = NULL;
    int descriptor = -1;
    int result = -1;
    int existing = read_marker(directory, uid, hash, scope, NULL);
    int temporary_length;

    if (existing != 0)
        return existing > 0 ? 0 : -1;
    if (marker_path(directory, uid, hash, scope, path, sizeof(path)) != 0)
        return -1;
    temporary_length = snprintf(temporary, sizeof(temporary),
                                "%s/.grant-%lu-XXXXXX", directory,
                                (unsigned long)uid);
    if (temporary_length <= 0
        || (size_t)temporary_length >= sizeof(temporary))
        return -1;
    (void)snprintf(executable, sizeof(executable), "%s",
                   path_text == NULL ? "" : path_text);
    for (unsigned char *cursor = (unsigned char *)executable;
         *cursor != '\0'; cursor++)
        if (*cursor < 0x20u || *cursor == 0x7fu)
            *cursor = (unsigned char)'?';
    descriptor = mkstemp(temporary);
    if (descriptor < 0 || fchmod(descriptor, 0600) != 0)
        goto done;
    file = fdopen(descriptor, "w");
    if (file == NULL)
        goto done;
    descriptor = -1;
    if (fprintf(file, KSP_GRANT_VERSION "\n%lu\t%s\t%08x\t%llu\t%s\n",
                 (unsigned long)uid, hash, scope,
                (unsigned long long)time(NULL), executable) < 0
        || fflush(file) != 0 || fsync(fileno(file)) != 0)
        goto done;
    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;
    if (rename(temporary, path) != 0 || fsync_directory(directory) != 0)
        goto done;
    result = 0;

done:
    if (file != NULL)
        fclose(file);
    if (descriptor >= 0)
        close(descriptor);
    if (result != 0)
        (void)unlink(temporary);
    return result;
}

static int write_scopes_locked(const char *directory, uid_t uid,
                                     const char *hash, const char *executable,
                                     uint32_t scopes)
{
    for (uint32_t bit = 1u; bit != 0u; bit <<= 1u)
        if ((scopes & bit) != 0u
            && write_marker_locked(directory, uid, hash, executable, bit) != 0)
            return -1;
    return 0;
}

static int get_locked(const char *directory, uid_t uid, const char *app_hash,
                      uint32_t scopes, uint32_t *allowed)
{
    int result = 0;

    *allowed = 0u;
    for (uint32_t bit = 1u; bit != 0u; bit <<= 1u) {
        if ((scopes & bit) == 0u)
            continue;
        int found = read_marker(directory, uid, app_hash, bit, NULL);
        if (found < 0) {
            result = -1;
            break;
        }
        if (found > 0)
            *allowed |= bit;
    }
    return result;
}

int ksi_shared_permissions_get(const char *directory, uid_t uid,
                               const char *app_hash, uint32_t scopes,
                               uint32_t *allowed)
{
    int lock;
    int result;

    if (allowed == NULL || !valid_hash(app_hash))
        return -1;
    lock = lock_store(directory, LOCK_SH);
    if (lock < 0)
        return -1;
    result = get_locked(directory, uid, app_hash, scopes, allowed);
    (void)flock(lock, LOCK_UN);
    close(lock);
    return result;
}

int ksi_shared_permissions_grant(const char *directory, uid_t uid,
                                 const char *app_hash, const char *executable,
                                 uint32_t scopes)
{
    int lock;
    int result;

    if (!valid_hash(app_hash) || scopes == 0u)
        return -1;
    lock = lock_store(directory, LOCK_EX);
    if (lock < 0)
        return -1;
    result = write_scopes_locked(directory, uid, app_hash,
                                 executable, scopes);
    (void)flock(lock, LOCK_UN);
    close(lock);
    return result;
}

static int generation_path(const char *runtime_directory, uid_t uid,
                           char *path, size_t capacity)
{
    int length;

    if (runtime_directory == NULL)
        return -1;
    length = snprintf(path, capacity, "%s/revoke-%lu.generation",
                      runtime_directory, (unsigned long)uid);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

int ksi_shared_permissions_generation_read(const char *runtime_directory,
                                           uid_t uid, uint64_t *generation)
{
    char path[4096];
    struct stat info;
    uint64_t value;
    unsigned char trailing;
    int descriptor;

    if (generation == NULL
        || generation_path(runtime_directory, uid, path, sizeof(path)) != 0)
        return -1;
    *generation = 0u;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != geteuid() || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || read(descriptor, &value, sizeof(value)) != (ssize_t)sizeof(value)
        || read(descriptor, &trailing, 1u) != 0) {
        close(descriptor);
        return -1;
    }
    close(descriptor);
    *generation = value;
    return 0;
}

int ksi_shared_permissions_get_at_generation(
    const char *directory, const char *runtime_directory, uid_t uid,
    const char *app_hash, uint32_t scopes, uint32_t *allowed,
    uint64_t *generation)
{
    int lock;
    int result;

    if (allowed == NULL || generation == NULL || !valid_hash(app_hash))
        return -1;
    *allowed = 0u;
    *generation = 0u;
    lock = lock_store(directory, LOCK_SH);
    if (lock < 0)
        return -1;
    result = get_locked(directory, uid, app_hash, scopes, allowed);
    if (result == 0)
        result = ksi_shared_permissions_generation_read(runtime_directory, uid,
                                                        generation);
    (void)flock(lock, LOCK_UN);
    close(lock);
    return result;
}

static int bump_generation(const char *runtime_directory, uid_t uid)
{
    char path[4096];
    char lock_path[4096];
    char temporary[4096];
    uint64_t generation = 0u;
    int lock = -1;
    int descriptor = -1;
    int result = -1;
    int lock_length;
    int temporary_length;

    if (generation_path(runtime_directory, uid, path, sizeof(path)) != 0)
        return -1;
    lock_length = snprintf(lock_path, sizeof(lock_path),
                           "%s/.revoke-%lu.lock", runtime_directory,
                           (unsigned long)uid);
    temporary_length = snprintf(temporary, sizeof(temporary),
                                "%s/.revoke-%lu.XXXXXX", runtime_directory,
                                (unsigned long)uid);
    if (lock_length <= 0 || (size_t)lock_length >= sizeof(lock_path)
        || temporary_length <= 0
        || (size_t)temporary_length >= sizeof(temporary)
        || ksi_shared_permissions_prepare_runtime(runtime_directory) != 0)
        return -1;
    lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || fchmod(lock, 0600) != 0 || flock(lock, LOCK_EX) != 0)
        goto done;
    if (ksi_shared_permissions_generation_read(runtime_directory, uid,
                                               &generation) != 0)
        goto done;
    generation++;
    if (generation == 0u)
        generation = 1u;
    descriptor = mkstemp(temporary);
    if (descriptor < 0 || fchmod(descriptor, 0644) != 0
        || !write_all(descriptor, &generation, sizeof(generation))
        || fsync(descriptor) != 0)
        goto cleanup_path;
    if (close(descriptor) != 0) {
        descriptor = -1;
        goto cleanup_path;
    }
    descriptor = -1;
    if (rename(temporary, path) != 0
        || fsync_directory(runtime_directory) != 0)
        goto cleanup_path;
    result = 0;
    goto done;

cleanup_path:
    (void)unlink(temporary);
done:
    if (descriptor >= 0)
        close(descriptor);
    if (lock >= 0) {
        (void)flock(lock, LOCK_UN);
        close(lock);
    }
    return result;
}

int ksi_shared_permissions_grant_if_generation(
    const char *directory, const char *runtime_directory, uid_t uid,
    const char *app_hash, const char *executable, uint32_t scopes,
    uint64_t expected_generation)
{
    uint64_t generation;
    int lock;
    int result;

    if (!valid_hash(app_hash) || scopes == 0u)
        return -1;
    lock = lock_store(directory, LOCK_EX);
    if (lock < 0)
        return -1;
    if (ksi_shared_permissions_generation_read(runtime_directory, uid,
                                               &generation) != 0)
        result = -1;
    else if (generation != expected_generation)
        result = 1;
    else
        result = write_scopes_locked(directory, uid, app_hash,
                                     executable, scopes);
    (void)flock(lock, LOCK_UN);
    close(lock);
    return result;
}

int ksi_shared_permissions_revoke(const char *directory,
                                  const char *runtime_directory, uid_t uid,
                                  const char *app_hash, uint32_t scopes)
{
    char path[4224];
    int lock;
    int result = -1;

    if (!valid_hash(app_hash) || scopes == 0u)
        return -1;
    lock = lock_store(directory, LOCK_EX);
    if (lock < 0)
        return -1;
    if (bump_generation(runtime_directory, uid) != 0)
        goto done;
    for (uint32_t bit = 1u; bit != 0u; bit <<= 1u) {
        if ((scopes & bit) == 0u)
            continue;
        if (marker_path(directory, uid, app_hash, bit, path, sizeof(path)) != 0
            || (unlink(path) != 0 && errno != ENOENT))
            goto done;
    }
    if (fsync_directory(directory) != 0
        || bump_generation(runtime_directory, uid) != 0)
        goto done;
    result = 0;

done:
    (void)flock(lock, LOCK_UN);
    close(lock);
    return result;
}

bool ksi_shared_permissions_parse_marker_name(const char *name, uid_t *uid,
                                              char hash[65], uint32_t *scope)
{
    static const char prefix_text[] = "grant-";
    char canonical_prefix[64];
    const char *uid_end;
    const char *hash_text;
    const char *bit_text;
    const char *suffix;
    char *end;
    unsigned long uid_value;
    unsigned long bit_value;
    uid_t parsed_uid;
    size_t length;
    size_t suffix_length = strlen(KSP_MARKER_SUFFIX);
    int prefix_length;

    if (name == NULL || uid == NULL || hash == NULL || scope == NULL
        || strncmp(name, prefix_text, sizeof(prefix_text) - 1u) != 0)
        return false;
    uid_end = strchr(name + sizeof(prefix_text) - 1u, '-');
    if (uid_end == NULL)
        return false;
    errno = 0;
    uid_value = strtoul(name + sizeof(prefix_text) - 1u, &end, 10);
    parsed_uid = (uid_t)uid_value;
    if (errno != 0 || end != uid_end || end == name + sizeof(prefix_text) - 1u
        || (unsigned long)parsed_uid != uid_value)
        return false;
    prefix_length = snprintf(canonical_prefix, sizeof(canonical_prefix),
                             "grant-%lu-", (unsigned long)parsed_uid);
    if (prefix_length <= 0 || (size_t)prefix_length >= sizeof(canonical_prefix)
        || (size_t)(uid_end - name + 1) != (size_t)prefix_length
        || memcmp(name, canonical_prefix, (size_t)prefix_length) != 0)
        return false;
    length = strlen(name);
    if (length != (size_t)prefix_length + 64u + 1u + 8u + suffix_length
        || strcmp(name + length - suffix_length, KSP_MARKER_SUFFIX) != 0)
        return false;
    hash_text = name + prefix_length;
    for (size_t index = 0u; index < 64u; index++)
        if (!((hash_text[index] >= '0' && hash_text[index] <= '9')
              || (hash_text[index] >= 'a' && hash_text[index] <= 'f')))
            return false;
    if (hash_text[64] != '-')
        return false;
    bit_text = hash_text + 65u;
    suffix = bit_text + 8u;
    for (size_t index = 0u; index < 8u; index++)
        if (!((bit_text[index] >= '0' && bit_text[index] <= '9')
              || (bit_text[index] >= 'a' && bit_text[index] <= 'f')))
            return false;
    errno = 0;
    bit_value = strtoul(bit_text, &end, 16);
    if (errno != 0 || end != suffix || bit_value == 0u
        || bit_value > UINT32_MAX || (bit_value & (bit_value - 1u)) != 0u)
        return false;
    memcpy(hash, hash_text, 64u);
    hash[64] = '\0';
    *uid = parsed_uid;
    *scope = (uint32_t)bit_value;
    return true;
}

void ksi_shared_permissions_for_each(const char *directory, uid_t uid_filter,
                                     uint32_t scopes,
                                     ksi_shared_permission_visit_fn visit,
                                     void *user_data)
{
    ksi_shared_permission_entry *entries = NULL;
    size_t count = 0u;
    DIR *stream;
    int lock;

    if (visit == NULL)
        return;
    entries = calloc(KSP_MAX_ENTRIES, sizeof(*entries));
    if (entries == NULL)
        return;
    lock = lock_store(directory, LOCK_SH);
    if (lock < 0) {
        free(entries);
        return;
    }
    stream = opendir(directory);
    if (stream == NULL)
        goto done;
    for (;;) {
        struct dirent *item = readdir(stream);
        uid_t uid;
        uint32_t scope;
        char hash[65];
        ksi_shared_permission_entry marker;
        size_t target;

        if (item == NULL)
            break;
        if (!ksi_shared_permissions_parse_marker_name(item->d_name, &uid,
                                                       hash, &scope)
            || (scopes & scope) == 0u
            || (uid_filter != (uid_t)-1 && uid_filter != uid)
            || read_marker(directory, uid, hash, scope, &marker) <= 0)
            continue;
        for (target = 0u; target < count; target++)
            if (entries[target].uid == uid
                && strcmp(entries[target].app_hash, hash) == 0)
                break;
        if (target == count) {
            if (count == KSP_MAX_ENTRIES)
                break;
            entries[count++] = marker;
        } else {
            entries[target].scopes |= scope;
            if (marker.granted_at_utc > entries[target].granted_at_utc) {
                entries[target].granted_at_utc = marker.granted_at_utc;
                (void)snprintf(entries[target].executable,
                               sizeof(entries[target].executable), "%s",
                               marker.executable);
            }
        }
    }
    closedir(stream);
    for (size_t index = 0u; index < count; index++)
        if (!visit(&entries[index], user_data))
            break;

done:
    (void)flock(lock, LOCK_UN);
    close(lock);
    free(entries);
}
