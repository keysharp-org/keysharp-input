#include "owned_text_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool is_simple_absolute_path(const char *path)
{
    size_t length;

    if (path == NULL || path[0] != '/' || strstr(path, "//") != NULL
        || strstr(path, "/./") != NULL || strstr(path, "/../") != NULL) {
        return false;
    }

    length = strlen(path);
    return length > 1u
        && !(length >= 2u && strcmp(path + length - 2u, "/.") == 0)
        && !(length >= 3u && strcmp(path + length - 3u, "/..") == 0);
}

static bool parent_chain_is_protected(const char *path, uid_t owner,
    const char *protected_root)
{
    char *current;
    char *separator;
    struct stat info;
    bool protected = false;

    if (!is_simple_absolute_path(path) || protected_root == NULL
        || protected_root[0] != '/' || (protected_root[1] != '\0'
            && protected_root[strlen(protected_root) - 1u] == '/')) {
        errno = EINVAL;
        return false;
    }

    current = strdup(path);
    if (current == NULL) {
        return false;
    }

    errno = 0;
    separator = strrchr(current, '/');
    if (separator == current) {
        current[1] = '\0';
    } else {
        *separator = '\0';
    }

    for (;;) {
        if (lstat(current, &info) != 0 || !S_ISDIR(info.st_mode)
            || info.st_uid != owner
            || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            if (errno == 0) {
                errno = EPERM;
            }
            break;
        }

        if (strcmp(current, protected_root) == 0) {
            protected = true;
            break;
        }

        if (strcmp(current, "/") == 0) {
            errno = EPERM;
            break;
        }

        separator = strrchr(current, '/');
        if (separator == current) {
            current[1] = '\0';
        } else {
            *separator = '\0';
        }
    }

    if (!protected && errno == 0) {
        errno = EPERM;
    }
    free(current);
    return protected;
}

static bool descriptor_matches_text(int descriptor, const char *contents)
{
    struct stat info;
    size_t expected_length = strlen(contents);
    size_t offset = 0u;
    char buffer[4096];

    if (fstat(descriptor, &info) != 0) {
        return false;
    }
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_size < 0
        || (uintmax_t)info.st_size != (uintmax_t)expected_length) {
        errno = EEXIST;
        return false;
    }
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
        return false;
    }

    while (offset < expected_length) {
        size_t remaining = expected_length - offset;
        size_t wanted = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t count = read(descriptor, buffer, wanted);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0 || memcmp(buffer, contents + offset, (size_t)count) != 0) {
            if (count >= 0) {
                errno = EEXIST;
            }
            return false;
        }
        offset += (size_t)count;
    }

    return true;
}

static int secure_existing_file(const char *path, const char *contents,
    uid_t owner, gid_t group)
{
    struct stat info;
    int descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    int saved_error;

    if (descriptor < 0) {
        return -1;
    }

    if (!descriptor_matches_text(descriptor, contents)) {
        saved_error = errno != 0 ? errno : EEXIST;
        (void)close(descriptor);
        errno = saved_error;
        return -1;
    }

    if (fstat(descriptor, &info) != 0) {
        saved_error = errno;
        (void)close(descriptor);
        errno = saved_error;
        return -1;
    }

    if ((info.st_uid != owner || info.st_gid != group)
        && fchown(descriptor, owner, group) != 0) {
        saved_error = errno;
        (void)close(descriptor);
        errno = saved_error;
        return -1;
    }
    if ((info.st_mode & 07777) != 0644 && fchmod(descriptor, 0644) != 0) {
        saved_error = errno;
        (void)close(descriptor);
        errno = saved_error;
        return -1;
    }
    if (fsync(descriptor) != 0 || fstat(descriptor, &info) != 0
        || info.st_uid != owner || info.st_gid != group
        || (info.st_mode & 07777) != 0644) {
        saved_error = errno != 0 ? errno : EPERM;
        (void)close(descriptor);
        errno = saved_error;
        return -1;
    }

    return close(descriptor);
}

static int write_all(int descriptor, const char *contents)
{
    size_t length = strlen(contents);
    size_t offset = 0u;

    while (offset < length) {
        ssize_t count = write(descriptor, contents + offset, length - offset);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            if (count == 0) {
                errno = EIO;
            }
            return -1;
        }
        offset += (size_t)count;
    }

    return 0;
}

int ksi_ensure_owned_text_file(const char *path, const char *contents,
    uid_t owner, gid_t group, const char *protected_root)
{
    struct stat info;
    int descriptor;
    int saved_error;

    if (contents == NULL || !parent_chain_is_protected(path, owner, protected_root)) {
        return -1;
    }

    descriptor = open(path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        if (errno == EEXIST) {
            return secure_existing_file(path, contents, owner, group);
        }
        return -1;
    }

    if (write_all(descriptor, contents) != 0 || fstat(descriptor, &info) != 0
        || ((info.st_uid != owner || info.st_gid != group)
            && fchown(descriptor, owner, group) != 0)
        || fchmod(descriptor, 0644) != 0 || fsync(descriptor) != 0) {
        saved_error = errno;
        (void)close(descriptor);
        (void)unlink(path);
        errno = saved_error;
        return -1;
    }

    if (close(descriptor) != 0) {
        saved_error = errno;
        (void)unlink(path);
        errno = saved_error;
        return -1;
    }

    return 0;
}
