#include "owned_text_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool expect(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    }
    return condition;
}

static bool metadata_matches(const char *path, uid_t owner, gid_t group,
    mode_t mode)
{
    struct stat info;

    return stat(path, &info) == 0 && S_ISREG(info.st_mode)
        && info.st_uid == owner && info.st_gid == group
        && (info.st_mode & 07777) == mode;
}

static bool replace_contents(const char *path, const char *contents)
{
    int descriptor = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    size_t length = strlen(contents);
    ssize_t count;

    if (descriptor < 0) {
        return false;
    }
    count = write(descriptor, contents, length);
    return close(descriptor) == 0 && count == (ssize_t)length;
}

int main(void)
{
    static const char expected[] = "expected configuration\n";
    char temporary[] = "/tmp/ksi-owned-text-XXXXXX";
    char path[512];
    char target[512];
    char unsafe_parent[512];
    char unsafe_path[520];
    uid_t owner = geteuid();
    gid_t group = getegid();
    bool passed = true;

    if (mkdtemp(temporary) == NULL || chmod(temporary, 0700) != 0) {
        perror("mkdtemp");
        return 1;
    }

    (void)snprintf(path, sizeof(path), "%s/config", temporary);
    passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
        temporary) == 0, "create protected configuration") && passed;
    passed = expect(metadata_matches(path, owner, group, 0644),
        "new configuration has exact ownership and mode") && passed;

    passed = expect(chmod(path, 0666) == 0, "make mode unsafe") && passed;
    passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
        temporary) == 0, "repair exact configuration mode") && passed;
    passed = expect(metadata_matches(path, owner, group, 0644),
        "repaired configuration has exact mode") && passed;

    passed = expect(replace_contents(path, "modified\n"),
        "replace configuration contents") && passed;
    passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
        temporary) != 0, "reject modified configuration") && passed;
    passed = expect(replace_contents(path, expected),
        "restore configuration contents") && passed;

    (void)snprintf(target, sizeof(target), "%s/target", temporary);
    passed = expect(ksi_ensure_owned_text_file(target, expected, owner, group,
        temporary) == 0, "create symlink target") && passed;
    passed = expect(unlink(path) == 0 && symlink(target, path) == 0,
        "replace configuration with symlink") && passed;
    passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
        temporary) != 0, "reject final symlink") && passed;
    passed = expect(unlink(path) == 0, "remove final symlink") && passed;

    (void)snprintf(unsafe_parent, sizeof(unsafe_parent), "%s/unsafe", temporary);
    (void)snprintf(unsafe_path, sizeof(unsafe_path), "%s/config", unsafe_parent);
    passed = expect(mkdir(unsafe_parent, 0700) == 0
        && chmod(unsafe_parent, 0770) == 0,
        "create writable parent") && passed;
    passed = expect(ksi_ensure_owned_text_file(unsafe_path, expected, owner, group,
        temporary) != 0, "reject group-writable parent") && passed;

    if (owner == 0) {
        passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
            temporary) == 0, "recreate root configuration") && passed;
        passed = expect(chown(path, 65534, 65534) == 0,
            "make configuration non-root-owned") && passed;
        passed = expect(ksi_ensure_owned_text_file(path, expected, owner, group,
            temporary) == 0, "repair exact non-root-owned configuration") && passed;
        passed = expect(metadata_matches(path, owner, group, 0644),
            "repair restores root ownership") && passed;
    } else {
        passed = expect(ksi_ensure_owned_text_file(target, expected, 0, 0, "/") != 0,
            "non-root-owned configuration is not root protected") && passed;
    }

    (void)unlink(path);
    (void)unlink(target);
    (void)unlink(unsafe_path);
    (void)rmdir(unsafe_parent);
    (void)rmdir(temporary);

    if (!passed) {
        return 1;
    }
    puts("owned text file checks passed");
    return 0;
}
