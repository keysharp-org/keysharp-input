#include "platform/linux_terminal.h"
#include "terminal_contract.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <unistd.h>

typedef struct ksi_terminal_logind {
    void *handle;
    int (*seat_get_active)(const char *, char **, uid_t *);
    int (*uid_get_sessions)(uid_t, int, char ***);
    int (*session_get_uid)(const char *, uid_t *);
    int (*session_get_vt)(const char *, unsigned int *);
    int (*session_get_seat)(const char *, char **);
    int (*session_get_type)(const char *, char **);
    int (*session_get_state)(const char *, char **);
    int (*session_is_remote)(const char *);
} ksi_terminal_logind;

static bool terminal_symbol(void *handle, const char *name, void *destination, size_t size)
{
    void *symbol = dlsym(handle, name);
    if (symbol == NULL || size != sizeof(symbol)) return false;
    memcpy(destination, &symbol, size);
    return true;
}

static bool terminal_logind_open(ksi_terminal_logind *api)
{
    memset(api, 0, sizeof(*api));
    api->handle = dlopen("libsystemd.so.0", RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) { errno = ENOSYS; return false; }
#define LOAD(member, symbol) terminal_symbol(api->handle, symbol, &api->member, sizeof(api->member))
    bool loaded = LOAD(seat_get_active, "sd_seat_get_active")
        && LOAD(uid_get_sessions, "sd_uid_get_sessions")
        && LOAD(session_get_uid, "sd_session_get_uid")
        && LOAD(session_get_vt, "sd_session_get_vt")
        && LOAD(session_get_seat, "sd_session_get_seat")
        && LOAD(session_get_type, "sd_session_get_type")
        && LOAD(session_get_state, "sd_session_get_state")
        && LOAD(session_is_remote, "sd_session_is_remote");
#undef LOAD
    if (!loaded) {
        (void)dlclose(api->handle);
        api->handle = NULL;
        errno = ENOSYS;
    }
    return loaded;
}

static bool terminal_session_matches(const ksi_terminal_logind *api,
    const char *session, uid_t uid, uint32_t target)
{
    uid_t owner = (uid_t)-1;
    uid_t active = (uid_t)-1;
    unsigned int vt = 0u;
    char *seat = NULL, *type = NULL, *state = NULL;
    bool matches = api->seat_get_active("seat0", NULL, &active) >= 0 && active == uid
        && api->session_get_uid(session, &owner) >= 0 && owner == uid
        && api->session_get_vt(session, &vt) >= 0 && vt == target
        && api->session_is_remote(session) == 0
        && api->session_get_seat(session, &seat) >= 0 && seat != NULL && strcmp(seat, "seat0") == 0
        && api->session_get_type(session, &type) >= 0 && type != NULL && strcmp(type, "tty") == 0
        && api->session_get_state(session, &state) >= 0 && state != NULL
        && (strcmp(state, "online") == 0 || strcmp(state, "active") == 0);
    free(seat); free(type); free(state);
    if (!matches) errno = EACCES;
    return matches;
}

static char *terminal_find_session(const ksi_terminal_logind *api, uid_t uid, uint32_t target)
{
    char **sessions = NULL;
    char *found = NULL;
    int count = api->uid_get_sessions(uid, 0, &sessions);
    if (count < 0) { errno = -count; return NULL; }
    for (int i = 0; i < count; i++) {
        if (found == NULL && terminal_session_matches(api, sessions[i], uid, target)) {
            found = sessions[i];
        } else free(sessions[i]);
    }
    free(sessions);
    if (found == NULL) errno = EACCES;
    return found;
}

static bool terminal_fd_valid(int fd, uid_t uid, uint32_t target, uint32_t flags,
    struct termios *attributes)
{
    struct stat info;
    int display_mode = -1, keyboard_mode = -1, discipline = -1;
    if (fstat(fd, &info) != 0) return false;
    if (!S_ISCHR(info.st_mode) || major(info.st_rdev) != TTY_MAJOR
        || minor(info.st_rdev) != target || info.st_uid != uid) {
        errno = EACCES; return false;
    }
    if (ioctl(fd, KDGETMODE, &display_mode) != 0
        || ioctl(fd, KDGKBMODE, &keyboard_mode) != 0
        || ioctl(fd, TIOCGETD, &discipline) != 0
        || tcgetattr(fd, attributes) != 0) return false;
    if (display_mode != KD_TEXT || (keyboard_mode != K_XLATE && keyboard_mode != K_UNICODE)
        || discipline != N_TTY
        || ((flags & KSI_TERMINAL_INPUT_REQUIRE_UTF8) != 0u
            && (keyboard_mode != K_UNICODE || (attributes->c_iflag & IUTF8) == 0u))) {
        errno = ENOTSUP; return false;
    }
    return true;
}

static ksi_status terminal_error_status(int error)
{
    switch (error) {
        case EACCES: case EPERM: return KSI_STATUS_DENIED;
        case ENOSYS: case ENOTSUP: case ENOTTY: return KSI_STATUS_UNSUPPORTED;
        case ENOENT: case ENODEV: case ENXIO: return KSI_STATUS_NOT_FOUND;
        case ECANCELED: return KSI_STATUS_REVOKED;
        case EINVAL: return KSI_STATUS_INVALID_REQUEST;
        case ENOMEM: case EMFILE: case ENFILE: return KSI_STATUS_RESOURCE_EXHAUSTED;
        default: return KSI_STATUS_UNAVAILABLE;
    }
}

ksi_status ksi_linux_terminal_input(uid_t uid, uint32_t target,
    uint32_t flags, const uint8_t *bytes, uint32_t count,
    const ksi_terminal_gate *gate, uint32_t *accepted, int *system_error)
{
    *accepted = 0u;
    *system_error = 0;
    if (!ksi_terminal_request_valid(KSI_TERMINAL_TARGET_LINUX_VT, target, flags, bytes, count)
        || gate == NULL || gate->begin == NULL || gate->check == NULL || gate->end == NULL) {
        *system_error = EINVAL; return KSI_STATUS_INVALID_REQUEST;
    }
    ksi_terminal_logind api;
    if (!terminal_logind_open(&api)) {
        *system_error = errno; return terminal_error_status(errno);
    }
    char *session = terminal_find_session(&api, uid, target);
    int fd = -1;
    int saved_error = 0;
    struct termios attributes;
    bool backspace = (flags & KSI_TERMINAL_INPUT_TEXT) != 0u
        && count != 0u && memchr(bytes, '\b', count) != NULL;
    if (session == NULL) { saved_error = errno; goto done; }
    char path[32];
    (void)snprintf(path, sizeof(path), "/dev/tty%u", target);
    fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { saved_error = errno; goto done; }
    /* Keep this descriptor for the whole request: reopening after a hangup
     * could submit the remaining bytes into a different login. */
    do {
        if (!gate->begin(gate->context)) { saved_error = ECANCELED; break; }
        /* The gate may wait; validate both login and descriptor after acquiring
         * it, then recheck cancellation after the external state queries. */
        if (!terminal_session_matches(&api, session, uid, target)
            || !terminal_fd_valid(fd, uid, target, flags, &attributes)) {
            saved_error = errno;
            gate->end(gate->context);
            break;
        }
        if (backspace && attributes.c_cc[VERASE] == _POSIX_VDISABLE) {
            saved_error = ENOTSUP;
            gate->end(gate->context);
            break;
        }
        if (*accepted == count) { gate->end(gate->context); break; }
        if (!gate->check(gate->context)) {
            saved_error = ECANCELED;
            gate->end(gate->context);
            break;
        }
        uint8_t value = bytes[*accepted];
        if ((flags & KSI_TERMINAL_INPUT_TEXT) != 0u && value == '\b')
            value = attributes.c_cc[VERASE];
        int injected = ioctl(fd, TIOCSTI, &value);
        saved_error = injected == 0 ? 0 : errno;
        gate->end(gate->context);
        if (injected != 0) break;
        (*accepted)++;
    } while (*accepted < count);
done:
    if (fd >= 0) (void)close(fd);
    free(session);
    (void)dlclose(api.handle);
    *system_error = saved_error;
    return saved_error == 0 ? KSI_STATUS_OK : terminal_error_status(saved_error);
}
