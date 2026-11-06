#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <unistd.h>

static void *fake_dlopen(const char *name, int flags);
static void *fake_dlsym(void *handle, const char *name);
static int fake_dlclose(void *handle);
static int fake_open(const char *name, int flags, ...);
static int fake_close(int fd);
static int fake_fstat(int fd, struct stat *info);
static int fake_ioctl(int fd, unsigned long operation, ...);
static int fake_tcgetattr(int fd, struct termios *attributes);
#define dlopen fake_dlopen
#define dlsym fake_dlsym
#define dlclose fake_dlclose
#define open fake_open
#define close fake_close
#define fstat fake_fstat
#define ioctl fake_ioctl
#define tcgetattr fake_tcgetattr
#include "../src/platform/linux_terminal.c"
#undef dlopen
#undef dlsym
#undef dlclose
#undef open
#undef close
#undef fstat
#undef ioctl
#undef tcgetattr

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); return false; \
} } while (0)

static struct {
    uint32_t injected, fail_at, mutate_at, cancelled_at;
    unsigned int opens, closes, loads, mutations, gate_mutation;
    int open_flags, error, keyboard_mode, display_mode, discipline;
    bool remote, bad_device, no_sessions, utf8, erase_disabled, gate_held, cancel_during_validation;
    uid_t active_uid, session_uid, file_uid;
    const char *seat, *type, *state;
    uint8_t output[KSI_MAX_TERMINAL_INPUT_BYTES];
} fixture;

static void reset(void)
{
    memset(&fixture, 0, sizeof(fixture));
    fixture.fail_at = fixture.mutate_at = fixture.cancelled_at = UINT32_MAX;
    fixture.active_uid = fixture.session_uid = fixture.file_uid = 1000u;
    fixture.seat = "seat0"; fixture.type = "tty"; fixture.state = "online";
    fixture.keyboard_mode = K_UNICODE; fixture.display_mode = KD_TEXT;
    fixture.discipline = N_TTY; fixture.utf8 = true;
}

static void mutate(void)
{
    if (fixture.injected != fixture.mutate_at) return;
    switch (fixture.mutations) {
        case 1u: fixture.file_uid++; break;
        case 2u: fixture.active_uid++; break;
        case 3u: fixture.keyboard_mode = K_RAW; break;
        case 4u: fixture.state = "closing"; break;
        case 5u: fixture.session_uid++; break;
        default: break;
    }
    fixture.mutate_at = UINT32_MAX;
}

static int fake_seat_active(const char *seat, char **session, uid_t *uid)
{
    (void)seat; (void)session; mutate(); *uid = fixture.active_uid; return 0;
}
static int fake_sessions(uid_t uid, int active, char ***out)
{
    (void)uid; (void)active;
    if (fixture.no_sessions) { *out = NULL; return 0; }
    *out = calloc(2u, sizeof(char *)); (*out)[0] = strdup("c3"); return 1;
}
static int fake_uid(const char *session, uid_t *uid)
{ (void)session; *uid = fixture.session_uid; return 0; }
static int fake_vt(const char *session, unsigned int *vt)
{ (void)session; *vt = 3u; return 0; }
static int fake_seat(const char *session, char **seat)
{ (void)session; *seat = strdup(fixture.seat); return 0; }
static int fake_type(const char *session, char **type)
{ (void)session; *type = strdup(fixture.type); return 0; }
static int fake_state(const char *session, char **state)
{ (void)session; *state = strdup(fixture.state); return 0; }
static int fake_remote(const char *session)
{ (void)session; return fixture.remote ? 1 : 0; }
static void *function_address(void (*function)(void))
{ void *address; memcpy(&address, &function, sizeof(address)); return address; }
static void *fake_dlopen(const char *name, int flags)
{ (void)name; (void)flags; fixture.loads++; return &fixture; }
static int fake_dlclose(void *handle) { (void)handle; return 0; }
static void *fake_dlsym(void *handle, const char *name)
{
    (void)handle;
#define SYMBOL(symbol, function) if (strcmp(name, symbol) == 0) return function_address((void (*)(void))function)
    SYMBOL("sd_seat_get_active", fake_seat_active);
    SYMBOL("sd_uid_get_sessions", fake_sessions);
    SYMBOL("sd_session_get_uid", fake_uid);
    SYMBOL("sd_session_get_vt", fake_vt);
    SYMBOL("sd_session_get_seat", fake_seat);
    SYMBOL("sd_session_get_type", fake_type);
    SYMBOL("sd_session_get_state", fake_state);
    SYMBOL("sd_session_is_remote", fake_remote);
#undef SYMBOL
    return NULL;
}
static int fake_open(const char *name, int flags, ...)
{
    fixture.opens++; fixture.open_flags = flags;
    if (strcmp(name, "/dev/tty3") != 0) { errno = ENOENT; return -1; }
    return 37;
}
static int fake_close(int fd) { (void)fd; fixture.closes++; return 0; }
static int fake_fstat(int fd, struct stat *info)
{
    (void)fd; memset(info, 0, sizeof(*info));
    info->st_mode = S_IFCHR; info->st_uid = fixture.file_uid;
    info->st_rdev = makedev(fixture.bad_device ? 5u : TTY_MAJOR, 3u);
    return 0;
}
static int fake_ioctl(int fd, unsigned long operation, ...)
{
    (void)fd; va_list args; va_start(args, operation); void *value = va_arg(args, void *); va_end(args);
    if (operation == KDGETMODE) { *(int *)value = fixture.display_mode; return 0; }
    if (operation == KDGKBMODE) { *(int *)value = fixture.keyboard_mode; return 0; }
    if (operation == TIOCGETD) { *(int *)value = fixture.discipline; return 0; }
    if (operation == TIOCSTI && fixture.gate_held) {
        if (fixture.injected == fixture.fail_at) { errno = fixture.error; return -1; }
        fixture.output[fixture.injected++] = *(uint8_t *)value;
        return 0;
    }
    errno = ENOTTY; return -1;
}
static int fake_tcgetattr(int fd, struct termios *attributes)
{
    (void)fd; memset(attributes, 0, sizeof(*attributes));
    if (fixture.cancel_during_validation) fixture.cancelled_at = fixture.injected;
    attributes->c_iflag = fixture.utf8 ? IUTF8 : 0u;
    attributes->c_cc[VERASE] = fixture.erase_disabled ? _POSIX_VDISABLE : 127u;
    return 0;
}
static bool gate_begin(void *context)
{
    (void)context;
    if (fixture.injected == fixture.cancelled_at) return false;
    if (fixture.gate_mutation != 0u) {
        fixture.mutate_at = fixture.injected;
        fixture.mutations = fixture.gate_mutation;
        fixture.gate_mutation = 0u;
        mutate();
    }
    fixture.gate_held = true; return true;
}
static void gate_end(void *context) { (void)context; fixture.gate_held = false; }
static bool gate_check(void *context)
{ (void)context; return fixture.injected != fixture.cancelled_at; }

static ksi_status submit(const uint8_t *bytes, uint32_t count, uint32_t flags, uint32_t *accepted)
{
    const ksi_terminal_gate gate = { .begin = gate_begin, .check = gate_check, .end = gate_end };
    int error = 0;
    ksi_status status = ksi_linux_terminal_input(1000u, 3u, flags, bytes, count, &gate, accepted, &error);
    if (status != KSI_STATUS_OK && error == 0) return KSI_STATUS_INTERNAL;
    return status;
}

static bool test_terminal_input(void)
{
    const uint8_t text[] = {'a', 0xceu, 0xa9u, '\b', '\r'};
    uint32_t accepted;
    reset();
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_OK);
    CHECK(accepted == sizeof(text) && fixture.injected == accepted && fixture.output[3] == 127u);
    CHECK(fixture.opens == 1u && fixture.closes == 1u && !fixture.gate_held);
    CHECK((fixture.open_flags & (O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW))
        == (O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    reset();
    CHECK(submit(text, sizeof(text), 0u, &accepted) == KSI_STATUS_OK && fixture.output[3] == '\b');
    for (unsigned int mutation = 1u; mutation <= 5u; mutation++) {
        reset(); fixture.mutate_at = 2u; fixture.mutations = mutation;
        CHECK(submit(text, sizeof(text), 3u, &accepted) != KSI_STATUS_OK);
        CHECK(accepted == 2u && fixture.injected == 2u && fixture.opens == 1u && fixture.closes == 1u);
    }
    reset(); fixture.fail_at = 2u; fixture.error = EPERM;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && accepted == 2u);
    CHECK(!fixture.gate_held && fixture.opens == 1u);
    reset(); fixture.fail_at = 0u; fixture.error = EIO;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNAVAILABLE && accepted == 0u);
    reset(); fixture.cancelled_at = 2u;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_REVOKED && accepted == 2u);
    reset(); fixture.bad_device = true;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && accepted == 0u);
    for (unsigned int mutation = 1u; mutation <= 5u; mutation++) {
        reset(); fixture.gate_mutation = mutation;
        CHECK(submit(text, sizeof(text), 3u, &accepted)
            == (mutation == 3u ? KSI_STATUS_UNSUPPORTED : KSI_STATUS_DENIED));
        CHECK(accepted == 0u && !fixture.gate_held);
    }
    reset(); fixture.cancel_during_validation = true;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_REVOKED);
    CHECK(accepted == 0u && !fixture.gate_held);
    reset(); fixture.no_sessions = true;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && fixture.opens == 0u);
    reset(); fixture.type = "wayland";
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && fixture.opens == 0u);
    reset(); fixture.remote = true;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && fixture.opens == 0u);
    reset(); fixture.seat = "seat1";
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_DENIED && fixture.opens == 0u);
    reset(); fixture.display_mode = KD_GRAPHICS;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNSUPPORTED && accepted == 0u);
    reset(); fixture.keyboard_mode = K_XLATE;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNSUPPORTED && accepted == 0u);
    CHECK(submit(text, sizeof(text), 0u, &accepted) == KSI_STATUS_OK);
    reset(); fixture.utf8 = false;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNSUPPORTED && accepted == 0u);
    reset(); fixture.erase_disabled = true;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNSUPPORTED && accepted == 0u);
    reset(); fixture.discipline = 1;
    CHECK(submit(text, sizeof(text), 3u, &accepted) == KSI_STATUS_UNSUPPORTED && accepted == 0u);
    reset();
    const uint8_t invalid[][4] = {{0xc0, 0x80}, {0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}, {0x80}, {0xce}};
    const uint32_t lengths[] = {2u, 3u, 4u, 1u, 1u};
    for (size_t i = 0u; i < sizeof(lengths) / sizeof(lengths[0]); i++)
        CHECK(submit(invalid[i], lengths[i], 3u, &accepted) == KSI_STATUS_INVALID_REQUEST && accepted == 0u);
    CHECK(submit(NULL, 1025u, 3u, &accepted) == KSI_STATUS_INVALID_REQUEST && fixture.loads == 0u);
    CHECK(!ksi_terminal_request_valid(1u, 0u, 0u, NULL, 0u));
    CHECK(!ksi_terminal_request_valid(1u, 64u, 0u, NULL, 0u));
    CHECK(!ksi_terminal_request_valid(2u, 3u, 0u, NULL, 0u));
    CHECK(submit(NULL, 0u, 3u, &accepted) == KSI_STATUS_OK && accepted == 0u);
    uint8_t maximum[KSI_MAX_TERMINAL_INPUT_BYTES];
    memset(maximum, 'x', sizeof(maximum));
    reset();
    CHECK(submit(maximum, sizeof(maximum), 3u, &accepted) == KSI_STATUS_OK);
    CHECK(accepted == sizeof(maximum) && memcmp(fixture.output, maximum, sizeof(maximum)) == 0);
    return true;
}

int main(void)
{
    if (!test_terminal_input()) return 1;
    puts("PASS targeted Linux terminal input");
    return 0;
}
