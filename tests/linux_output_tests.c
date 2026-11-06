#include <errno.h>
#include <linux/input.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>

static int grab_error, release_error;
static unsigned int grabs, releases;
static bool wrong_request;

static int fake_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    int enabled = va_arg(args, int);
    va_end(args);
    if (fd != 17 || request != EVIOCGRAB) wrong_request = true;
    if (enabled) grabs++;
    else releases++;
    int error = enabled ? grab_error : release_error;
    if (error != 0) { errno = error; return -1; }
    return 0;
}

#define ioctl fake_ioctl
#include "../src/platform/linux_output.c"
#undef ioctl

static bool check_probe(int grab_failure, int release_failure,
    int expected, unsigned int expected_releases)
{
    grab_error = grab_failure;
    release_error = release_failure;
    grabs = releases = 0u;
    wrong_request = false;
    return ksi_linux_output_probe_grabbed(17) == expected
        && grabs == 1u && releases == expected_releases && !wrong_request;
}

int main(void)
{
    if (!check_probe(0, 0, 0, 1u)
        || !check_probe(EBUSY, 0, 1, 0u)
        || !check_probe(ENODEV, 0, -1, 0u)
        || !check_probe(0, EIO, -1, 1u)) {
        fprintf(stderr, "FAIL grab probe result or release ownership\n");
        return 1;
    }
    puts("PASS");
    return 0;
}
