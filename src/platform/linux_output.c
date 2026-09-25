#include "linux_output.h"

#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* uinput has no backpressure: a reader whose evdev buffer overflows gets
 * SYN_DROPPED and loses events. Yield during sustained output; an idle gap
 * means readers have drained, so isolated events never sleep. */
#define KSI_OUTPUT_PACE_EVENTS 16u
#define KSI_OUTPUT_IDLE_NS 8000000u
#define KSI_OUTPUT_PAUSE_NS 350000L

static size_t paced_events;
static uint64_t last_emit_ns;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

int ksi_linux_output_write(int fd, const struct input_event *events, size_t count)
{
    ssize_t written;

    pthread_mutex_lock(&output_mutex);
    /* uinput writes never return EAGAIN; only EINTR is retried. */
    do {
        written = write(fd, events, count * sizeof(*events));
    } while (written < 0 && errno == EINTR);
    pthread_mutex_unlock(&output_mutex);
    return written == (ssize_t)(count * sizeof(*events)) ? 0 : -1;
}

void ksi_linux_output_pace(size_t count)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        uint64_t ns = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
        if (last_emit_ns != 0u && ns - last_emit_ns >= KSI_OUTPUT_IDLE_NS)
            paced_events = 0u;
        last_emit_ns = ns;
    }
    paced_events += count;
    if (paced_events < KSI_OUTPUT_PACE_EVENTS) return;
    ksi_linux_sleep_ns(KSI_OUTPUT_PAUSE_NS);
    paced_events = 0u;
}

uint64_t ksi_linux_monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0u;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

void ksi_linux_sleep_ns(long nanoseconds)
{
    struct timespec pause = { .tv_sec = nanoseconds / 1000000000L,
        .tv_nsec = nanoseconds % 1000000000L }, remaining;
    while (clock_nanosleep(CLOCK_MONOTONIC, 0, &pause, &remaining) == EINTR)
        pause = remaining;
}

int ksi_linux_output_probe_grabbed(int fd)
{
    pthread_mutex_lock(&output_mutex);
    int result = ioctl(fd, EVIOCGRAB, 1) == 0 ? 0 : errno == EBUSY ? 1 : -1;
    if (result == 0) (void)ioctl(fd, EVIOCGRAB, 0);
    pthread_mutex_unlock(&output_mutex);
    return result;
}
