#ifndef KEYSHARP_INPUT_LINUX_OUTPUT_H
#define KEYSHARP_INPUT_LINUX_OUTPUT_H

#include <linux/input.h>
#include <stddef.h>
#include <stdint.h>

#define KSI_UINPUT_PATH "/dev/uinput"

/* Serializes uinput writes with the grab probe below. */
int ksi_linux_output_write(int fd, const struct input_event *events, size_t count);
/* Output sequencer only, without devices_mutex or output_mutex held. */
void ksi_linux_output_pace(size_t count);
/* Probe an evdev reader without letting the temporary grab consume output
 * written by the sequencer. Returns 1 when another grabber owns the node, 0
 * when it is ungrabbed, and -1 when the probe is inconclusive. */
int ksi_linux_output_probe_grabbed(int fd);
/* Zero when the clock is unavailable. */
uint64_t ksi_linux_monotonic_ms(void);
void ksi_linux_sleep_ns(long nanoseconds);

#endif
