#ifndef KEYSHARP_INPUT_LINUX_WHEEL_H
#define KEYSHARP_INPUT_LINUX_WHEEL_H

#include <stdint.h>

/* Preserve sub-detent movement across events, including direction changes. */
static inline int32_t ksi_linux_wheel_steps(int32_t delta, int32_t *remainder)
{
    int64_t total = (int64_t)delta + *remainder;
    *remainder = (int32_t)(total % 120);
    return (int32_t)(total / 120);
}

#endif
