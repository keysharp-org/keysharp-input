#ifndef KEYSHARP_INPUT_LINUX_TERMINAL_H
#define KEYSHARP_INPUT_LINUX_TERMINAL_H

#include <keysharp_input/constants.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct ksi_terminal_gate {
    bool (*begin)(void *context);
    bool (*check)(void *context);
    void (*end)(void *context);
    void *context;
} ksi_terminal_gate;

ksi_status ksi_linux_terminal_input(uid_t uid, uint32_t target,
    uint32_t flags, const uint8_t *bytes, uint32_t count,
    const ksi_terminal_gate *gate, uint32_t *accepted, int *system_error);

#endif
