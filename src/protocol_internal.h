#ifndef KEYSHARP_INPUT_PROTOCOL_INTERNAL_H
#define KEYSHARP_INPUT_PROTOCOL_INTERNAL_H

#include <keysharp_permissions/permissions.h>

#include <stdint.h>

/* These bits describe work already admitted by the daemon. They never cross
 * the client protocol boundary. */
#define KSI_INTERNAL_SYNTH_BATCH_FRAGMENT 0x00000002u
#define KSI_INTERNAL_SYNTH_REPLAY 0x00000004u
#define KSI_INTERNAL_SYNTH_BATCH_START 0x00000008u
/* Readiness of the second uinput device (ABS_X/ABS_Y). Deliberately outside the
 * public KSI_OPERATION_ALL range: it is only ever OR-ed into
 * ksi_daemon_state.ready_operations, never into the advertised
 * available_operations, so the HELLO mask on the wire is unchanged and a client
 * built against an older constants.h still accepts the handshake. The relative
 * device can be created while the absolute one fails (an older kernel rejecting
 * UI_ABS_SETUP, fd exhaustion); without this bit an absolute MouseMove was
 * accepted with STATUS_OK and then dropped inside the backend. */
#define KSI_INTERNAL_OPERATION_SYNTHESIZE_MOUSE_ABSOLUTE \
    UINT64_C(0x8000000000000000)
#define KSI_INPUT_PERMISSION_SCOPES \
    ((uint32_t)KSP_SCOPE_INPUT_MONITORING \
        | (uint32_t)KSP_SCOPE_INPUT_CONTROL)

#endif
