#ifndef KEYSHARP_INPUT_PROTOCOL_INTERNAL_H
#define KEYSHARP_INPUT_PROTOCOL_INTERNAL_H

#include <keysharp_permissions/permissions.h>

/* These bits describe work already admitted by the daemon. They never cross
 * the client protocol boundary. */
#define KSI_INTERNAL_SYNTH_BATCH_FRAGMENT 0x00000002u
#define KSI_INTERNAL_SYNTH_REPLAY 0x00000004u
#define KSI_INTERNAL_SYNTH_BATCH_START 0x00000008u
#define KSI_INPUT_PERMISSION_SCOPES \
    ((uint32_t)KSP_SCOPE_INPUT_MONITORING \
        | (uint32_t)KSP_SCOPE_INPUT_CONTROL)

#endif
