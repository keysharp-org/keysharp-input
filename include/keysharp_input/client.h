#ifndef KEYSHARP_INPUT_CLIENT_H
#define KEYSHARP_INPUT_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <keysharp_input/constants.h>

#if defined(_WIN32)
#  if defined(KEYSHARP_INPUT_CLIENT_BUILD)
#    define KSI_API __declspec(dllexport)
#  else
#    define KSI_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define KSI_API __attribute__((visibility("default")))
#else
#  define KSI_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_CLIENT_ABI_MAJOR 0u
#define KSI_CLIENT_ABI_MINOR 1u
#define KSI_DEFAULT_SOCKET_PATH "/run/keysharp-input/keysharp-input.sock"
#define KSI_SOCKET_ENV "KEYSHARP_INPUT_SOCKET"

#define KSI_ERROR_MESSAGE_CAPACITY 256u
#define KSI_PERMISSION_HASH_HEX_SIZE 65u
#define KSI_EXECUTABLE_PATH_SIZE 4096u
#define KSI_DEFAULT_REQUEST_TIMEOUT_MS 130000u
typedef struct ksi_connection ksi_connection;

typedef struct ksi_error {
    uint32_t struct_size;
    uint32_t detail;
    int32_t system_error;
    uint32_t reserved0;
    char message[KSI_ERROR_MESSAGE_CAPACITY];
    uint64_t reserved[4];
} ksi_error;

typedef struct ksi_connect_options {
    uint32_t struct_size;
    uint32_t role;
    uint32_t authorization_mode;
    uint32_t requested_scopes;
    const char *socket_path;
    uint32_t timeout_ms;
    uint32_t flags;
    uint64_t reserved[4];
} ksi_connect_options;

typedef struct ksi_service_info {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t granted_scopes;
    uint64_t available_operations;
    uint64_t reserved[4];
} ksi_service_info;

typedef struct ksi_permission_entry {
    uint32_t struct_size;
    uint32_t scopes;
    uint64_t granted_at_utc;
    char hash[KSI_PERMISSION_HASH_HEX_SIZE];
    char executable[KSI_EXECUTABLE_PATH_SIZE];
    uint8_t reserved[7];
    uint64_t reserved64[4];
} ksi_permission_entry;

typedef struct ksi_permission_revoke {
    uint32_t struct_size;
    uint32_t target_kind;
    uint32_t scopes;
    uint32_t reserved0;
    uint64_t pid;
    char hash[KSI_PERMISSION_HASH_HEX_SIZE];
    uint8_t reserved1[7];
    uint64_t reserved[4];
} ksi_permission_revoke;

/* Return true to continue. False drains the response and returns CANCELLED. */
typedef bool (*ksi_permission_visitor)(
    const ksi_permission_entry *entry,
    void *context);

KSI_API uint32_t ksi_client_abi_major(void);
KSI_API uint32_t ksi_client_abi_minor(void);
KSI_API const char *ksi_client_product_name(void);
KSI_API const char *ksi_client_product_version(void);
KSI_API const char *ksi_status_name(ksi_status status);
KSI_API const char *ksi_scope_name(ksi_permission_scopes scope);
KSI_API void ksi_connect_options_init(ksi_connect_options *options);
KSI_API void ksi_error_init(ksi_error *error);
KSI_API void ksi_service_info_init(ksi_service_info *service_info);
KSI_API void ksi_permission_entry_init(ksi_permission_entry *entry);
KSI_API void ksi_permission_revoke_init(ksi_permission_revoke *request);

KSI_API ksi_status ksi_connect(
    const ksi_connect_options *options,
    ksi_connection **connection,
    ksi_service_info *service_info,
    ksi_error *error);
KSI_API void ksi_disconnect(ksi_connection *connection);
KSI_API ksi_status ksi_authorize(
    ksi_connection *connection,
    ksi_authorization_mode authorization_mode,
    ksi_permission_scopes requested_scopes,
    ksi_permission_scopes *granted_scopes,
    ksi_error *error);
KSI_API ksi_status ksi_ping(ksi_connection *connection, ksi_error *error);
KSI_API ksi_permission_scopes ksi_connection_granted_scopes(
    const ksi_connection *connection);
KSI_API ksi_operations ksi_connection_available_operations(
    const ksi_connection *connection);

KSI_API ksi_status ksi_permissions_list(
    ksi_connection *connection,
    ksi_permission_visitor visitor,
    void *context,
    ksi_error *error);
KSI_API ksi_status ksi_permissions_revoke(
    ksi_connection *connection,
    const ksi_permission_revoke *request,
    ksi_error *error);

/* Waits for a revocation on an authorization-lease connection. A timeout of
 * UINT32_MAX waits indefinitely. */
KSI_API ksi_status ksi_lease_next(
    ksi_connection *connection,
    uint32_t timeout_ms,
    ksi_permission_scopes *revoked_scopes,
    ksi_error *error);
KSI_API ksi_permission_scopes ksi_lease_granted_scopes(
    const ksi_connection *connection);

typedef struct ksi_keyboard_input {
    uint16_t vk;
    uint16_t scan;
    uint32_t flags;
    uint32_t time;
    uint32_t reserved0;
    uint64_t extra_info;
    uint64_t reserved[2];
} ksi_keyboard_input;

typedef struct ksi_mouse_input {
    int32_t dx;
    int32_t dy;
    uint32_t mouse_data;
    uint32_t flags;
    uint32_t time;
    uint32_t reserved0;
    uint64_t extra_info;
    uint64_t reserved[2];
} ksi_mouse_input;

typedef struct ksi_input {
    uint32_t struct_size;
    uint32_t type;
    union {
        ksi_keyboard_input keyboard;
        ksi_mouse_input mouse;
    } data;
    uint64_t reserved[2];
} ksi_input;

typedef struct ksi_keyboard_hook_event {
    uint32_t message;
    uint32_t vk_code;
    uint32_t scan_code;
    uint32_t flags;
    uint64_t time_ms;
    uint64_t extra_info;
    uint32_t device_id;
    uint32_t reserved0;
} ksi_keyboard_hook_event;

typedef struct ksi_mouse_hook_event {
    uint32_t message;
    int32_t x;
    int32_t y;
    uint32_t mouse_data;
    uint32_t flags;
    uint32_t reserved0;
    uint64_t time_ms;
    uint64_t extra_info;
    uint32_t device_id;
    int32_t delta_x;
    int32_t delta_y;
    uint32_t reserved1;
} ksi_mouse_hook_event;

typedef struct ksi_hook_event {
    uint32_t struct_size;
    uint32_t hook_type;
    uint64_t request_id;
    union {
        ksi_keyboard_hook_event keyboard;
        ksi_mouse_hook_event mouse;
    } event;
    uint64_t reserved[4];
} ksi_hook_event;

typedef struct ksi_hook_reply {
    uint32_t struct_size;
    uint32_t decision;
    const ksi_input *inputs;
    uint32_t input_count;
    uint32_t reserved0;
    uint64_t reserved[4];
} ksi_hook_reply;

typedef struct ksi_hook_quarantined {
    uint32_t struct_size;
    uint32_t hook_type;
    uint32_t reason;
    uint32_t generation;
    uint64_t event_id;
    uint32_t strike_count;
    uint32_t retry_after_ms;
    uint64_t reserved[4];
} ksi_hook_quarantined;

typedef uint32_t ksi_hook_message_kind;
enum {
    KSI_HOOK_MESSAGE_EVENT = 1u,
    KSI_HOOK_MESSAGE_QUARANTINED = 2u,
    KSI_HOOK_MESSAGE_SESSION_REVOKED = 3u,
};

typedef struct ksi_hook_message {
    uint32_t struct_size;
    uint32_t kind;
    union {
        ksi_hook_event event;
        ksi_hook_quarantined quarantined;
        ksi_permission_scopes revoked_scopes;
    } data;
    uint64_t reserved[4];
} ksi_hook_message;

typedef ksi_status (*ksi_nested_hook_handler)(
    ksi_connection *connection,
    const ksi_hook_event *event,
    ksi_hook_reply *reply,
    void *context,
    ksi_error *error);

KSI_API ksi_status ksi_set_nested_hook_handler(
    ksi_connection *connection,
    ksi_nested_hook_handler handler,
    void *context,
    ksi_error *error);
KSI_API ksi_status ksi_hook_subscribe(
    ksi_connection *connection,
    ksi_hook_type hook_type,
    ksi_operations *active_operations,
    ksi_error *error);
KSI_API ksi_status ksi_hook_unsubscribe(
    ksi_connection *connection,
    ksi_hook_type hook_type,
    ksi_operations *active_operations,
    ksi_error *error);
KSI_API ksi_status ksi_hook_next(
    ksi_connection *connection,
    uint32_t timeout_ms,
    ksi_hook_message *message,
    ksi_error *error);
KSI_API ksi_status ksi_hook_reply_event(
    ksi_connection *connection,
    const ksi_hook_event *event,
    const ksi_hook_reply *reply,
    ksi_error *error);
KSI_API ksi_status ksi_synthesize(
    ksi_connection *connection,
    const ksi_input *inputs,
    uint32_t input_count,
    uint32_t flags,
    ksi_error *error);
KSI_API ksi_status ksi_set_block_input(
    ksi_connection *connection,
    uint32_t block_mask,
    uint32_t *effective_mask,
    ksi_error *error);

typedef struct ksi_indicator_state {
    uint32_t struct_size;
    uint8_t caps_lock;
    uint8_t num_lock;
    uint8_t scroll_lock;
    uint8_t reserved0;
    uint64_t reserved[2];
} ksi_indicator_state;

typedef struct ksi_pointer_position {
    uint32_t struct_size;
    uint8_t valid;
    uint8_t reserved0[3];
    int32_t x;
    int32_t y;
    int32_t x_min;
    int32_t x_max;
    int32_t y_min;
    int32_t y_max;
    uint64_t reserved[2];
} ksi_pointer_position;

typedef struct ksi_key_state {
    uint32_t struct_size;
    uint32_t modifiers_lr;
    uint8_t caps_lock;
    uint8_t num_lock;
    uint8_t scroll_lock;
    uint8_t reserved0;
    uint8_t logical_keys[KSI_KEY_STATE_BITMAP_BYTES];
    uint8_t physical_keys[KSI_KEY_STATE_BITMAP_BYTES];
    uint64_t reserved[2];
} ksi_key_state;

typedef struct ksi_pointer_buttons {
    uint32_t struct_size;
    uint8_t valid;
    uint8_t reserved0[3];
    uint32_t logical_buttons;
    uint32_t physical_buttons;
    uint64_t reserved[2];
} ksi_pointer_buttons;

typedef struct ksi_idle_time {
    uint32_t struct_size;
    uint8_t valid;
    uint8_t reserved0[3];
    uint64_t idle_time_ms;
    uint64_t reserved[2];
} ksi_idle_time;

typedef struct ksi_modifier_state {
    uint32_t struct_size;
    uint32_t logical_modifiers_lr;
    uint32_t physical_modifiers_lr;
    uint8_t caps_lock;
    uint8_t num_lock;
    uint8_t scroll_lock;
    uint8_t reserved0;
    uint64_t reserved[2];
} ksi_modifier_state;

KSI_API void ksi_input_init(ksi_input *input);
KSI_API void ksi_hook_event_init(ksi_hook_event *event);
KSI_API void ksi_hook_reply_init(ksi_hook_reply *reply);
KSI_API void ksi_hook_quarantined_init(ksi_hook_quarantined *event);
KSI_API void ksi_hook_message_init(ksi_hook_message *message);
KSI_API void ksi_indicator_state_init(ksi_indicator_state *state);
KSI_API void ksi_pointer_position_init(ksi_pointer_position *position);
KSI_API void ksi_key_state_init(ksi_key_state *state);
KSI_API void ksi_pointer_buttons_init(ksi_pointer_buttons *buttons);
KSI_API void ksi_idle_time_init(ksi_idle_time *idle_time);
KSI_API void ksi_modifier_state_init(ksi_modifier_state *state);

KSI_API ksi_status ksi_get_indicator_state(
    ksi_connection *connection,
    ksi_indicator_state *state,
    ksi_error *error);
KSI_API ksi_status ksi_get_pointer_position(
    ksi_connection *connection,
    ksi_pointer_position *position,
    ksi_error *error);
KSI_API ksi_status ksi_get_key_state(
    ksi_connection *connection,
    ksi_key_state *state,
    ksi_error *error);
KSI_API ksi_status ksi_get_pointer_buttons(
    ksi_connection *connection,
    ksi_pointer_buttons *buttons,
    ksi_error *error);
KSI_API ksi_status ksi_get_idle_time(
    ksi_connection *connection,
    ksi_idle_time *idle_time,
    ksi_error *error);
KSI_API ksi_status ksi_get_modifier_state(
    ksi_connection *connection,
    ksi_modifier_state *state,
    ksi_error *error);

/* A connection is used by one thread at a time. The nested-hook callback is
 * the sole reentrant path: it may call this API on the same connection before
 * returning. Event and reply pointers are borrowed only for the duration of
 * the call that receives or sends them. */

#ifdef __cplusplus
}
#endif

#endif
