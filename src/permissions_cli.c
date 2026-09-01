#include "keysharp_input/client.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct list_context {
    bool wrote_entry;
} list_context;

static void print_usage(FILE *stream)
{
    fprintf(stream,
        "Usage: keysharp-input permissions list [--socket PATH]\n"
        "       keysharp-input permissions revoke "
        "(--hash HASH | --pid PID | --all) "
        "[input-monitoring|input-control|all] [--socket PATH]\n");
}

static const char *scope_text(uint32_t scopes)
{
    switch (scopes & KSI_SCOPE_ALL) {
        case KSI_SCOPE_INPUT_MONITORING:
            return ksi_scope_name(KSI_SCOPE_INPUT_MONITORING);
        case KSI_SCOPE_INPUT_CONTROL:
            return ksi_scope_name(KSI_SCOPE_INPUT_CONTROL);
        case KSI_SCOPE_ALL:
            return "input-monitoring,input-control";
        default:
            return "none";
    }
}

static void print_escaped(const char *value)
{
    for (const unsigned char *cursor = (const unsigned char *)value;
        *cursor != '\0'; cursor++) {
        switch (*cursor) {
            case '\\': fputs("\\\\", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            default: fputc(*cursor, stdout); break;
        }
    }
}

static bool print_entry(const ksi_permission_entry *entry, void *context)
{
    list_context *state = context;

    if (state->wrote_entry) {
        putchar('\n');
    }
    state->wrote_entry = true;
    printf("uid=%lu\n", (unsigned long)getuid());
    printf("hash=%s\n", entry->hash);
    printf("executable=");
    print_escaped(entry->executable);
    printf("\nscopes=%s\n", scope_text(entry->scopes));
    printf("granted_at_utc=%" PRIu64 "\n", entry->granted_at_utc);
    return true;
}

static int connect_service(
    const char *socket_path,
    ksi_connection **connection,
    ksi_error *error)
{
    ksi_connect_options options;

    ksi_connect_options_init(&options);
    options.socket_path = socket_path;
    ksi_status status = ksi_connect(&options, connection, NULL, error);
    if (status != KSI_STATUS_OK) {
        fprintf(stderr, "permissions: %s\n",
            error->message[0] == '\0' ? ksi_status_name(status) : error->message);
        return 1;
    }
    return 0;
}

static int list_main(int argc, char **argv)
{
    const char *socket_path = NULL;
    ksi_connection *connection = NULL;
    ksi_error error;
    list_context context = { 0 };

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc
            && socket_path == NULL) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 && argc == 1) {
            print_usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "permissions list: unexpected argument: %s\n", argv[i]);
            return 2;
        }
    }
    ksi_error_init(&error);
    if (connect_service(socket_path, &connection, &error) != 0) {
        return 1;
    }
    ksi_status status = ksi_permissions_list(
        connection, print_entry, &context, &error);
    ksi_disconnect(connection);
    if (status != KSI_STATUS_OK) {
        fprintf(stderr, "permissions list: %s\n",
            error.message[0] == '\0' ? ksi_status_name(status) : error.message);
        return 1;
    }
    return 0;
}

static uint32_t parse_scope(const char *value)
{
    if (strcmp(value, "input-monitoring") == 0) {
        return KSI_SCOPE_INPUT_MONITORING;
    }
    if (strcmp(value, "input-control") == 0) {
        return KSI_SCOPE_INPUT_CONTROL;
    }
    if (strcmp(value, "all") == 0) {
        return KSI_SCOPE_ALL;
    }
    return 0u;
}

static bool parse_pid(const char *value, uint64_t *pid)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0u) {
        return false;
    }
    *pid = (uint64_t)parsed;
    return true;
}

static bool hash_is_canonical(const char *hash)
{
    if (hash == NULL || strlen(hash) != 64u) {
        return false;
    }
    for (size_t i = 0u; i < 64u; i++) {
        if (!((hash[i] >= '0' && hash[i] <= '9')
                || (hash[i] >= 'a' && hash[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static int revoke_main(int argc, char **argv)
{
    const char *socket_path = NULL;
    ksi_permission_revoke request;
    ksi_connection *connection = NULL;
    ksi_error error;
    bool have_target = false;
    bool have_scope = false;

    ksi_permission_revoke_init(&request);
    request.scopes = KSI_SCOPE_ALL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc
            && socket_path == NULL) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc
            && !have_target) {
            const char *hash = argv[++i];
            if (!hash_is_canonical(hash)) {
                fprintf(stderr, "permissions revoke: HASH must be 64 lowercase hex characters\n");
                return 2;
            }
            memcpy(request.hash, hash, 65u);
            request.target_kind = KSI_PERMISSION_TARGET_HASH;
            have_target = true;
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc
            && !have_target) {
            if (!parse_pid(argv[++i], &request.pid)) {
                fprintf(stderr, "permissions revoke: PID must be a positive integer\n");
                return 2;
            }
            request.target_kind = KSI_PERMISSION_TARGET_PID;
            have_target = true;
        } else if (strcmp(argv[i], "--all") == 0 && !have_target) {
            request.target_kind = KSI_PERMISSION_TARGET_ALL;
            have_target = true;
        } else if (strcmp(argv[i], "--help") == 0 && argc == 1) {
            print_usage(stdout);
            return 0;
        } else if (argv[i][0] != '-' && !have_scope) {
            request.scopes = parse_scope(argv[i]);
            if (request.scopes == 0u) {
                fprintf(stderr, "permissions revoke: unknown scope: %s\n", argv[i]);
                return 2;
            }
            have_scope = true;
        } else {
            fprintf(stderr, "permissions revoke: unexpected or conflicting argument: %s\n",
                argv[i]);
            return 2;
        }
    }
    if (!have_target) {
        fprintf(stderr, "permissions revoke: choose --hash, --pid, or --all\n");
        return 2;
    }
    ksi_error_init(&error);
    if (connect_service(socket_path, &connection, &error) != 0) {
        return 1;
    }
    ksi_status status = ksi_permissions_revoke(connection, &request, &error);
    ksi_disconnect(connection);
    if (status != KSI_STATUS_OK) {
        fprintf(stderr, "permissions revoke: %s\n",
            error.message[0] == '\0' ? ksi_status_name(status) : error.message);
        return 1;
    }
    printf("revoked_scopes=%s\n", scope_text(request.scopes));
    return 0;
}

int permissions_cli_main(int argc, char **argv)
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "list") == 0) {
        return list_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "revoke") == 0) {
        return revoke_main(argc - 2, argv + 2);
    }
    fprintf(stderr, "permissions: unknown command: %s\n", argv[1]);
    print_usage(stderr);
    return 2;
}
