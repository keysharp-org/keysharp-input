#ifndef KEYSHARP_INPUT_OWNED_TEXT_FILE_H
#define KEYSHARP_INPUT_OWNED_TEXT_FILE_H

#include <sys/types.h>

int ksi_ensure_owned_text_file(const char *path, const char *contents,
    uid_t owner, gid_t group, const char *protected_root);

#endif
