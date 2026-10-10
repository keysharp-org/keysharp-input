#!/bin/sh
set -eu

library_dir=${1:?library directory is required}
configuration=${2:-/etc/ld.so.conf.d/keysharp-input.conf}

if [ -L "$configuration" ] || [ -e "$configuration" ]; then
    if [ ! -L "$configuration" ] && [ -f "$configuration" ] \
        && printf '%s\n' "$library_dir" | cmp -s - "$configuration"; then
        exit 0
    fi
    echo "Keeping modified $configuration; it must contain only $library_dir. Remove it and rerun the installer to restore library discovery." >&2
    exit 1
fi

install -d -m 0755 "${configuration%/*}"
temporary=$(mktemp "${configuration%/*}/.keysharp-input.conf.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
printf '%s\n' "$library_dir" > "$temporary"
chmod 0644 "$temporary"
mv -- "$temporary" "$configuration"
