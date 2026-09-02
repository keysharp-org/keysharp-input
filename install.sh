#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV LD_LIBRARY_PATH LD_PRELOAD 2>/dev/null || true

prefix=${PREFIX:-/usr/local}
build_dir=${BUILD_DIR:-build-install}

case "${1:-}" in
    "") ;;
    -h|--help) echo "Usage: sudo ./install.sh"; exit 0 ;;
    *) echo "Usage: sudo ./install.sh" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "Usage: sudo ./install.sh" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$source_dir"

if [ ! -f third_party/keysharp-permissions/CMakeLists.txt ]; then
    echo "keysharp-permissions was not found; initialize the submodule with" >&2
    echo "  git submodule update --init --recursive" >&2
    exit 1
fi

# The install step refreshes the linker cache, creates the permission store, and
# configures udev and the service itself, so there is nothing to do afterwards.
cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix"
cmake --build "$build_dir" --parallel
cmake --install "$build_dir"

uninstaller=$prefix/share/doc/keysharp-input/uninstall.sh
if [ -x "$uninstaller" ]; then
    removal="Remove it with: sudo $uninstaller"
else
    removal="Remove it with this checkout's ./uninstall.sh, which owns /usr/local."
fi
printf '%s\n' "Installed keysharp-input ${prefix}." "$removal"
