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

# CMake's own setup step is deferred because it starts the daemon, which needs the
# client library resolvable and its permission-store directory present. Both are
# arranged below, so setup runs last, in the release installer's order.
cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DKEYSHARP_INPUT_SETUP_ON_INSTALL=OFF
cmake --build "$build_dir" --parallel
cmake --install "$build_dir"

[ ! -x /sbin/ldconfig ] || /sbin/ldconfig
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create \
        "$prefix/lib/tmpfiles.d/keysharp-input-permissions.conf" || true
fi
if ! "$prefix/bin/keysharp-input" daemon --install-input-access; then
    echo "keysharp-input service setup was not completed; run as root:" >&2
    echo "  $prefix/bin/keysharp-input daemon --install-input-access" >&2
    exit 1
fi

uninstaller=$prefix/share/doc/keysharp-input/uninstall.sh
if [ -x "$uninstaller" ]; then
    removal="Remove it with: sudo $uninstaller"
else
    removal="Remove it with this checkout's ./uninstall.sh, which owns /usr/local."
fi
printf '%s\n' "Installed keysharp-input ${prefix}." "$removal"
