#!/bin/sh
set -eu

case "${1:-}" in
    "") ;;
    -h|--help) echo "Usage: sudo ./uninstall.sh"; exit 0 ;;
    *) echo "Usage: sudo ./uninstall.sh" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "Usage: sudo ./uninstall.sh" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must be run as root" >&2
    exit 1
fi
if command -v dpkg-query >/dev/null 2>&1 \
    && dpkg-query -W -f='${db:Status-Abbrev}' keysharp-input 2>/dev/null \
        | grep -q '^ii '; then
    echo "A package-managed keysharp-input is installed; use the package manager to remove it." >&2
    exit 1
fi

systemctl disable --now keysharp-input.service keysharp-input.socket || true
if [ -x /usr/local/bin/keysharp-input ]; then
    /usr/local/bin/keysharp-input daemon --remove-input-access || true
fi

library_payload=
if [ -L /usr/local/lib/libkeysharp-input.so.0 ]; then
    candidate=$(readlink -f -- /usr/local/lib/libkeysharp-input.so.0 2>/dev/null || true)
    case "$candidate" in
        /usr/local/lib/libkeysharp-input.so.0.*)
            if [ -f "$candidate" ] \
                && [ "$(stat -Lc '%u' -- "$candidate" 2>/dev/null || true)" = 0 ]; then
                library_payload=$candidate
            fi
            ;;
    esac
fi

rm -f -- \
    /usr/local/bin/keysharp-input \
    /usr/local/lib/libkeysharp-input.so \
    /usr/local/lib/libkeysharp-input.so.0 \
    /usr/local/lib/libkeysharp-input.so.0.2.0 \
    /usr/local/lib/pkgconfig/keysharp-input.pc \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputConfig.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputConfigVersion.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputTargets.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputTargets-release.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputTargets-relwithdebinfo.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputTargets-minsizerel.cmake \
    /usr/local/lib/cmake/KeysharpInput/KeysharpInputTargets-debug.cmake \
    /usr/local/include/keysharp_input/client.h \
    /usr/local/include/keysharp_input/constants.h \
    /etc/systemd/system/keysharp-input.service \
    /etc/systemd/system/keysharp-input.socket \
    /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf \
    /usr/share/polkit-1/actions/org.keysharp.input.policy \
    /etc/udev/rules.d/70-keysharp-input-uaccess.rules \
    /usr/local/share/doc/keysharp-input/LICENSE \
    /usr/local/share/doc/keysharp-input/README.md \
    /usr/local/share/doc/keysharp-input/PROVENANCE.md \
    /usr/local/share/doc/keysharp-input/docs/app-identity.md \
    /usr/local/share/doc/keysharp-input/docs/integrating.md \
    /usr/local/share/doc/keysharp-input/docs/packaging.md \
    /usr/local/share/doc/keysharp-input/docs/permission-store.md \
    /usr/local/share/doc/keysharp-input/docs/physical-live-tests.md \
    /usr/local/share/doc/keysharp-input/docs/protocol.md \
    /usr/local/share/doc/keysharp-input/docs/security-model.md \
    /usr/local/share/doc/keysharp-input/uninstall.sh
[ -z "$library_payload" ] || rm -f -- "$library_payload"
rmdir --ignore-fail-on-non-empty \
    /usr/local/lib/cmake/KeysharpInput \
    /usr/local/include/keysharp_input \
    /usr/local/share/doc/keysharp-input/docs \
    /usr/local/share/doc/keysharp-input 2>/dev/null || true
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi
systemctl daemon-reload
echo "Removed the portable keysharp-input installation. Shared permission data was kept."
