#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV LD_LIBRARY_PATH LD_PRELOAD 2>/dev/null || true

is_package_managed() {
    managed_path=$1
    managed_resolved=$(readlink -f -- "$managed_path" 2>/dev/null || true)
    if command -v dpkg-query >/dev/null 2>&1 \
        && { dpkg-query -S "$managed_path" >/dev/null 2>&1 \
            || { [ -n "$managed_resolved" ] \
                && dpkg-query -S "$managed_resolved" >/dev/null 2>&1; }; }; then
        return 0
    fi
    if command -v rpm >/dev/null 2>&1 \
        && { rpm -qf "$managed_path" >/dev/null 2>&1 \
            || { [ -n "$managed_resolved" ] \
                && rpm -qf "$managed_resolved" >/dev/null 2>&1; }; }; then
        return 0
    fi
    if command -v pacman >/dev/null 2>&1 \
        && { pacman -Qo "$managed_path" >/dev/null 2>&1 \
            || { [ -n "$managed_resolved" ] \
                && pacman -Qo "$managed_resolved" >/dev/null 2>&1; }; }; then
        return 0
    fi
    return 1
}

is_component_package_installed() {
    if command -v dpkg-query >/dev/null 2>&1 \
        && dpkg-query -W -f='${db:Status-Abbrev}' keysharp-input 2>/dev/null \
            | grep -q '^ii '; then
        return 0
    fi
    command -v rpm >/dev/null 2>&1 && rpm -q keysharp-input >/dev/null 2>&1 \
        && return 0
    command -v pacman >/dev/null 2>&1 && pacman -Q keysharp-input >/dev/null 2>&1 \
        && return 0
    return 1
}

layered_install_present() {
    portable_resolved=$(readlink -f -- /usr/local/bin/keysharp-inputd 2>/dev/null || true)
    for system_binary in /usr/bin/keysharp-inputd \
        /run/current-system/sw/bin/keysharp-inputd; do
        [ -e "$system_binary" ] || [ -L "$system_binary" ] || continue
        system_resolved=$(readlink -f -- "$system_binary" 2>/dev/null || true)
        [ -n "$portable_resolved" ] && [ "$system_resolved" = "$portable_resolved" ] \
            && continue
        return 0
    done
    for managed_path in /usr/local/bin/keysharp-inputd \
        /etc/systemd/system/keysharp-inputd.service \
        /etc/systemd/system/keysharp-inputd.socket \
        /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf \
        /usr/local/include/keysharp-inputd/protocol.h \
        /usr/share/polkit-1/actions/org.keysharp.input.policy; do
        [ -e "$managed_path" ] || [ -L "$managed_path" ] || continue
        is_package_managed "$managed_path" && return 0
    done
    is_component_package_installed
}

case "${1:-}" in
    "") ;;
    -h|--help) echo "Usage: sudo ./uninstall.sh"; exit 0 ;;
    *) echo "Usage: sudo ./uninstall.sh" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must be run as root" >&2
    exit 1
fi

if layered_install_present; then
    echo "Refusing to remove a portable layer while another or package-managed keysharp-input installation is present." >&2
    echo "Remove the other installation first, uninstall this portable copy, then reinstall the desired package." >&2
    exit 1
fi

systemctl disable --now keysharp-inputd.service keysharp-inputd.socket || true

if [ -x /usr/local/bin/keysharp-inputd ]; then
    /usr/local/bin/keysharp-inputd --remove-input-access || true
fi

rm -f -- /usr/local/bin/keysharp-inputd \
    /etc/systemd/system/keysharp-inputd.service \
    /etc/systemd/system/keysharp-inputd.socket \
    /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf \
    /usr/share/polkit-1/actions/org.keysharp.input.policy \
    /usr/local/include/keysharp-inputd/protocol.h \
    /usr/local/share/doc/keysharp-input/LICENSE \
    /usr/local/share/doc/keysharp-input/PROVENANCE.md \
    /usr/local/share/doc/keysharp-input/README.md \
    /usr/local/share/doc/keysharp-input/uninstall.sh \
    /usr/local/share/doc/keysharp-input/docs/app-identity.md \
    /usr/local/share/doc/keysharp-input/docs/permission-store.md \
    /usr/local/share/doc/keysharp-input/docs/physical-live-tests.md \
    /usr/local/share/doc/keysharp-input/docs/protocol.md
rmdir -- \
    /usr/local/include/keysharp-inputd \
    /usr/local/share/doc/keysharp-input/docs \
    /usr/local/share/doc/keysharp-input 2>/dev/null || true
systemctl daemon-reload || true

echo "Removed keysharp-input."
echo "Shared grants in /var/lib/keysharp-permissions were retained; revoke them through a permission CLI."
