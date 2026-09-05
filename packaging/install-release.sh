#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV LD_LIBRARY_PATH LD_PRELOAD 2>/dev/null || true

expected_version=0.2.0
expected_client_abi_major=0
expected_client_abi_minor=2

usage() {
    echo "Usage: sudo ./install.sh [--skip-if-compatible]"
}

skip_if_compatible=false
case "${1:-}" in
    "") ;;
    --skip-if-compatible) skip_if_compatible=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

is_root_protected_chain() {
    current=$1
    while :; do
        metadata=$(stat -Lc '%u %a' -- "$current" 2>/dev/null) || return 1
        # shellcheck disable=SC2086 # deliberate split into uid and mode
        set -- $metadata
        [ "$1" = 0 ] && [ $((0$2 & 022)) -eq 0 ] || return 1
        [ "$current" = / ] && return 0
        current=${current%/*}
        [ -n "$current" ] || current=/
    done
}

is_root_protected_file() {
    resolved=$(readlink -f -- "$1" 2>/dev/null) || return 1
    [ -f "$resolved" ] && [ -s "$resolved" ] || return 1
    is_root_protected_chain "$1" && is_root_protected_chain "$resolved"
}

is_root_protected_executable() {
    is_root_protected_file "$1" && [ -x "$(readlink -f -- "$1")" ]
}

portable_library_payload() {
    link=/usr/local/lib/libkeysharp-input.so.0
    [ -L "$link" ] || return 1
    resolved=$(readlink -f -- "$link" 2>/dev/null) || return 1
    case "$resolved" in
        /usr/local/lib/libkeysharp-input.so.0.*) ;;
        *) return 1 ;;
    esac
    is_root_protected_file "$resolved" || return 1
    printf '%s\n' "$resolved"
}

atomic_install_file() {
    atomic_source=$1
    atomic_destination=$2
    atomic_mode=$3
    atomic_directory=${atomic_destination%/*}
    [ "$atomic_directory" != "$atomic_destination" ] || return 1
    atomic_temporary=$(mktemp "$atomic_directory/.keysharp-install.XXXXXX") \
        || return 1
    if install -m "$atomic_mode" "$atomic_source" "$atomic_temporary" \
        && mv -f -- "$atomic_temporary" "$atomic_destination"; then
        atomic_temporary=
        return 0
    fi
    rm -f -- "$atomic_temporary"
    atomic_temporary=
    return 1
}

atomic_install_symlink() {
    atomic_link_target=$1
    atomic_link_destination=$2
    case "$atomic_link_target" in
        ''|/*|*/*) return 1 ;;
    esac
    atomic_link_directory=${atomic_link_destination%/*}
    [ "$atomic_link_directory" != "$atomic_link_destination" ] || return 1
    atomic_temporary=$(mktemp "$atomic_link_directory/.keysharp-link.XXXXXX") \
        || return 1
    rm -f -- "$atomic_temporary"
    if ln -s -- "$atomic_link_target" "$atomic_temporary" \
        && mv -f -- "$atomic_temporary" "$atomic_link_destination"; then
        atomic_temporary=
        return 0
    fi
    rm -f -- "$atomic_temporary"
    atomic_temporary=
    return 1
}

client_abi_matches() {
    "$1" info 2>/dev/null | awk -F= \
        -v expected_major="$expected_client_abi_major" \
        -v minimum_minor="$expected_client_abi_minor" '
        $1 == "client_abi_major" {
            major_count++
            major = $2
            next
        }
        $1 == "client_abi_minor" {
            minor_count++
            minor = $2
            next
        }
        END {
            if (major_count != 1 || minor_count != 1 ||
                major !~ /^[0-9]+$/ || minor !~ /^[0-9]+$/ ||
                major + 0 != expected_major || minor + 0 < minimum_minor)
                exit 1
        }
    '
}

unit_value() {
    awk -v wanted_section="$2" -v wanted_key="$3" '
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == wanted_section && $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
            value = substr($0, index($0, "=") + 1)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            count++
        }
        END { if (count == 1) print value }
    ' "$1"
}

unit_lacks_key() {
    awk -v wanted_section="$2" -v wanted_key="$3" '
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == wanted_section && $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
            found = 1
        }
        END { exit found ? 1 : 0 }
    ' "$1"
}

service_device_allow_matches() {
    awk '
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == "Service" && $0 ~ "^[[:space:]]*DeviceAllow[[:space:]]*=" {
            value = substr($0, index($0, "=") + 1)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            if (value == "char-input r") input++
            else if (value == "/dev/uinput rw") uinput++
            else invalid = 1
        }
        END { if (invalid || input != 1 || uinput != 1) exit 1 }
    ' "$1"
}

service_configuration_matches() {
    [ "$(unit_value "$1" Unit Requires)" = keysharp-input.socket ] \
        && [ "$(unit_value "$1" Service Type)" = simple ] \
        && [ "$(unit_value "$1" Service ExecStart)" \
            = "$2 daemon --system-service" ] \
        && [ "$(unit_value "$1" Service ExecStartPre)" \
            = "+/usr/bin/systemd-tmpfiles --create $3" ] \
        && [ "$(unit_value "$1" Service NoNewPrivileges)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectClock)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectControlGroups)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectKernelLogs)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectKernelModules)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectKernelTunables)" = yes ] \
        && [ "$(unit_value "$1" Service ProtectSystem)" = strict ] \
        && [ "$(unit_value "$1" Service ReadWritePaths)" \
            = "/var/lib/keysharp-permissions /run/keysharp-permissions" ] \
        && [ "$(unit_value "$1" Service UMask)" = 0077 ] \
        && [ "$(unit_value "$1" Service DevicePolicy)" = closed ] \
        && [ "$(unit_value "$1" Install WantedBy)" = multi-user.target ] \
        && service_device_allow_matches "$1" \
        && unit_lacks_key "$1" Service User \
        && unit_lacks_key "$1" Service Group \
        && unit_lacks_key "$1" Service DynamicUser
}

socket_configuration_matches() {
    [ "$(unit_value "$1" Socket ListenStream)" \
        = /run/keysharp-input/keysharp-input.sock ] \
        && [ "$(unit_value "$1" Socket Accept)" = no ] \
        && [ "$(unit_value "$1" Socket SocketMode)" = 0666 ] \
        && [ "$(unit_value "$1" Socket DirectoryMode)" = 0755 ] \
        && [ "$(unit_value "$1" Install WantedBy)" = sockets.target ]
}

tmpfiles_configuration_matches() {
    awk '
        /^[[:space:]]*($|#)/ { next }
        NF == 7 && $1 == "d" && $2 == "/var/lib/keysharp-permissions" &&
            $3 == "0700" && $4 == "root" && $5 == "root" &&
            $6 == "-" && $7 == "-" { persistent_root++; next }
        NF == 7 && $1 == "d" && $2 == "/var/lib/keysharp-permissions/v1" &&
            $3 == "0700" && $4 == "root" && $5 == "root" &&
            $6 == "-" && $7 == "-" { version_root++; next }
        NF == 7 && $1 == "d" && $2 == "/run/keysharp-permissions" &&
            $3 == "0755" && $4 == "root" && $5 == "root" &&
            $6 == "-" && $7 == "-" { runtime_root++; next }
        { invalid = 1 }
        END {
            if (invalid || persistent_root != 1 || version_root != 1 ||
                runtime_root != 1)
                exit 1
        }
    ' "$1"
}

policy_configuration_matches() {
    awk '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
        }
        line ~ /^<action[[:space:]]/ {
            action_tags++
            if (inside || line != "<action id=\"org.keysharp.input.grant\">")
                invalid = 1
            inside = 1
            next
        }
        inside && line ~ /^<allow_(any|inactive|active)>/ {
            if (line == "<allow_any>no</allow_any>") allow_any++
            else if (line == "<allow_inactive>no</allow_inactive>") allow_inactive++
            else if (line == "<allow_active>auth_self</allow_active>") allow_active++
            else invalid = 1
            next
        }
        inside && line ~ /^<message>/ {
            if (line == "<message>$(polkit.message)</message>") messages++
            else invalid = 1
            next
        }
        inside && line == "</action>" {
            inside = 0
            closes++
        }
        END {
            if (invalid || inside || action_tags != 1 || closes != 1 ||
                messages != 1 || allow_any != 1 || allow_inactive != 1 ||
                allow_active != 1)
                exit 1
        }
    ' "$1"
}

udev_configuration_matches() {
    awk '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
        }
        line == "" || line ~ /^#/ { next }
        line == "ACTION!=\"add|change\", GOTO=\"keysharp_uaccess_end\"" {
            action++; next
        }
        line == "SUBSYSTEM!=\"input\", GOTO=\"keysharp_uaccess_end\"" {
            subsystem++; next
        }
        line == "ATTRS{name}==\"Keysharp Virtual Input\", TAG+=\"uaccess\"" {
            keyboard++; next
        }
        line == "ATTRS{name}==\"Keysharp Virtual Pointer\", TAG+=\"uaccess\"" {
            pointer++; next
        }
        line == "LABEL=\"keysharp_uaccess_end\"" { label++; next }
        { invalid = 1 }
        END {
            if (invalid || action != 1 || subsystem != 1 || keyboard != 1 ||
                pointer != 1 || label != 1)
                exit 1
        }
    ' "$1"
}

first_existing_path() {
    for candidate in "$@"; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

installed_debian_provider_satisfies() {
    required=$1
    command -v dpkg-query >/dev/null 2>&1 || return 1
    dpkg-query -W -f='${db:Status-Abbrev}|${Provides}\n' 2>/dev/null | awk \
        -F '|' -v required="$required" '
        $1 == "ii " {
            count = split($2, provided, ",")
            for (i = 1; i <= count; i++) {
                value = provided[i]
                sub(/^[[:space:]]*/, "", value)
                sub(/[[:space:]]*$/, "", value)
                sub(/[[:space:]]*\(.*/, "", value)
                if (value == required)
                    found = 1
            }
        }
        END { exit found ? 0 : 1 }
    '
}

installation_complete_for_channel() {
    channel=$1
    case "$channel" in
        package)
            binary=/usr/bin/keysharp-input
            library=$(first_existing_path \
                /usr/lib/libkeysharp-input.so.0 \
                /usr/lib64/libkeysharp-input.so.0 \
                /usr/lib/x86_64-linux-gnu/libkeysharp-input.so.0 \
                /usr/lib/aarch64-linux-gnu/libkeysharp-input.so.0) || return 1
            service=$(first_existing_path \
                /usr/lib/systemd/system/keysharp-input.service \
                /lib/systemd/system/keysharp-input.service) || return 1
            socket=$(first_existing_path \
                /usr/lib/systemd/system/keysharp-input.socket \
                /lib/systemd/system/keysharp-input.socket) || return 1
            tmpfiles=/usr/lib/tmpfiles.d/keysharp-input-permissions.conf
            policy=/usr/share/polkit-1/actions/org.keysharp.input.policy
            udev=$(first_existing_path \
                /usr/lib/udev/rules.d/70-keysharp-input-uaccess.rules \
                /lib/udev/rules.d/70-keysharp-input-uaccess.rules) || return 1
            ;;
        portable)
            binary=/usr/local/bin/keysharp-input
            library=$(first_existing_path \
                /usr/local/lib/libkeysharp-input.so.0 \
                /usr/local/lib64/libkeysharp-input.so.0 \
                /usr/local/lib/x86_64-linux-gnu/libkeysharp-input.so.0 \
                /usr/local/lib/aarch64-linux-gnu/libkeysharp-input.so.0) \
                || return 1
            service=/etc/systemd/system/keysharp-input.service
            socket=/etc/systemd/system/keysharp-input.socket
            tmpfiles=/usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf
            policy=/usr/share/polkit-1/actions/org.keysharp.input.policy
            udev=/etc/udev/rules.d/70-keysharp-input-uaccess.rules
            ;;
        *) return 1 ;;
    esac

    is_root_protected_executable "$binary" \
        && is_root_protected_file "$library" \
        && is_root_protected_file "$service" \
        && is_root_protected_file "$socket" \
        && is_root_protected_file "$tmpfiles" \
        && is_root_protected_file "$policy" \
        && is_root_protected_file "$udev" \
        && client_abi_matches "$binary" \
        && service_configuration_matches "$service" "$binary" "$tmpfiles" \
        && socket_configuration_matches "$socket" \
        && tmpfiles_configuration_matches "$tmpfiles" \
        && policy_configuration_matches "$policy" \
        && udev_configuration_matches "$udev"
}

archive_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
for required in \
    bin/keysharp-input \
    lib/libkeysharp-input.so.0.2.0 \
    include/keysharp_input/client.h \
    include/keysharp_input/constants.h \
    include/keysharp_input/devices.h \
    pkgconfig/keysharp-input.pc \
    cmake/KeysharpInputConfig.cmake \
    cmake/KeysharpInputConfigVersion.cmake \
    cmake/KeysharpInputTargets.cmake \
    cmake/KeysharpInputTargets-release.cmake \
    systemd/keysharp-input.service \
    systemd/keysharp-input.socket \
    tmpfiles/keysharp-input-permissions.conf \
    polkit/org.keysharp.input.policy \
    udev/70-keysharp-input-uaccess.rules \
    uninstall.sh LICENSE README.md; do
    if [ ! -s "$archive_dir/$required" ]; then
        echo "Portable archive is incomplete: $required is missing." >&2
        exit 1
    fi
done

if installed_debian_provider_satisfies keysharp-input-client-abi-0; then
    if $skip_if_compatible && installation_complete_for_channel package; then
        echo "Compatible package-managed keysharp-input provider is already installed."
        exit 0
    fi
    echo "A package-managed keysharp-input client ABI provider is installed; use the package manager to update it." >&2
    exit 1
fi

if installation_complete_for_channel package; then
    if $skip_if_compatible; then
        echo "Compatible system keysharp-input client ABI is already installed."
        exit 0
    fi
    echo "A compatible system keysharp-input installation exists; use its installation channel to update it." >&2
    exit 1
fi

if $skip_if_compatible && installation_complete_for_channel portable; then
    echo "Compatible portable keysharp-input client ABI is already installed."
    exit 0
fi

sh "$archive_dir/check-runtime.sh" --install
previous_library=$(portable_library_payload || true)
install -d -m 0755 /usr/local/bin /usr/local/lib
atomic_temporary=
cleanup_install_temporary() {
    [ -z "$atomic_temporary" ] || rm -f -- "$atomic_temporary"
}
trap cleanup_install_temporary EXIT HUP INT TERM
atomic_install_file "$archive_dir/lib/libkeysharp-input.so.0.2.0" \
    /usr/local/lib/libkeysharp-input.so.0.2.0 0755
atomic_install_symlink libkeysharp-input.so.0.2.0 \
    /usr/local/lib/libkeysharp-input.so.0
atomic_install_symlink libkeysharp-input.so.0 \
    /usr/local/lib/libkeysharp-input.so
atomic_install_file "$archive_dir/bin/keysharp-input" \
    /usr/local/bin/keysharp-input 0755
current_library=$(portable_library_payload) || {
    echo "Installed keysharp-input client library is invalid." >&2
    exit 1
}
if [ -n "$previous_library" ] \
    && [ "$previous_library" != "$current_library" ]; then
    rm -f -- "$previous_library"
fi
install -D -m 0644 "$archive_dir/include/keysharp_input/client.h" \
    /usr/local/include/keysharp_input/client.h
install -D -m 0644 "$archive_dir/include/keysharp_input/constants.h" \
    /usr/local/include/keysharp_input/constants.h
install -D -m 0644 "$archive_dir/include/keysharp_input/devices.h" \
    /usr/local/include/keysharp_input/devices.h
install -D -m 0644 "$archive_dir/pkgconfig/keysharp-input.pc" \
    /usr/local/lib/pkgconfig/keysharp-input.pc
for metadata in KeysharpInputConfig.cmake KeysharpInputConfigVersion.cmake \
    KeysharpInputTargets.cmake KeysharpInputTargets-release.cmake; do
    install -D -m 0644 "$archive_dir/cmake/$metadata" \
        "/usr/local/lib/cmake/KeysharpInput/$metadata"
done
install -D -m 0644 "$archive_dir/systemd/keysharp-input.service" \
    /etc/systemd/system/keysharp-input.service
install -D -m 0644 "$archive_dir/systemd/keysharp-input.socket" \
    /etc/systemd/system/keysharp-input.socket
install -D -m 0644 "$archive_dir/tmpfiles/keysharp-input-permissions.conf" \
    /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf
install -D -m 0644 "$archive_dir/polkit/org.keysharp.input.policy" \
    /usr/share/polkit-1/actions/org.keysharp.input.policy
install -D -m 0644 "$archive_dir/udev/70-keysharp-input-uaccess.rules" \
    /etc/udev/rules.d/70-keysharp-input-uaccess.rules
install -D -m 0644 "$archive_dir/LICENSE" \
    /usr/local/share/doc/keysharp-input/LICENSE
install -D -m 0644 "$archive_dir/README.md" \
    /usr/local/share/doc/keysharp-input/README.md
install -D -m 0755 "$archive_dir/uninstall.sh" \
    /usr/local/share/doc/keysharp-input/uninstall.sh

if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create \
        /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf
fi
systemctl daemon-reload
/usr/local/bin/keysharp-input daemon --install-input-access
echo "Installed keysharp-input $expected_version."
