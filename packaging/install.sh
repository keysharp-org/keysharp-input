#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV LD_LIBRARY_PATH LD_PRELOAD 2>/dev/null || true

expected_version=0.1.0
expected_protocol_name=keysharp-inputd/windows-input-v1
skip_compatible=false

usage() {
    echo "Usage: sudo ./install.sh [--skip-if-compatible]"
}

is_root_protected_chain() {
    current=$1
    while :; do
        metadata=$(stat -Lc '%u %a' -- "$current" 2>/dev/null) || return 1
        set -- $metadata
        [ "$1" = 0 ] || return 1
        # Multi-user Nix uses a root-owned sticky, group-writable store root.
        # Sticky-bit ownership still prevents build users replacing store paths.
        if [ $((0$2 & 022)) -ne 0 ]; then
            [ "$current" = /nix/store ] \
                && [ $((0$2 & 002)) -eq 0 ] \
                && [ $((0$2 & 01000)) -ne 0 ] \
                || return 1
        fi
        [ "$current" = / ] && break
        current=${current%/*}
        [ -n "$current" ] || current=/
    done
}

is_root_protected_executable() {
    resolved=$(readlink -f -- "$1" 2>/dev/null) || return 1
    [ -f "$resolved" ] && [ -x "$resolved" ] || return 1
    is_root_protected_chain "$1" && is_root_protected_chain "$resolved"
}

is_root_protected_file() {
    resource_resolved=$(readlink -f -- "$1" 2>/dev/null) || return 1
    [ -f "$resource_resolved" ] && [ -s "$resource_resolved" ] || return 1
    is_root_protected_chain "$1" \
        && is_root_protected_chain "$resource_resolved"
}

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

service_configuration_matches() {
    expected_resolved=$1
    service_exec=$2
    service_path=$(printf '%s\n' "$service_exec" \
        | sed -n 's/.*[ {]path=\([^ ;}]*\).*/\1/p' | sed -n '1p')
    service_argv=$(printf '%s\n' "$service_exec" \
        | sed -n 's/.*argv\[\]=\([^;]*\) ;.*/\1/p' | sed -n '1p')
    service_resolved=$(readlink -f -- "$service_path" 2>/dev/null || true)
    [ -n "$service_path" ] \
        && [ "$service_resolved" = "$expected_resolved" ] \
        && [ "$service_argv" = "$service_path --system-service" ]
}

socket_configuration_matches() {
    [ "$1" = "/run/keysharp-inputd/keysharp-inputd.sock (Stream)" ] \
        && [ "$2" = no ] \
        && [ "$3" = 0666 ] \
        && [ "$4" = 0755 ]
}

unit_property() {
    awk -v wanted_section="$2" -v wanted_key="$3" '
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == wanted_section &&
                $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
            value = substr($0, index($0, "=") + 1)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            count++
        }
        END { if (count == 1) print value }
    ' "$1"
}

unit_lacks_property() {
    awk -v wanted_section="$2" -v wanted_key="$3" '
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == wanted_section &&
                $0 ~ "^[[:space:]]*" wanted_key "[[:space:]]*=" {
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
        section == "Service" &&
                $0 ~ "^[[:space:]]*DeviceAllow[[:space:]]*=" {
            value = substr($0, index($0, "=") + 1)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            if (value == "char-input r") input++
            else if (value == "/dev/uinput rw") uinput++
            else invalid = 1
        }
        END { exit invalid || input != 1 || uinput != 1 }
    ' "$1"
}

policy_configuration_matches() {
    [ -s "$1" ] || return 1
    awk '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
        }
        line ~ /^<action[[:space:]]/ {
            action_tags++
            if (inside || line != "<action id=\"org.keysharp.input.grant\">") invalid = 1
            inside = 1
            next
        }
        inside && line == "<message>$(polkit.message)</message>" {
            messages++
            next
        }
        inside && line ~ /^<allow_(any|inactive|active)>/ {
            if (line == "<allow_any>no</allow_any>") allow_any++
            else if (line == "<allow_inactive>no</allow_inactive>") allow_inactive++
            else if (line == "<allow_active>auth_self</allow_active>") allow_active++
            else invalid = 1
            next
        }
        inside && line == "</action>" {
            inside = 0
            closes++
        }
        END {
            if (invalid || inside || action_tags != 1 || closes != 1 ||
                messages != 1 ||
                allow_any != 1 || allow_inactive != 1 || allow_active != 1)
                exit 1
        }
    ' "$1"
}

tmpfiles_configuration_matches() {
    [ -s "$1" ] || return 1
    awk '
        /^[[:space:]]*($|#)/ { next }
        NF == 7 && $1 == "d" && $2 == "/var/lib/keysharp-permissions" && $3 == "0700" && $4 == "root" && $5 == "root" && $6 == "-" && $7 == "-" { persistent_root++; next }
        NF == 7 && $1 == "d" && $2 == "/var/lib/keysharp-permissions/v1" && $3 == "0700" && $4 == "root" && $5 == "root" && $6 == "-" && $7 == "-" { version_root++; next }
        NF == 7 && $1 == "d" && $2 == "/run/keysharp-permissions" && $3 == "0755" && $4 == "root" && $5 == "root" && $6 == "-" && $7 == "-" { runtime_root++; next }
        { invalid = 1 }
        END {
            if (invalid || persistent_root != 1 || version_root != 1 ||
                runtime_root != 1)
                exit 1
        }
    ' "$1"
}

uaccess_configuration_matches() {
    [ -s "$1" ] || return 1
    awk '
        /^[[:space:]]*($|#)/ { next }
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            rule++
            if (rule == 1 && line == "ACTION!=\"add|change\", GOTO=\"keysharp_uaccess_end\"") next
            if (rule == 2 && line == "SUBSYSTEM!=\"input\", GOTO=\"keysharp_uaccess_end\"") next
            if (rule == 3 && line == "ATTRS{name}==\"Keysharp Virtual Input\", TAG+=\"uaccess\"") next
            if (rule == 4 && line == "ATTRS{name}==\"Keysharp Virtual Pointer\", TAG+=\"uaccess\"") next
            if (rule == 5 && line == "LABEL=\"keysharp_uaccess_end\"") next
            invalid = 1
        }
        END { if (invalid || rule != 5) exit 1 }
    ' "$1"
}

archive_service_configuration_matches() {
    [ -s "$1" ] \
        && [ "$(unit_property "$1" Unit Requires)" = keysharp-inputd.socket ] \
        && [ "$(unit_property "$1" Service Type)" = simple ] \
        && [ "$(unit_property "$1" Service ExecStartPre)" \
            = "+/usr/bin/systemd-tmpfiles --create /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf" ] \
        && [ "$(unit_property "$1" Service ExecStart)" \
            = "/usr/local/bin/keysharp-inputd --system-service" ] \
        && [ "$(unit_property "$1" Service NoNewPrivileges)" = yes ] \
        && [ "$(unit_property "$1" Service ProtectSystem)" = strict ] \
        && [ "$(unit_property "$1" Service ReadWritePaths)" \
            = "/var/lib/keysharp-permissions /run/keysharp-permissions" ] \
        && [ "$(unit_property "$1" Service UMask)" = 0077 ] \
        && [ "$(unit_property "$1" Service DevicePolicy)" = closed ] \
        && [ "$(unit_property "$1" Install WantedBy)" = multi-user.target ] \
        && service_device_allow_matches "$1" \
        && unit_lacks_property "$1" Service User \
        && unit_lacks_property "$1" Service Group \
        && unit_lacks_property "$1" Service DynamicUser
}

archive_socket_configuration_matches() {
    [ -s "$1" ] \
        && [ "$(unit_property "$1" Socket ListenStream)" \
            = /run/keysharp-inputd/keysharp-inputd.sock ] \
        && [ "$(unit_property "$1" Socket Accept)" = no ] \
        && [ "$(unit_property "$1" Socket SocketMode)" = 0666 ] \
        && [ "$(unit_property "$1" Socket DirectoryMode)" = 0755 ] \
        && unit_lacks_property "$1" Socket Service
}

installed_resource_is_valid() {
    is_root_protected_file "$2" && "$1" "$2"
}

installation_resources_match() {
    installed_resource_is_valid policy_configuration_matches "$1" \
        && installed_resource_is_valid tmpfiles_configuration_matches "$2" \
        && installed_resource_is_valid uaccess_configuration_matches "$3"
}

installation_complete() {
    installed_path=$1
    installed_resolved=$(readlink -f -- "$installed_path" 2>/dev/null) || return 1
    installed_prefix=${installed_resolved%/bin/keysharp-inputd}
    [ "$installed_prefix" != "$installed_resolved" ] || return 1

    command -v systemctl >/dev/null 2>&1 || return 1
    service_exec=$(systemctl show --property=ExecStart --value \
        keysharp-inputd.service 2>/dev/null || true)
    service_configuration_matches "$installed_resolved" "$service_exec" \
        || return 1
    [ "$(systemctl show --property=LoadState --value \
        keysharp-inputd.socket 2>/dev/null || true)" = loaded ] || return 1
    socket_configuration_matches \
        "$(systemctl show --property=Listen --value \
            keysharp-inputd.socket 2>/dev/null || true)" \
        "$(systemctl show --property=Accept --value \
            keysharp-inputd.socket 2>/dev/null || true)" \
        "$(systemctl show --property=SocketMode --value \
            keysharp-inputd.socket 2>/dev/null || true)" \
        "$(systemctl show --property=DirectoryMode --value \
            keysharp-inputd.socket 2>/dev/null || true)" \
        || return 1

    case "$installed_prefix" in
        /usr|/nix/store/*|/gnu/store/*)
            policy="$installed_prefix/share/polkit-1/actions/org.keysharp.input.policy"
            uaccess_rule="$installed_prefix/lib/udev/rules.d/70-keysharp-inputd-uaccess.rules"
            ;;
        *)
            policy=/usr/share/polkit-1/actions/org.keysharp.input.policy
            uaccess_rule=/etc/udev/rules.d/70-keysharp-inputd-uaccess.rules
            ;;
    esac
    installation_resources_match "$policy" \
        "$installed_prefix/lib/tmpfiles.d/keysharp-input-permissions.conf" \
        "$uaccess_rule"
}

archive_complete() {
    [ -x "$1/bin/keysharp-inputd" ] && [ -s "$1/bin/keysharp-inputd" ] \
        && [ -x "$1/uninstall.sh" ] || return 1
    for archive_relative in LICENSE README.md PROVENANCE.md \
        systemd/keysharp-inputd.service systemd/keysharp-inputd.socket \
        tmpfiles/keysharp-input-permissions.conf \
        polkit/org.keysharp.input.policy \
        udev/70-keysharp-inputd-uaccess.rules \
        include/keysharp-inputd/protocol.h \
        docs/app-identity.md docs/permission-store.md \
        docs/physical-live-tests.md docs/protocol.md; do
        [ -s "$1/$archive_relative" ] || return 1
    done
    policy_configuration_matches "$1/polkit/org.keysharp.input.policy" \
        && tmpfiles_configuration_matches \
            "$1/tmpfiles/keysharp-input-permissions.conf" \
        && uaccess_configuration_matches \
            "$1/udev/70-keysharp-inputd-uaccess.rules" \
        && archive_service_configuration_matches \
            "$1/systemd/keysharp-inputd.service" \
        && archive_socket_configuration_matches \
            "$1/systemd/keysharp-inputd.socket"
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

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-if-compatible) skip_compatible=true ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root" >&2
    exit 1
fi

archive_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! archive_complete "$archive_dir"; then
    echo "The portable keysharp-input archive is incomplete; refusing a partial install." >&2
    exit 1
fi

if [ "$skip_compatible" = true ]; then
    for installed_binary in /usr/bin/keysharp-inputd \
        /run/current-system/sw/bin/keysharp-inputd \
        /usr/local/bin/keysharp-inputd; do
        is_root_protected_executable "$installed_binary" || continue
        installed_info=$("$installed_binary" --info 2>/dev/null || true)
        installed_protocol_name=$(printf '%s\n' "$installed_info" | sed -n 's/^protocol-name=//p')
        installed_major=$(printf '%s\n' "$installed_info" | sed -n 's/^protocol-major=//p')
        installed_minor=$(printf '%s\n' "$installed_info" | sed -n 's/^protocol-minor=//p')

        case "$installed_minor" in
            ''|*[!0-9]*) installed_minor=0 ;;
        esac

        if [ "$installed_protocol_name" = "$expected_protocol_name" ] \
            && [ "$installed_major" = 1 ] && [ "$installed_minor" -eq 2 ] \
            && installation_complete "$installed_binary"; then
            echo "A compatible keysharp-inputd is already installed; leaving it unchanged."
            exit 0
        fi
    done
fi

if layered_install_present; then
    echo "A package-managed or differently rooted keysharp-input installation is present." >&2
    echo "Refusing to layer a portable install over it; repair or upgrade that installation through its owner." >&2
    exit 1
fi

if ! archive_info=$("$archive_dir/bin/keysharp-inputd" --info 2>&1); then
    echo "The portable keysharp-inputd binary cannot run on this host:" >&2
    printf '%s\n' "$archive_info" >&2
    echo "Install its runtime libraries (libudev and libevdev) or use the distribution package." >&2
    exit 1
fi

archive_name=$(printf '%s\n' "$archive_info" | sed -n 's/^name=//p')
archive_version=$(printf '%s\n' "$archive_info" | sed -n 's/^version=//p')
archive_protocol_name=$(printf '%s\n' "$archive_info" | sed -n 's/^protocol-name=//p')
archive_protocol_major=$(printf '%s\n' "$archive_info" | sed -n 's/^protocol-major=//p')
archive_protocol_minor=$(printf '%s\n' "$archive_info" | sed -n 's/^protocol-minor=//p')
if [ "$archive_name" != keysharp-inputd ] \
    || [ "$archive_version" != "$expected_version" ] \
    || [ "$archive_protocol_name" != "$expected_protocol_name" ] \
    || [ "$archive_protocol_major" != 1 ] \
    || [ "$archive_protocol_minor" != 2 ]; then
    echo "The portable archive binary metadata does not match this installer." >&2
    exit 1
fi

if [ ! -x /usr/bin/pkcheck ]; then
    echo "The polkit pkcheck helper is required at /usr/bin/pkcheck; install polkit first." >&2
    exit 1
fi

install -D -m 0755 "$archive_dir/bin/keysharp-inputd" /usr/local/bin/keysharp-inputd
install -D -m 0644 "$archive_dir/systemd/keysharp-inputd.service" /etc/systemd/system/keysharp-inputd.service
install -D -m 0644 "$archive_dir/systemd/keysharp-inputd.socket" /etc/systemd/system/keysharp-inputd.socket
install -D -m 0644 "$archive_dir/tmpfiles/keysharp-input-permissions.conf" \
    /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf
install -D -m 0644 "$archive_dir/polkit/org.keysharp.input.policy" \
    /usr/share/polkit-1/actions/org.keysharp.input.policy
install -D -m 0644 "$archive_dir/include/keysharp-inputd/protocol.h" \
    /usr/local/include/keysharp-inputd/protocol.h
install -D -m 0644 "$archive_dir/LICENSE" /usr/local/share/doc/keysharp-input/LICENSE
install -D -m 0644 "$archive_dir/README.md" /usr/local/share/doc/keysharp-input/README.md
install -D -m 0644 "$archive_dir/PROVENANCE.md" \
    /usr/local/share/doc/keysharp-input/PROVENANCE.md
install -d -m 0755 /usr/local/share/doc/keysharp-input/docs
for documentation_name in app-identity.md permission-store.md \
    physical-live-tests.md protocol.md; do
    install -m 0644 "$archive_dir/docs/$documentation_name" \
        "/usr/local/share/doc/keysharp-input/docs/$documentation_name"
done
install -D -m 0755 "$archive_dir/uninstall.sh" \
    /usr/local/share/doc/keysharp-input/uninstall.sh

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create \
        /usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf
else
    install -d -m 0700 /var/lib/keysharp-permissions \
        /var/lib/keysharp-permissions/v1
    install -d -m 0755 /run/keysharp-permissions
fi

/usr/local/bin/keysharp-inputd --install-input-access
echo "Installed keysharp-input $expected_version."
echo "Uninstall separately with /usr/local/share/doc/keysharp-input/uninstall.sh."
