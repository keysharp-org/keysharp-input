#!/bin/sh
set -eu

source_dir=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

sed '/^while \[ "$#" -gt 0 \]; do/,$d' \
    "$source_dir/packaging/install.sh" > "$temporary/functions.sh"
. "$temporary/functions.sh"

binary="$temporary/keysharp-inputd"
: > "$binary"
chmod 0755 "$binary"
resolved=$(readlink -f -- "$binary")
valid_exec="{ path=$binary ; argv[]=$binary --system-service ; ignore_errors=no ; }"

service_configuration_matches "$resolved" "$valid_exec"
! service_configuration_matches "$resolved" \
    "{ path=$binary ; argv[]=$binary ; ignore_errors=no ; }"
! service_configuration_matches "$resolved" \
    "{ path=$binary ; argv[]=$binary --system-service extra ; ignore_errors=no ; }"
! service_configuration_matches "$resolved" \
    "{ path=/usr/bin/false ; argv[]=/usr/bin/false --system-service ; ignore_errors=no ; }"

socket_configuration_matches \
    "/run/keysharp-inputd/keysharp-inputd.sock (Stream)" no 0666 0755
! socket_configuration_matches "/tmp/input.sock (Stream)" no 0666 0755
! socket_configuration_matches \
    "/run/keysharp-inputd/keysharp-inputd.sock (Datagram)" no 0666 0755
! socket_configuration_matches \
    "/run/keysharp-inputd/keysharp-inputd.sock (Stream)" yes 0666 0755
! socket_configuration_matches \
    "/run/keysharp-inputd/keysharp-inputd.sock (Stream)" no 0600 0755
! socket_configuration_matches \
    "/run/keysharp-inputd/keysharp-inputd.sock (Stream)" no 0666 0777

resource_root=$temporary/resources
mkdir -p "$resource_root/bin" "$resource_root/systemd" \
    "$resource_root/tmpfiles" "$resource_root/polkit" \
    "$resource_root/udev" "$resource_root/include/keysharp-inputd" \
    "$resource_root/docs"

cp "$source_dir/polkit/org.keysharp.input.policy" \
    "$resource_root/polkit/org.keysharp.input.policy"
cp "$source_dir/systemd/keysharp-input-permissions.conf" \
    "$resource_root/tmpfiles/keysharp-input-permissions.conf"
cp "$source_dir/udev/70-keysharp-inputd-uaccess.rules" \
    "$resource_root/udev/70-keysharp-inputd-uaccess.rules"
sed -e 's|@CMAKE_INSTALL_FULL_BINDIR@|/usr/local/bin|g' \
    -e 's|@KEYSHARP_INPUTD_TMPFILES_CONFIG@|/usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf|g' \
    "$source_dir/systemd/keysharp-inputd.service.in" \
    > "$resource_root/systemd/keysharp-inputd.service"
cp "$source_dir/systemd/keysharp-inputd.socket" \
    "$resource_root/systemd/keysharp-inputd.socket"

policy="$resource_root/polkit/org.keysharp.input.policy"
tmpfiles="$resource_root/tmpfiles/keysharp-input-permissions.conf"
uaccess="$resource_root/udev/70-keysharp-inputd-uaccess.rules"
service="$resource_root/systemd/keysharp-inputd.service"
socket="$resource_root/systemd/keysharp-inputd.socket"

policy_configuration_matches "$policy"
tmpfiles_configuration_matches "$tmpfiles"
uaccess_configuration_matches "$uaccess"
archive_service_configuration_matches "$service"
archive_socket_configuration_matches "$socket"

sed 's/<allow_active>auth_self<\//<allow_active>yes<\//' \
    "$policy" > "$temporary/insecure.policy"
! policy_configuration_matches "$temporary/insecure.policy"
sed '/<message>/d' "$policy" > "$temporary/missing-message.policy"
! policy_configuration_matches "$temporary/missing-message.policy"
sed '/<\/policyconfig>/i\  <action id="org.example.unexpected"></action>' \
    "$policy" > "$temporary/extra-action.policy"
! policy_configuration_matches "$temporary/extra-action.policy"
sed '/<policyconfig>/a\  <!-- compatible packaging comment -->' \
    "$policy" > "$temporary/commented.policy"
policy_configuration_matches "$temporary/commented.policy"

cp "$tmpfiles" "$temporary/insecure.tmpfiles"
printf '%s\n' 'd /var/lib/keysharp-input 0777 root root - -' \
    >> "$temporary/insecure.tmpfiles"
! tmpfiles_configuration_matches "$temporary/insecure.tmpfiles"

cp "$uaccess" "$temporary/insecure.rules"
printf '%s\n' 'KERNEL=="event*", MODE="0666"' >> "$temporary/insecure.rules"
! uaccess_configuration_matches "$temporary/insecure.rules"

sed 's|/usr/local/bin/keysharp-inputd --system-service|/tmp/inputd --system-service|' \
    "$service" > "$temporary/insecure.service"
! archive_service_configuration_matches "$temporary/insecure.service"
sed 's/NoNewPrivileges=yes/NoNewPrivileges=no/' \
    "$service" > "$temporary/weak-service.service"
! archive_service_configuration_matches "$temporary/weak-service.service"
sed '/^\[Install\]/i\DeviceAllow=/dev/mem rw' \
    "$service" > "$temporary/extra-device.service"
! archive_service_configuration_matches "$temporary/extra-device.service"

sed 's|/run/keysharp-inputd/keysharp-inputd.sock|/tmp/input.sock|' \
    "$socket" > "$temporary/insecure.socket"
! archive_socket_configuration_matches "$temporary/insecure.socket"

is_root_protected_file /bin/sh
ln -s /bin/sh "$temporary/unprotected-link"
! is_root_protected_file "$temporary/unprotected-link"
! installed_resource_is_valid policy_configuration_matches "$policy"

printf '%s\n' '#!/bin/sh' 'exit 0' > "$resource_root/bin/keysharp-inputd"
chmod 0755 "$resource_root/bin/keysharp-inputd"
cp "$source_dir/packaging/uninstall.sh" "$resource_root/uninstall.sh"
chmod 0755 "$resource_root/uninstall.sh"
cp "$source_dir/LICENSE" "$source_dir/README.md" "$source_dir/PROVENANCE.md" \
    "$resource_root/"
cp "$source_dir/include/keysharp_inputd/protocol.h" \
    "$resource_root/include/keysharp-inputd/protocol.h"
cp "$source_dir/docs/app-identity.md" "$source_dir/docs/permission-store.md" \
    "$source_dir/docs/physical-live-tests.md" "$source_dir/docs/protocol.md" \
    "$resource_root/docs/"
archive_complete "$resource_root"
rm -f -- "$resource_root/systemd/keysharp-inputd.socket"
! archive_complete "$resource_root"

echo "portable compatibility checks passed"
