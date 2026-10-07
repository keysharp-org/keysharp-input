#!/bin/sh
set -eu

source_dir=${1:?source directory is required}
temporary=$(mktemp -d)
upgrade_pid=
cleanup() {
    if [ -n "$upgrade_pid" ]; then
        kill "$upgrade_pid" 2>/dev/null || true
        wait "$upgrade_pid" 2>/dev/null || true
    fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

sed -n '/^is_root_protected_chain() {$/,/^archive_dir=/p' \
    "$source_dir/packaging/install-release.sh" | sed '$d' \
    > "$temporary/install-functions.sh"
expected_client_abi_major=$(awk '$2 == "KSI_CLIENT_ABI_MAJOR" { gsub(/u[[:space:]]*$/, "", $3); print $3 }' \
    "$source_dir/include/keysharp_input/client.h")
expected_client_abi_minor=$(awk '$2 == "KSI_CLIENT_ABI_MINOR" { gsub(/u[[:space:]]*$/, "", $3); print $3 }' \
    "$source_dir/include/keysharp_input/client.h")
for component in major minor; do
    installer_value=$(sed -n "s/^expected_client_abi_${component}=//p" \
        "$source_dir/packaging/install-release.sh")
    if [ "$component" = major ]; then
        header_value=$expected_client_abi_major
    else
        header_value=$expected_client_abi_minor
    fi
    if [ "$installer_value" != "$header_value" ]; then
        echo "archive installer ABI $component does not match its public header" >&2
        exit 1
    fi
done
# shellcheck source=/dev/null
. "$temporary/install-functions.sh"

# A build sandbox maps every uid but the builder's to nobody and carries no system
# layout, so nothing there can be root-protected and only the rejection cases stay
# meaningful. Probe ownership directly rather than through the predicate under test.
if [ "$(stat -Lc '%u' /etc 2>/dev/null || echo 1)" = 0 ] && [ -e /etc/os-release ]
then
    is_root_protected_file /etc/os-release
else
    echo "skipping the acceptance case: no root-owned system files here" >&2
fi
printf 'ordinary\n' > "$temporary/ordinary"
if is_root_protected_file "$temporary/ordinary"; then
    echo "a file below a user-writable directory was accepted as protected" >&2
    exit 1
fi

shell_binary=$(command -v sh)
[ -x "$shell_binary" ]
printf '%s\n' '#!/bin/sh' 'exit 0' > "$temporary/replacement"
chmod 0755 "$temporary/replacement"

mkdir "$temporary/live"
live_executable=$temporary/live/sh
cp "$shell_binary" "$live_executable"
chmod 0755 "$live_executable"
old_inode=$(stat -c '%i' "$live_executable")
mkfifo "$temporary/ready" "$temporary/block"
exec 3<> "$temporary/block"
# The child announces readiness after startup, then blocks in the shell's read builtin.
"$live_executable" -c 'printf "%s\n" ready; read -r ignored' \
    < "$temporary/block" > "$temporary/ready" &
upgrade_pid=$!
IFS= read -r ready < "$temporary/ready"
[ "$ready" = ready ]
atomic_install_file "$temporary/replacement" "$live_executable" 0755
new_inode=$(stat -c '%i' "$live_executable")
[ "$old_inode" != "$new_inode" ]
kill -0 "$upgrade_pid"
"$live_executable"
kill "$upgrade_pid"
wait "$upgrade_pid" 2>/dev/null || true
upgrade_pid=
exec 3>&-

mkdir -p "$temporary/live-lib"
printf '%s\n' old > "$temporary/live-lib/libkeysharp-input.so.1.0.0"
old_inode=$(stat -c '%i' \
    "$temporary/live-lib/libkeysharp-input.so.1.0.0")
printf '%s\n' new > "$temporary/new-library"
atomic_install_file "$temporary/new-library" \
    "$temporary/live-lib/libkeysharp-input.so.1.0.0" 0755
new_inode=$(stat -c '%i' \
    "$temporary/live-lib/libkeysharp-input.so.1.0.0")
[ "$old_inode" != "$new_inode" ]
atomic_install_symlink libkeysharp-input.so.1.0.0 \
    "$temporary/live-lib/libkeysharp-input.so.1"
atomic_install_symlink libkeysharp-input.so.1 \
    "$temporary/live-lib/libkeysharp-input.so"
[ "$(cat "$temporary/live-lib/libkeysharp-input.so")" = new ]

service_configuration_matches \
    "$source_dir/systemd/keysharp-input.service.in" \
    '@CMAKE_INSTALL_FULL_BINDIR@/keysharp-input' \
    '@KEYSHARP_INPUT_TMPFILES_CONFIG@'
for weakening in 's/NoNewPrivileges=yes/NoNewPrivileges=no/' \
    's/DeviceAllow=char-input rw/DeviceAllow=char-input r/'; do
    sed "$weakening" "$source_dir/systemd/keysharp-input.service.in" \
        > "$temporary/weakened.service"
    if service_configuration_matches "$temporary/weakened.service" \
        '@CMAKE_INSTALL_FULL_BINDIR@/keysharp-input' \
        '@KEYSHARP_INPUT_TMPFILES_CONFIG@'; then
        echo "a weakened system service was accepted: $weakening" >&2
        exit 1
    fi
done
socket_configuration_matches "$source_dir/systemd/keysharp-input.socket"
sed 's/SocketMode=0666/SocketMode=0600/' \
    "$source_dir/systemd/keysharp-input.socket" > "$temporary/wrong.socket"
if socket_configuration_matches "$temporary/wrong.socket"; then
    echo "a socket with incompatible access was accepted" >&2
    exit 1
fi
tmpfiles_configuration_matches \
    "$source_dir/systemd/keysharp-input-permissions.conf"
policy_configuration_matches "$source_dir/polkit/org.keysharp.input.policy"
sed 's/<allow_active>auth_self<\//<allow_active>yes<\//' \
    "$source_dir/polkit/org.keysharp.input.policy" \
    > "$temporary/weakened.policy"
if policy_configuration_matches "$temporary/weakened.policy"; then
    echo "a weakened grant policy was accepted" >&2
    exit 1
fi
udev_configuration_matches "$source_dir/udev/70-keysharp-input-uaccess.rules"
# Rules that drop the hwdb lookup or grant the session a Keysharp device.
for weakening in '/keysharp-input\/forward/d' '/^SUBSYSTEM!=/a\
ATTRS{phys}=="keysharp-input/forward/*", TAG+="uaccess"' '/^SUBSYSTEM!=/a\
ATTRS{name}=="Keysharp Virtual Input", TAG+="uaccess"'; do
    sed "$weakening" "$source_dir/udev/70-keysharp-input-uaccess.rules" \
        > "$temporary/weakened.rules"
    if udev_configuration_matches "$temporary/weakened.rules"; then
        echo "a weakened udev rule was accepted: $weakening" >&2
        exit 1
    fi
done

printf '%s\n' '#!/bin/sh' \
    "printf '%s\\n' client_abi_major=$expected_client_abi_major client_abi_minor=$expected_client_abi_minor" \
    > "$temporary/good-info"
chmod 0755 "$temporary/good-info"
client_abi_matches "$temporary/good-info"

mkdir -p "$temporary/bin"
cat > "$temporary/bin/dpkg-query" <<'EOF'
#!/bin/sh
printf '%s\n' \
    'ii |unrelated-provider, keysharp-input-client-abi-1 (= 1.0)' \
    'rc |ignored-provider, keysharp-input-client-abi-1'
EOF
chmod 0755 "$temporary/bin/dpkg-query"
old_path=$PATH
PATH="$temporary/bin:$PATH"
installed_debian_provider_satisfies keysharp-input-client-abi-1
if installed_debian_provider_satisfies ignored-provider; then
    echo "a removed package was accepted as an installed provider" >&2
    exit 1
fi
PATH=$old_path

printf '%s\n' '#!/bin/sh' \
    "printf '%s\\n' client_abi_major=$((expected_client_abi_major - 1)) client_abi_minor=$expected_client_abi_minor" \
    > "$temporary/old-info"
chmod 0755 "$temporary/old-info"
if client_abi_matches "$temporary/old-info"; then
    echo "an older client ABI major was accepted" >&2
    exit 1
fi

sed -n '/^path_present() {$/,/^case /p' \
    "$source_dir/packaging/debian/preinst" | sed '$d' \
    > "$temporary/preinst-functions.sh"
# shellcheck source=/dev/null
. "$temporary/preinst-functions.sh"
mkdir -p "$temporary/local" "$temporary/package"
printf 'stale\n' > "$temporary/local/libkeysharp-input.so.1"
portable_library_conflicts "$temporary/local/libkeysharp-input.so.1" \
    "$temporary/package/libkeysharp-input.so.1"
printf 'packaged\n' > "$temporary/package/libkeysharp-input.so.1"
rm -f -- "$temporary/local/libkeysharp-input.so.1"
ln -s ../package/libkeysharp-input.so.1 \
    "$temporary/local/libkeysharp-input.so.1"
if portable_library_conflicts "$temporary/local/libkeysharp-input.so.1" \
    "$temporary/package/libkeysharp-input.so.1"; then
    echo "an alias to the packaged client library was rejected" >&2
    exit 1
fi

uninstall_root=$temporary/uninstall-root
mkdir -p "$uninstall_root/usr/local/bin" "$uninstall_root/usr/local/lib" \
    "$uninstall_root/usr/local/share/doc/keysharp-input" \
    "$uninstall_root/etc/systemd/system" "$uninstall_root/usr/bin" \
    "$uninstall_root/usr/lib" "$uninstall_root/var/lib/keysharp-permissions/v1" \
    "$uninstall_root/run/keysharp-permissions" "$temporary/uninstall-bin"
# Translate every system path before running the uninstaller against a disposable tree.
sed "s|/usr/|$uninstall_root/usr/|g; s|/etc/|$uninstall_root/etc/|g; \
    s|/var/|$uninstall_root/var/|g; s|/run/|$uninstall_root/run/|g" \
    "$source_dir/uninstall.sh" > "$temporary/uninstall.sh"
cat > "$temporary/uninstall-bin/mock" <<'EOF'
#!/bin/sh
set -eu
case "${0##*/}" in
    id) printf '0\n' ;;
    dpkg-query) printf '%s' "$KSI_UNINSTALL_TEST_STATUS" ;;
    systemctl|ldconfig) printf '%s %s\n' "${0##*/}" "$*" >> "$KSI_UNINSTALL_TEST_CALLS" ;;
    *) exit 99 ;;
esac
EOF
chmod 0755 "$temporary/uninstall-bin/mock"
for command in id dpkg-query systemctl ldconfig; do
    ln -s mock "$temporary/uninstall-bin/$command"
done
cat > "$uninstall_root/usr/local/bin/keysharp-input" <<'EOF'
#!/bin/sh
printf 'keysharp-input %s\n' "$*" >> "$KSI_UNINSTALL_TEST_CALLS"
EOF
chmod 0755 "$uninstall_root/usr/local/bin/keysharp-input"
for path in \
    usr/local/lib/libkeysharp-input.so.0.4.0 \
    usr/local/lib/libkeysharp-input.so.1.0.0 \
    usr/local/share/doc/keysharp-input/uninstall.sh \
    etc/systemd/system/keysharp-input.service \
    etc/systemd/system/keysharp-input.socket \
    usr/bin/keysharp-input usr/lib/libkeysharp-input.so.1 \
    usr/local/lib/libunrelated.so \
    var/lib/keysharp-permissions/v1/grant run/keysharp-permissions/lease; do
    printf 'keep-or-remove\n' > "$uninstall_root/$path"
done
ln -s libkeysharp-input.so.0.4.0 "$uninstall_root/usr/local/lib/libkeysharp-input.so.0"
ln -s libkeysharp-input.so.1.0.0 "$uninstall_root/usr/local/lib/libkeysharp-input.so.1"
ln -s libkeysharp-input.so.1 "$uninstall_root/usr/local/lib/libkeysharp-input.so"
KSI_UNINSTALL_TEST_CALLS=$temporary/uninstall-calls
export KSI_UNINSTALL_TEST_CALLS
if PATH="$temporary/uninstall-bin:$PATH" KSI_UNINSTALL_TEST_STATUS='ii ' \
    sh "$temporary/uninstall.sh" > "$temporary/uninstall-output" 2>&1; then
    echo "portable uninstaller accepted an installed Debian package" >&2
    exit 1
fi
[ ! -e "$KSI_UNINSTALL_TEST_CALLS" ]
[ -x "$uninstall_root/usr/local/bin/keysharp-input" ]
[ -f "$uninstall_root/usr/local/lib/libkeysharp-input.so.1.0.0" ]
PATH="$temporary/uninstall-bin:$PATH" KSI_UNINSTALL_TEST_STATUS='rc ' \
    sh "$temporary/uninstall.sh" > "$temporary/uninstall-output" 2>&1
for path in \
    usr/local/bin/keysharp-input usr/local/lib/libkeysharp-input.so \
    usr/local/lib/libkeysharp-input.so.0 usr/local/lib/libkeysharp-input.so.0.4.0 \
    usr/local/lib/libkeysharp-input.so.1 usr/local/lib/libkeysharp-input.so.1.0.0 \
    usr/local/share/doc/keysharp-input \
    etc/systemd/system/keysharp-input.service etc/systemd/system/keysharp-input.socket; do
    [ ! -e "$uninstall_root/$path" ] && [ ! -L "$uninstall_root/$path" ]
done
for path in \
    usr/bin/keysharp-input usr/lib/libkeysharp-input.so.1 \
    usr/local/lib/libunrelated.so \
    var/lib/keysharp-permissions/v1/grant run/keysharp-permissions/lease; do
    [ -f "$uninstall_root/$path" ]
done
grep -q '^systemctl disable --now keysharp-input.service keysharp-input.socket$' \
    "$KSI_UNINSTALL_TEST_CALLS"
grep -q '^keysharp-input daemon --remove-input-access$' "$KSI_UNINSTALL_TEST_CALLS"

echo "keysharp-input packaging semantics passed"
