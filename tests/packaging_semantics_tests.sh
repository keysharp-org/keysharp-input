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
expected_client_abi_major=$(awk '$2 == "KSI_CLIENT_ABI_MAJOR" { gsub(/u$/, "", $3); print $3 }' \
    "$source_dir/include/keysharp_input/client.h")
expected_client_abi_minor=$(awk '$2 == "KSI_CLIENT_ABI_MINOR" { gsub(/u$/, "", $3); print $3 }' \
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

# A sandbox carries only /bin/sh, so locate on PATH the one binary this needs: a process
# that stays alive across its own replacement. The copy keeps the name "sleep" because a
# multi-call coreutils, which is what a sandbox usually supplies, picks its program from
# argv[0] and refuses to run under any other name. The replacement is written here.
sleep_binary=$(command -v sleep)
[ -x "$sleep_binary" ]
printf '%s\n' '#!/bin/sh' 'exit 0' > "$temporary/replacement"
chmod 0755 "$temporary/replacement"

mkdir "$temporary/live"
live_executable=$temporary/live/sleep
cp "$sleep_binary" "$live_executable"
chmod 0755 "$live_executable"
old_inode=$(stat -c '%i' "$live_executable")
"$live_executable" 30 &
upgrade_pid=$!
atomic_install_file "$temporary/replacement" "$live_executable" 0755
new_inode=$(stat -c '%i' "$live_executable")
[ "$old_inode" != "$new_inode" ]
kill -0 "$upgrade_pid"
"$live_executable"
kill "$upgrade_pid"
wait "$upgrade_pid" 2>/dev/null || true
upgrade_pid=

mkdir -p "$temporary/live-lib"
printf '%s\n' old > "$temporary/live-lib/libkeysharp-input.so.0.2.0"
old_inode=$(stat -c '%i' \
    "$temporary/live-lib/libkeysharp-input.so.0.2.0")
printf '%s\n' new > "$temporary/new-library"
atomic_install_file "$temporary/new-library" \
    "$temporary/live-lib/libkeysharp-input.so.0.2.0" 0755
new_inode=$(stat -c '%i' \
    "$temporary/live-lib/libkeysharp-input.so.0.2.0")
[ "$old_inode" != "$new_inode" ]
atomic_install_symlink libkeysharp-input.so.0.2.0 \
    "$temporary/live-lib/libkeysharp-input.so.0"
atomic_install_symlink libkeysharp-input.so.0 \
    "$temporary/live-lib/libkeysharp-input.so"
[ "$(cat "$temporary/live-lib/libkeysharp-input.so")" = new ]

service_configuration_matches \
    "$source_dir/systemd/keysharp-input.service.in" \
    '@CMAKE_INSTALL_FULL_BINDIR@/keysharp-input' \
    '@KEYSHARP_INPUT_TMPFILES_CONFIG@'
sed 's/NoNewPrivileges=yes/NoNewPrivileges=no/' \
    "$source_dir/systemd/keysharp-input.service.in" \
    > "$temporary/weakened.service"
if service_configuration_matches "$temporary/weakened.service" \
    '@CMAKE_INSTALL_FULL_BINDIR@/keysharp-input' \
    '@KEYSHARP_INPUT_TMPFILES_CONFIG@'; then
    echo "a weakened system service was accepted" >&2
    exit 1
fi
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

printf '%s\n' '#!/bin/sh' \
    "printf '%s\\n' client_abi_major=$expected_client_abi_major client_abi_minor=$expected_client_abi_minor" \
    > "$temporary/good-info"
chmod 0755 "$temporary/good-info"
client_abi_matches "$temporary/good-info"

mkdir -p "$temporary/bin"
cat > "$temporary/bin/dpkg-query" <<'EOF'
#!/bin/sh
printf '%s\n' \
    'ii |unrelated-provider, keysharp-input-client-abi-0 (= 0.2)' \
    'rc |ignored-provider, keysharp-input-client-abi-0'
EOF
chmod 0755 "$temporary/bin/dpkg-query"
old_path=$PATH
PATH="$temporary/bin:$PATH"
installed_debian_provider_satisfies keysharp-input-client-abi-0
if installed_debian_provider_satisfies ignored-provider; then
    echo "a removed package was accepted as an installed provider" >&2
    exit 1
fi
PATH=$old_path

printf '%s\n' '#!/bin/sh' \
    "printf '%s\\n' client_abi_major=$expected_client_abi_major client_abi_minor=$((expected_client_abi_minor - 1))" \
    > "$temporary/old-info"
chmod 0755 "$temporary/old-info"
if client_abi_matches "$temporary/old-info"; then
    echo "an older client ABI minor was accepted" >&2
    exit 1
fi

sed -n '/^path_present() {$/,/^case /p' \
    "$source_dir/packaging/debian/preinst" | sed '$d' \
    > "$temporary/preinst-functions.sh"
# shellcheck source=/dev/null
. "$temporary/preinst-functions.sh"
mkdir -p "$temporary/local" "$temporary/package"
printf 'stale\n' > "$temporary/local/libkeysharp-input.so.0"
portable_library_conflicts "$temporary/local/libkeysharp-input.so.0" \
    "$temporary/package/libkeysharp-input.so.0"
printf 'packaged\n' > "$temporary/package/libkeysharp-input.so.0"
rm -f -- "$temporary/local/libkeysharp-input.so.0"
ln -s ../package/libkeysharp-input.so.0 \
    "$temporary/local/libkeysharp-input.so.0"
if portable_library_conflicts "$temporary/local/libkeysharp-input.so.0" \
    "$temporary/package/libkeysharp-input.so.0"; then
    echo "an alias to the packaged client library was rejected" >&2
    exit 1
fi

echo "keysharp-input packaging semantics passed"
