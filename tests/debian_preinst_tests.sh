#!/bin/sh
set -eu

source_dir=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

portable_binary="$temporary/usr/local/bin/keysharp-inputd"
package_binary="$temporary/usr/bin/keysharp-inputd"
portable_service="$temporary/etc/systemd/system/keysharp-inputd.service"
portable_socket="$temporary/etc/systemd/system/keysharp-inputd.socket"
package_service="$temporary/usr/lib/systemd/system/keysharp-inputd.service"
package_socket="$temporary/usr/lib/systemd/system/keysharp-inputd.socket"
test_preinst="$temporary/preinst"

mkdir -p "$(dirname "$portable_binary")" "$(dirname "$package_binary")" \
    "$(dirname "$portable_service")"

sed \
    -e "s|/usr/local/bin/keysharp-inputd|$portable_binary|g" \
    -e "s|/usr/bin/keysharp-inputd|$package_binary|g" \
    -e "s|/etc/systemd/system/keysharp-inputd.service|$portable_service|g" \
    -e "s|/etc/systemd/system/keysharp-inputd.socket|$portable_socket|g" \
    -e "s|/usr/lib/systemd/system/keysharp-inputd.service|$package_service|g" \
    -e "s|/usr/lib/systemd/system/keysharp-inputd.socket|$package_socket|g" \
    "$source_dir/packaging/debian/preinst" > "$test_preinst"
chmod 0755 "$test_preinst"

"$test_preinst" install

: > "$package_binary"
chmod 0755 "$package_binary"
ln -s "$package_binary" "$portable_binary"
"$test_preinst" install
rm -f -- "$portable_binary"

: > "$portable_binary"
chmod 0755 "$portable_binary"
if "$test_preinst" install >/dev/null 2>&1; then
    echo "preinst accepted a distinct portable binary" >&2
    exit 1
fi
rm -f -- "$portable_binary"

cat > "$portable_service" <<EOF
[Service]
ExecStart=$portable_binary --system-service
EOF
if "$test_preinst" upgrade 1.1.0 >/dev/null 2>&1; then
    echo "preinst accepted the portable service unit" >&2
    exit 1
fi
cat > "$portable_service" <<EOF
[Service]
ExecStart=$package_binary --system-service
EOF
if "$test_preinst" install >/dev/null 2>&1; then
    echo "preinst accepted a modified shadowing service unit" >&2
    exit 1
fi
rm -f -- "$portable_service"
mkdir -p "$(dirname "$package_service")"
: > "$package_service"
ln -s "$package_service" "$portable_service"
"$test_preinst" install
rm -f -- "$portable_service"

cat > "$portable_socket" <<'EOF'
[Socket]
ListenStream=/run/keysharp-inputd/keysharp-inputd.sock
Accept=no
SocketMode=0666
DirectoryMode=0755
EOF
if "$test_preinst" install >/dev/null 2>&1; then
    echo "preinst accepted the portable socket unit" >&2
    exit 1
fi
cat > "$portable_socket" <<'EOF'
[Socket]
ListenStream=/run/keysharp-inputd/keysharp-inputd.sock
Accept=no
SocketMode=0600
DirectoryMode=0755
EOF
if "$test_preinst" install >/dev/null 2>&1; then
    echo "preinst accepted a modified shadowing socket unit" >&2
    exit 1
fi

rm -f -- "$portable_socket"
: > "$package_socket"
ln -s "$package_socket" "$portable_socket"
"$test_preinst" install
rm -f -- "$portable_socket"
"$test_preinst" abort-upgrade 1.1.0

echo "Debian preinst portable-layer checks passed"
