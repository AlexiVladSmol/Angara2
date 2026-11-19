#!/usr/bin/env bash
# Execute the shipped M08 admin-guide example from the archive.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
ARCHIVE=${M08_ARCHIVE:-}
SHA=${M08_SHA256:-}
[ -n "$ARCHIVE" ] || fail "M08_ARCHIVE is not set"
[ -f "$ARCHIVE" ] || fail "archive does not exist: $ARCHIVE"
[ -n "$SHA" ] || SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
PASSWORD='M08-GUIDE-SYNTHETIC'

printf '%s  %s\n' "$SHA" "$ARCHIVE" | sha256sum -c - >/dev/null
TMP=$(mktemp -d)
PIDS=
cleanup() {
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

mkdir -p "$TMP/archive"
tar -xzf "$ARCHIVE" -C "$TMP/archive" \
    --no-same-owner --same-permissions --delay-directory-restore
TOP=$(find "$TMP/archive" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$TOP" ] || fail "archive has no top-level directory"
EXAMPLE="$TOP/examples/m08-operations-https-basic.toml"
[ -f "$EXAMPLE" ] || fail "archive does not contain the complete M08 example"
python3 "$M08_DIR/pki.py" --dir "$TMP/pki"
"$M08_DIR/make_users.sh" "$BIN" "$TMP/users.local.toml" "$PASSWORD"

python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin.log" >"$TMP/http.out" 2>"$TMP/http.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18443 \
    --cert "$TMP/pki/site_chain.pem" --key "$TMP/pki/site_key.pem" \
    --log "$TMP/site.log" >"$TMP/site.out" 2>"$TMP/site.err" &
PIDS="$PIDS $!"
wait_port 127.0.0.1 18080
wait_port 127.0.0.1 18443

install -d -m 0750 -o root -g angara /etc/angara/tls
install -m 0640 -o root -g angara "$EXAMPLE" /etc/angara/angara.toml
install -m 0640 -o root -g angara "$TMP/users.local.toml" /etc/angara/users.local.toml
install -m 0640 -o root -g angara "$TMP/pki/proxy_chain.pem" \
    /etc/angara/tls/proxy-chain.pem
install -m 0640 -o root -g angara "$TMP/pki/proxy_key.pem" \
    /etc/angara/tls/proxy-key.pem
runuser -u angara -- "$BIN" check --config /etc/angara/angara.toml >/dev/null
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

cat >"$TMP/curl.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/bad-proxy-ca.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-user = "alice:$PASSWORD"
EOF
cat >"$TMP/bad-site-ca.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
EOF
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18080/)
assert_eq "$CODE" "200" "guide HTTP allowed"
CODE=$(curl --noproxy '' --proxy https://127.0.0.1:3129 \
    --proxy-cacert "$TMP/pki/proxy_ca.pem" -sS -o /dev/null -w '%{http_code}' \
    http://127.0.0.1:18080/ 2>/dev/null || true)
assert_eq "$CODE" "407" "guide missing credentials"
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/curl.conf")
assert_eq "$CODE" "200" "guide Basic allowed"
CODE=$(http_code https://127.0.0.1:3129 https://127.0.0.1:18443/ --config "$TMP/curl.conf")
assert_eq "$CODE" "200" "guide CONNECT allowed"
set +e
curl --config "$TMP/bad-proxy-ca.conf" \
    --proxy-cacert "$TMP/pki/site_ca.pem" \
    http://127.0.0.1:18080/ -o /dev/null 2>"$TMP/wrong-proxy-ca.err"
WRONG_PROXY_CA=$?
curl --config "$TMP/bad-site-ca.conf" \
    --cacert "$TMP/pki/proxy_ca.pem" https://127.0.0.1:18443/ \
    -o /dev/null 2>"$TMP/wrong-site-ca.err"
WRONG_SITE_CA=$?
set -e
assert_eq "$WRONG_PROXY_CA" "60" "guide wrong proxy CA"
if [ "$WRONG_SITE_CA" -ne 60 ] && [ "$WRONG_SITE_CA" -ne 35 ]; then
    fail "guide wrong site CA exit was $WRONG_SITE_CA"
fi

# Exercise the backup/restore commands from the guide.  The whole
# /etc/angara tree (config, users, TLS) must be identical afterwards and the
# authenticated listener must still work.
CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum \
    | sha256sum | awk '{print $1}')
install -d -m 0700 /var/lib/angara/backups
BACKUP="$TMP/angara-manual.tgz"
tar -C /etc -czf "$BACKUP" angara
systemctl stop angara.service
wait_service_inactive 20
tar -C /etc -xzf "$BACKUP"
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
assert_eq "$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum \
    | sha256sum | awk '{print $1}')" "$CONFIG_HASH" \
    "guide backup/restore tree hash"
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/curl.conf")
assert_eq "$CODE" "200" "guide Basic after restore"
log "admin guide checks passed"
