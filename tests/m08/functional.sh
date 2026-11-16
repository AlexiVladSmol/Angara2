#!/usr/bin/env bash
# Functional systemd stand: HTTP, HTTPS proxy, Basic, ACL, TLS-in-TLS, CONNECT.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
PASSWORD='M08-SYNTHETIC-MARKER-7c1e9a2b'
WRONG='M08-WRONG-MARKER-9911aa'

TMP=$(mktemp -d)
PIDS=""
cleanup() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

python3 "$M08_DIR/pki.py" --dir "$TMP/pki"
"$M08_DIR/make_users.sh" "$BIN" "$TMP/users.toml" "$PASSWORD"

# Origins: HTTP allowed, HTTP denied-by-port, TLS site on two loopback IPs.
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin-http.log" >"$TMP/http.out" 2>"$TMP/http.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18081 \
    --log "$TMP/origin-extra.log" >"$TMP/extra.out" 2>"$TMP/extra.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18443 \
    --cert "$TMP/pki/site_chain.pem" --key "$TMP/pki/site_key.pem" \
    --log "$TMP/origin-site.log" >"$TMP/site.out" 2>"$TMP/site.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.2 --port 18443 \
    --cert "$TMP/pki/site_chain.pem" --key "$TMP/pki/site_key.pem" \
    --log "$TMP/origin-site2.log" >"$TMP/site2.out" 2>"$TMP/site2.err" &
PIDS="$PIDS $!"
wait_port 127.0.0.1 18080
wait_port 127.0.0.1 18081
wait_port 127.0.0.1 18443
wait_port 127.0.0.2 18443

install -d -m 0750 -o root -g angara /etc/angara/tls
install -m 0640 -o root -g angara "$TMP/users.toml" /etc/angara/users.toml
install -m 0640 -o root -g angara "$TMP/pki/proxy_chain.pem" \
    /etc/angara/tls/proxy-chain.pem
install -m 0640 -o root -g angara "$TMP/pki/proxy_key.pem" \
    /etc/angara/tls/proxy-key.pem

python3 "$M08_DIR/make_config.py" \
    --output "$TMP/angara.toml" \
    --mode functional \
    --http-port 3128 \
    --https-port 3129 \
    --https2-port 3129 \
    --site-port 18443 \
    --extra-port 0 \
    --users-file /etc/angara/users.toml \
    --tls-cert /etc/angara/tls/proxy-chain.pem \
    --tls-key /etc/angara/tls/proxy-key.pem \
    --workers 2 \
    --shutdown-ms 5000 \
    --metrics-interval 1000
install -m 0640 -o root -g angara "$TMP/angara.toml" /etc/angara/angara.toml
runuser -u angara -- "$BIN" check --config /etc/angara/angara.toml \
    >"$TMP/check-service.txt"
grep -q 'config ok:' "$TMP/check-service.txt"
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

cat >"$TMP/http.conf" <<EOF
silent
show-error
proxy = "http://127.0.0.1:3128"
EOF
cat >"$TMP/https.conf" <<EOF
silent
show-error
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/https-bob.conf" <<EOF
silent
show-error
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "bob:$PASSWORD"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/https-bad.conf" <<EOF
silent
show-error
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$WRONG"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/https-noauth.conf" <<EOF
silent
show-error
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/https-alt.conf" <<EOF
silent
show-error
proxy = "https://127.0.0.2:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
EOF

# HTTP basics and body equality.
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ --config "$TMP/http.conf")
assert_eq "$CODE" "200" "HTTP allowed"
curl --config "$TMP/http.conf" -fsS http://127.0.0.1:18080/ -o "$TMP/http-body"
grep -q 'm08-origin-ok' "$TMP/http-body"
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ --config "$TMP/http.conf" -I)
assert_eq "$CODE" "200" "HTTP HEAD"
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18080/range \
    --config "$TMP/http.conf" -H 'Range: bytes=0-15')
assert_eq "$CODE" "206" "HTTP Range"
curl --config "$TMP/http.conf" -fsS -H 'Range: bytes=0-15' \
    http://127.0.0.1:18080/range -o "$TMP/range.bin"
assert_eq "$(wc -c <"$TMP/range.bin")" "16" "Range body"

head -c 1048576 /dev/urandom >"$TMP/upload.bin"
UPLOAD_SHA=$(sha256 "$TMP/upload.bin")
curl --config "$TMP/http.conf" -fsS --data-binary @"$TMP/upload.bin" \
    http://127.0.0.1:18080/upload -o "$TMP/upload.json"
python3 - "$TMP/upload.json" "$UPLOAD_SHA" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["received"] == 1048576, value
assert value["sha256"] == sys.argv[2], value
PY
EXPECTED_HASH=$(python3 "$M08_DIR/origin.py" --print-hash 1048576)
curl --config "$TMP/http.conf" -fsS "http://127.0.0.1:18080/download?bytes=1048576" \
    -o "$TMP/download.bin"
assert_eq "$(wc -c <"$TMP/download.bin")" "1048576" "HTTP download size"
assert_eq "$(sha256 "$TMP/download.bin")" "$EXPECTED_HASH" "HTTP download hash"

# ACL deny must not contact the origin.
EXTRA_BEFORE=$(line_count "$TMP/origin-extra.log")
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18081/ --config "$TMP/http.conf")
assert_eq "$CODE" "403" "ACL denied port"
sleep 0.3
EXTRA_AFTER=$(line_count "$TMP/origin-extra.log")
assert_eq "$EXTRA_AFTER" "$EXTRA_BEFORE" "ACL deny origin connections"

# HTTPS proxy auth and ACL outcomes.
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/https-noauth.conf")
assert_eq "$CODE" "407" "missing credentials"
curl --noproxy '' --proxy https://127.0.0.1:3129 \
    --proxy-cacert "$TMP/pki/proxy_ca.pem" -sS -D "$TMP/407.headers" -o /dev/null \
    http://127.0.0.1:18080/ || true
grep -qi '^Proxy-Authenticate: Basic' "$TMP/407.headers"
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/https-bad.conf")
assert_eq "$CODE" "407" "bad credentials"
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/https-bob.conf")
assert_eq "$CODE" "403" "user ACL"
CODE=$(http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ --config "$TMP/https.conf")
assert_eq "$CODE" "200" "HTTPS proxy allowed"

# Proxy-Authorization must not reach the origin, and usernames/passwords must
# not leak into the response body.
curl --config "$TMP/https.conf" -fsS http://127.0.0.1:18080/headers \
    -o "$TMP/headers.json"
python3 - "$TMP/headers.json" "$PASSWORD" <<'PY'
import json, sys
headers = {key.lower(): value for key, value in json.load(open(sys.argv[1], encoding="utf-8")).items()}
assert "proxy-authorization" not in headers, headers
assert all(sys.argv[2] not in value for value in headers.values()), headers
PY

# Layered TLS: proxy TLS plus site TLS inside CONNECT.
CODE=$(http_code https://127.0.0.1:3129 https://127.0.0.1:18443/ --config "$TMP/https.conf")
assert_eq "$CODE" "200" "layered TLS CONNECT"
curl --config "$TMP/https.conf" -fsS https://127.0.0.1:18443/ -o "$TMP/site-body"
grep -q 'm08-origin-ok' "$TMP/site-body"
curl --config "$TMP/https.conf" -fsS "https://127.0.0.1:18443/download?bytes=1048576" \
    -o "$TMP/site-download.bin"
assert_eq "$(wc -c <"$TMP/site-download.bin")" "1048576" "CONNECT download size"
assert_eq "$(sha256 "$TMP/site-download.bin")" "$EXPECTED_HASH" "CONNECT download hash"
curl --config "$TMP/https.conf" -fsS --data-binary @"$TMP/upload.bin" \
    https://127.0.0.1:18443/upload -o "$TMP/site-upload.json"
python3 - "$TMP/site-upload.json" "$UPLOAD_SHA" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["received"] == 1048576, value
assert value["sha256"] == sys.argv[2], value
PY

# Certificate failures: wrong proxy CA, wrong proxy name, wrong site CA, wrong
# site name. None may be accepted as a successful request.
set +e
curl --config "$TMP/https.conf" --proxy-cacert "$TMP/pki/site_ca.pem" \
    http://127.0.0.1:18080/ -o /dev/null 2>"$TMP/wrong-proxy-ca.err"
WRONG_PROXY_CA=$?
curl --config "$TMP/https-alt.conf" http://127.0.0.1:18080/ \
    -o /dev/null 2>"$TMP/wrong-proxy-name.err"
WRONG_PROXY_NAME=$?
curl --config "$TMP/https.conf" --cacert "$TMP/pki/proxy_ca.pem" \
    https://127.0.0.1:18443/ -o /dev/null 2>"$TMP/wrong-site-ca.err"
WRONG_SITE_CA=$?
curl --config "$TMP/https.conf" https://127.0.0.2:18443/ \
    -o /dev/null 2>"$TMP/wrong-site-name.err"
WRONG_SITE_NAME=$?
set -e
assert_eq "$WRONG_PROXY_CA" "60" "wrong proxy CA exit"
assert_eq "$WRONG_PROXY_NAME" "60" "wrong proxy name exit"
if [ "$WRONG_SITE_CA" -ne 60 ] && [ "$WRONG_SITE_CA" -ne 35 ]; then
    fail "wrong site CA exit was $WRONG_SITE_CA (expected 60/35)"
fi
assert_eq "$WRONG_SITE_NAME" "60" "wrong site name exit"
grep -Eqi 'certificate|unknown ca|SSL|alert' \
    "$TMP/wrong-proxy-ca.err" "$TMP/wrong-site-ca.err"

# No secret markers/usernames in the application journal or origin logs.
journalctl -u angara.service --since '10 minutes ago' -o cat --no-pager \
    >"$TMP/journal.txt"
if grep -Fq "$PASSWORD" "$TMP/journal.txt" "$TMP/origin-http.log" \
    "$TMP/origin-site.log" "$TMP/headers.json"; then
    fail "synthetic password marker leaked"
fi
if grep -Eq 'alice|bob|Proxy-Authorization|Authorization' "$TMP/journal.txt"; then
    fail "username/credential field leaked into journal"
fi
if grep -Fq 'M08-WRONG-MARKER' "$TMP/journal.txt" "$TMP/origin-http.log"; then
    fail "wrong password marker leaked"
fi

# The service process must not be able to write its binary, unit or config.
PID=$(systemctl show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "service has no main PID"
runuser -u angara -- test ! -w /opt/angara/current/bin/angara \
    || fail "service user can write the binary"
runuser -u angara -- test ! -w /etc/systemd/system/angara.service \
    || fail "service user can write the unit"
runuser -u angara -- test ! -w /etc/angara/angara.toml \
    || fail "service user can write the config"

log "functional checks passed"
