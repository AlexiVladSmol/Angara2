#!/usr/bin/env bash
# Bounded overload, fault injection and stop-under-load checks.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
command -v openssl >/dev/null 2>&1 || fail "openssl is required for the TLS flood"
REPORT_DIR=${M08_REPORT_DIR:-"$PWD/m08-reports"}
mkdir -p "$REPORT_DIR"
TMP=$(mktemp -d)
PIDS=
cleanup() {
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

PASSWORD='M08-OVERLOAD-SYNTHETIC'
WRONG='M08-OVERLOAD-WRONG-MARKER'
python3 "$M08_DIR/pki.py" --dir "$TMP/pki"
"$M08_DIR/make_users.sh" "$BIN" "$TMP/users.toml" "$PASSWORD"
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
install -m 0640 -o root -g angara "$TMP/users.toml" /etc/angara/users.toml
install -m 0640 -o root -g angara "$TMP/pki/proxy_chain.pem" /etc/angara/tls/proxy-chain.pem
install -m 0640 -o root -g angara "$TMP/pki/proxy_key.pem" /etc/angara/tls/proxy-key.pem
python3 "$M08_DIR/make_config.py" --output "$TMP/angara.toml" --mode functional \
    --http-port 3128 --https-port 3129 --https2-port 0 --site-port 18443 \
    --extra-port 0 --allow-ports 18080,18082,18443 \
    --users-file /etc/angara/users.toml \
    --tls-cert /etc/angara/tls/proxy-chain.pem \
    --tls-key /etc/angara/tls/proxy-key.pem \
    --workers 2 --https-users alice --shutdown-ms 3000 --reload-ms 5000 \
    --idle-ms 60000 --metrics-interval 1000 \
    --max-connections 128 --max-client-connections 64
TMPCONF=$(mktemp /etc/angara/.overload.XXXXXX)
cp "$TMP/angara.toml" "$TMPCONF"
chown root:angara "$TMPCONF"
chmod 0640 "$TMPCONF"
mv -f "$TMPCONF" /etc/angara/angara.toml
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

cat >"$TMP/https.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
cacert = "$TMP/pki/site_ca.pem"
EOF
cat >"$TMP/bad.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$WRONG"
cacert = "$TMP/pki/site_ca.pem"
EOF
printf 'overload baseline\n' | tee "$REPORT_DIR/overload.txt"

# Auth flood: bounded verifier; no 200 and no crash.
rm -rf "$TMP/auth"
mkdir -p "$TMP/auth"
AUTH_PIDS=
for index in $(seq 1 100); do
    (
        code=$(curl --config "$TMP/bad.conf" --noproxy '' --proxy https://127.0.0.1:3129 \
            -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ 2>/dev/null || true)
        printf '%s\n' "${code:-000}"
    ) >"$TMP/auth/$index" &
    AUTH_PIDS="$AUTH_PIDS $!"
done
for pid in $AUTH_PIDS; do wait "$pid" || true; done
AUTH_CODES=$(cat "$TMP/auth"/* | sort | uniq -c)
printf 'auth_flood_codes:\n%s\n' "$AUTH_CODES" | tee -a "$REPORT_DIR/overload.txt"
if [ -n "$(cat "$TMP/auth"/* | grep -v -E '^(407|503|000)$' || true)" ]; then
    fail "auth flood produced an unexpected HTTP outcome"
fi
systemctl is-active --quiet angara.service || fail "service died during auth flood"

# Connection flood: clients that never send a request header.
python3 - 127.0.0.1 3128 100 <<'PY' >"$TMP/conn-flood.out" 2>"$TMP/conn-flood.err"
import socket, sys, time
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sockets = []
for _ in range(count):
    try:
        sockets.append(socket.create_connection((host, port), timeout=1))
    except OSError:
        pass
print(f"opened={len(sockets)}")
time.sleep(2)
for sock in sockets:
    sock.close()
PY
cat "$TMP/conn-flood.out" | tee -a "$REPORT_DIR/overload.txt"
systemctl is-active --quiet angara.service || fail "service died during connection flood"

# TLS handshake flood.
set +e
TLS_PIDS=
for index in $(seq 1 50); do
    timeout 5 openssl s_client -connect 127.0.0.1:3129 -servername 127.0.0.1 \
        -CAfile "$TMP/pki/proxy_ca.pem" -brief </dev/null \
        >"$TMP/tls-$index.out" 2>"$TMP/tls-$index.err" &
    TLS_PIDS="$TLS_PIDS $!"
done
for pid in $TLS_PIDS; do wait "$pid" || true; done
set -e
TLS_OK=$(grep -L 'error\|verify' "$TMP"/tls-*.err 2>/dev/null | wc -l || true)
printf 'tls_handshake_flood_attempts=50 non_error=%s\n' "$TLS_OK" \
    | tee -a "$REPORT_DIR/overload.txt"
systemctl is-active --quiet angara.service || fail "service died during TLS flood"

# Slow clients and aborted transfers must not grow unbounded or kill the service.
SLOW_PIDS=
for index in $(seq 1 10); do
    curl --noproxy '' --proxy http://127.0.0.1:3128 --limit-rate 1k \
        "http://127.0.0.1:18080/download?bytes=67108864&delay_ms=1" \
        -o /dev/null >"$TMP/slow-$index.out" 2>"$TMP/slow-$index.err" &
    SLOW_PIDS="$SLOW_PIDS $!"
done
sleep 2
for pid in $SLOW_PIDS; do kill "$pid" 2>/dev/null || true; done
for pid in $SLOW_PIDS; do wait "$pid" 2>/dev/null || true; done
systemctl is-active --quiet angara.service || fail "service died during slow clients"
curl --noproxy '' --proxy http://127.0.0.1:3128 --max-time 1 \
    "http://127.0.0.1:18080/download?bytes=67108864&delay_ms=10" \
    -o /dev/null >"$TMP/abort.out" 2>"$TMP/abort.err" || true
systemctl is-active --quiet angara.service || fail "service died during client abort"

# DNS and connect failures are explicit, not success.
for target in "http://nonexistent.invalid:18080/" "http://127.0.0.1:18082/"; do
    code=$(http_code http://127.0.0.1:3128 "$target")
    case "$code" in
        502|503|504) ;;
        *) fail "fault target $target returned unexpected $code" ;;
    esac
    printf 'fault target=%s code=%s\n' "$target" "$code" \
        | tee -a "$REPORT_DIR/overload.txt"
done

# Stop with an active CONNECT download.
curl --config "$TMP/https.conf" --limit-rate 100k \
    "https://127.0.0.1:18443/download?bytes=67108864&delay_ms=1" \
    -o "$TMP/slow-connect.bin" >"$TMP/slow-connect.out" 2>"$TMP/slow-connect.err" &
CONNECT_PID=$!
for _ in $(seq 1 100); do
    [ -s "$TMP/slow-connect.bin" ] && break
    sleep 0.1
done
[ -s "$TMP/slow-connect.bin" ] || fail "CONNECT stop download did not start"
START_MS=$(date +%s%3N)
systemctl stop angara.service
END_MS=$(date +%s%3N)
ELAPSED=$((END_MS - START_MS))
[ "$ELAPSED" -le 6000 ] || fail "stop under CONNECT took ${ELAPSED}ms"
kill "$CONNECT_PID" 2>/dev/null || true
wait "$CONNECT_PID" 2>/dev/null || true
wait_service_inactive 20
assert_eq "$(systemctl show -p Result --value angara.service)" "success" "overload stop result"
if ss -ltn | grep -q ':3128'; then
    fail "stop under CONNECT left the listener open"
fi
printf 'stop_under_connect elapsed_ms=%s bytes=%s\n' "$ELAPSED" \
    "$(wc -c <"$TMP/slow-connect.bin")" | tee -a "$REPORT_DIR/overload.txt"

if journalctl -u angara.service --since '10 minutes ago' -o cat --no-pager \
    | grep -Fq "$WRONG"; then
    fail "wrong-password marker leaked into journal"
fi
log "overload checks passed"
