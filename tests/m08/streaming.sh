#!/usr/bin/env bash
# 64 MiB / 1 GiB streaming through HTTP and CONNECT with resource bounds.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
REPORT_DIR=${M08_REPORT_DIR:-"$PWD/m08-reports"}
mkdir -p "$REPORT_DIR"
TMP=$(mktemp -d)
PIDS=
SAMPLER=
cleanup() {
    [ -z "$SAMPLER" ] || kill "$SAMPLER" 2>/dev/null || true
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

PASSWORD='M08-STREAM-SYNTHETIC'
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
    --extra-port 0 --users-file /etc/angara/users.toml \
    --tls-cert /etc/angara/tls/proxy-chain.pem \
    --tls-key /etc/angara/tls/proxy-key.pem \
    --workers 2 --https-users alice --shutdown-ms 10000 --reload-ms 5000 \
    --idle-ms 60000 --metrics-interval 1000
TMPCONF=$(mktemp /etc/angara/.stream.XXXXXX)
cp "$TMP/angara.toml" "$TMPCONF"
chown root:angara "$TMPCONF"
chmod 0640 "$TMPCONF"
mv -f "$TMPCONF" /etc/angara/angara.toml
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
PID=$(systemctl show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "service has no PID"

cat >"$TMP/http.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "http://127.0.0.1:3128"
EOF
cat >"$TMP/https.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:$PASSWORD"
cacert = "$TMP/pki/site_ca.pem"
EOF

sample_process() {
    local mode=$1
    local file=$2
    if [ "$mode" = "start" ]; then
        (
            max_rss=0
            max_fd=0
            while true; do
                if [ ! -d "/proc/$PID" ]; then break; fi
                rss=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status" 2>/dev/null || true)
                rss=${rss:-0}
                fd=$(find "/proc/$PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l || true)
                fd=${fd:-0}
                if [ "$rss" -gt "$max_rss" ]; then max_rss=$rss; fi
                if [ "$fd" -gt "$max_fd" ]; then max_fd=$fd; fi
                printf '%s %s\n' "$max_rss" "$max_fd" >"$file.tmp" \
                    && mv -f "$file.tmp" "$file" || true
                sleep 0.2
            done
        ) &
        SAMPLER=$!
    else
        kill "$SAMPLER" 2>/dev/null || true
        wait "$SAMPLER" 2>/dev/null || true
    fi
}

BASELINE_RSS=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status")
BASELINE_FD=$(find "/proc/$PID/fd" -mindepth 1 -maxdepth 1 | wc -l)
MAX_PEAK_RSS=0
printf 'stream baseline rss_kib=%s fds=%s\n' "$BASELINE_RSS" "$BASELINE_FD" \
    | tee "$REPORT_DIR/streaming.txt"

run_transfer() {
    local label=$1 config=$2 url=$3 bytes=$4 output=$5
    local expected
    expected=$(python3 "$M08_DIR/origin.py" --print-hash "$bytes")
    sample_process start "$TMP/peak-$label.txt"
    local start end elapsed code
    start=$(date +%s%3N)
    set +e
    curl --config "$config" -o "$output" "$url"
    code=$?
    set -e
    end=$(date +%s%3N)
    elapsed=$((end - start))
    sample_process stop "$TMP/peak-$label.txt"
    [ "$code" -eq 0 ] || fail "$label curl exit $code"
    assert_eq "$(wc -c <"$output")" "$bytes" "$label size"
    assert_eq "$(sha256 "$output")" "$expected" "$label hash"
    local sample="$TMP/peak-$label.txt"
    [ -s "$sample" ] || fail "no resource sample for $label"
    if ! read -r peak_rss peak_fd <"$sample"; then
        fail "cannot read resource sample for $label"
    fi
    case "$peak_rss" in
        ''|*[!0-9]*) fail "invalid RSS sample for $label: $peak_rss" ;;
    esac
    case "$peak_fd" in
        ''|*[!0-9]*) fail "invalid FD sample for $label: $peak_fd" ;;
    esac
    if [ "$peak_rss" -gt "$MAX_PEAK_RSS" ]; then MAX_PEAK_RSS=$peak_rss; fi
    printf '%s bytes=%s elapsed_ms=%s peak_rss_kib=%s peak_fd=%s\n' \
        "$label" "$bytes" "$elapsed" "$peak_rss" "$peak_fd" \
        | tee -a "$REPORT_DIR/streaming.txt"
    rm -f "$output"
}

run_transfer http-64m-http "$TMP/http.conf" \
    "http://127.0.0.1:18080/download?bytes=67108864&delay_ms=1" 67108864 "$TMP/http-64m.bin"
run_transfer connect-64m-connect "$TMP/https.conf" \
    "https://127.0.0.1:18443/download?bytes=67108864&delay_ms=1" 67108864 "$TMP/connect-64m.bin"
run_transfer http-1g-http "$TMP/http.conf" \
    "http://127.0.0.1:18080/download?bytes=1073741824&delay_ms=1" 1073741824 "$TMP/http-1g.bin"
run_transfer connect-1g-connect "$TMP/https.conf" \
    "https://127.0.0.1:18443/download?bytes=1073741824&delay_ms=1" 1073741824 "$TMP/connect-1g.bin"

# 64 MiB uploads in both directions, checked by the origin's JSON hash.
head -c 67108864 /dev/urandom >"$TMP/upload-64m.bin"
UPLOAD_HASH=$(sha256 "$TMP/upload-64m.bin")
curl --config "$TMP/http.conf" -fsS --data-binary @"$TMP/upload-64m.bin" \
    http://127.0.0.1:18080/upload -o "$TMP/upload-http.json"
curl --config "$TMP/https.conf" -fsS --data-binary @"$TMP/upload-64m.bin" \
    https://127.0.0.1:18443/upload -o "$TMP/upload-connect.json"
for file in "$TMP/upload-http.json" "$TMP/upload-connect.json"; do
    python3 - "$file" "$UPLOAD_HASH" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["received"] == 67108864, value
assert value["sha256"] == sys.argv[2], value
PY
done
rm -f "$TMP/upload-64m.bin"

sleep 25
AFTER_RSS=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status")
AFTER_FD=$(find "/proc/$PID/fd" -mindepth 1 -maxdepth 1 | wc -l)
printf 'stream after rss_kib=%s fds=%s\n' "$AFTER_RSS" "$AFTER_FD" \
    | tee -a "$REPORT_DIR/streaming.txt"
[ "$AFTER_FD" -le $((BASELINE_FD + 8)) ] \
    || fail "FD did not return: baseline $BASELINE_FD, after $AFTER_FD"
[ "$AFTER_RSS" -le $((BASELINE_RSS + 65536)) ] \
    || fail "RSS did not return: baseline $BASELINE_RSS, after $AFTER_RSS"
[ "$MAX_PEAK_RSS" -le 524288 ] \
    || fail "peak RSS exceeded 512 MiB: $MAX_PEAK_RSS KiB"
printf 'stream peak_rss_kib=%s\n' "$MAX_PEAK_RSS" \
    | tee -a "$REPORT_DIR/streaming.txt"
log "streaming checks passed baseline_rss=$BASELINE_RSS after_rss=$AFTER_RSS"
