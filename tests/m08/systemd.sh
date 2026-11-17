#!/usr/bin/env bash
# Live systemd checks on an installed Angara archive.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
TMP=$(mktemp -d)
SLOW_PID=
STALL_PID=
cleanup() {
    [ -z "$SLOW_PID" ] || kill "$SLOW_PID" 2>/dev/null || true
    [ -z "$STALL_PID" ] || kill "$STALL_PID" 2>/dev/null || true
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
trap 'rc=$?; if [ "$rc" -ne 0 ]; then systemctl status angara.service --no-pager >&2 2>&1 || true; journalctl -u angara.service -n 80 --no-pager >&2 2>&1 || true; fi' ERR
umask 077

python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin.log" >"$TMP/origin.out" 2>"$TMP/origin.err" &
ORIGIN_PID=$!
cleanup() {
    [ -z "$SLOW_PID" ] || kill "$SLOW_PID" 2>/dev/null || true
    [ -z "$STALL_PID" ] || kill "$STALL_PID" 2>/dev/null || true
    kill "$ORIGIN_PID" 2>/dev/null || true
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
wait_port 127.0.0.1 18080

write_config() {
    local source=$1
    local target=/etc/angara/angara.toml
    local temp
    temp=$(mktemp /etc/angara/.angara.XXXXXX)
    cp "$source" "$temp"
    chown root:angara "$temp"
    chmod 0640 "$temp"
    mv -f "$temp" "$target"
}

reload_event() {
    local event=$1 outcome=${2:-}
    local cursor output
    cursor=$(journalctl -u angara.service -n 0 --show-cursor --no-pager 2>/dev/null \
        | sed -n 's/^-- cursor: //p')
    systemctl reload angara.service
    for _ in $(seq 1 100); do
        if [ -n "$cursor" ]; then
            output=$(journalctl -u angara.service --after-cursor "$cursor" -o cat --no-pager 2>/dev/null || true)
        else
            output=$(journalctl -u angara.service --since '30 seconds ago' -o cat --no-pager 2>/dev/null || true)
        fi
        if printf '%s\n' "$output" | grep -q "\"event\":\"$event\""; then
            if [ -z "$outcome" ] || printf '%s\n' "$output" | grep -q "\"outcome\":\"$outcome\""; then
                printf '%s\n' "$output"
                return 0
            fi
        fi
        sleep 0.1
    done
    fail "reload event not observed: $event ($outcome)"
}

journal_recent() {
    journalctl -u angara.service --since '5 minutes ago' -o cat --no-pager 2>/dev/null || true
}

reset_failed() {
    systemctl reset-failed angara.service >/dev/null 2>&1 || true
}

systemctl enable angara.service >/dev/null 2>&1 || true
reset_failed
systemctl start angara.service
wait_service_active
systemd-analyze verify /etc/systemd/system/angara.service

# Initial deny-by-default and service identity.
PID=$(systemctl show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "service has no main PID"
assert_eq "$(ps -o uid= -p "$PID" | tr -d ' ')" "$(id -u angara)" "service UID"
assert_eq "$(ps -o gid= -p "$PID" | tr -d ' ')" "$(id -g angara)" "service GID"
assert_eq "$(awk '/^CapEff:/{print $2}' "/proc/$PID/status")" \
    "0000000000000000" "effective capabilities"
test -r "/proc/$PID/status" || fail "/proc/self/status is not readable"
assert_eq "$(systemctl show -p NoNewPrivileges --value angara.service)" "yes" "NoNewPrivileges"
assert_eq "$(systemctl show -p ProtectSystem --value angara.service)" "strict" "ProtectSystem"
assert_eq "$(systemctl show -p ProtectHome --value angara.service)" "yes" "ProtectHome"
assert_eq "$(systemctl show -p PrivateTmp --value angara.service)" "yes" "PrivateTmp"
assert_eq "$(systemctl show -p PrivateDevices --value angara.service)" "yes" "PrivateDevices"
assert_eq "$(systemctl show -p ProtectKernelTunables --value angara.service)" "yes" "ProtectKernelTunables"
assert_eq "$(systemctl show -p ProtectKernelModules --value angara.service)" "yes" "ProtectKernelModules"
assert_eq "$(systemctl show -p ProtectControlGroups --value angara.service)" "yes" "ProtectControlGroups"
assert_eq "$(systemctl show -p RestrictSUIDSGID --value angara.service)" "yes" "RestrictSUIDSGID"
assert_eq "$(systemctl show -p LimitNOFILE --value angara.service)" "16384" "LimitNOFILE"
assert_eq "$(systemctl show -p TasksMax --value angara.service)" "512" "TasksMax"
assert_eq "$(systemctl show -p KillMode --value angara.service)" "control-group" "KillMode"
systemctl show -p TimeoutStopUSec --value angara.service | grep -Eq '315|5min 15s'
assert_eq "$(awk '/Max open files/{print $4}' "/proc/$PID/limits")" "16384" "process LimitNOFILE"
ss -ltnp | grep -q "127.0.0.1:3128.*pid=$PID"
runuser -u angara -- "$BIN" check --config /etc/angara/angara.toml >/dev/null

ORIGIN_BEFORE=$(line_count "$TMP/origin.log")
CODE=$(http_code http://127.0.0.1:3128 http://127.0.0.1:18080/)
assert_eq "$CODE" "403" "initial default deny"
sleep 0.3
ORIGIN_AFTER=$(line_count "$TMP/origin.log")
assert_eq "$ORIGIN_AFTER" "$ORIGIN_BEFORE" "initial deny origin connections"

# Apply an allowing generation with a 1 s metrics interval.  The interval is
# restart-required, so this first transition is a restart; all later checks use
# reload on configs with identical static fields.
COMMON=(
    --http-port 3128 --https-port 0 --extra-port 0
    --workers auto --shutdown-ms 10000 --reload-ms 5000 --idle-ms 60000
    --metrics-interval 1000
)
python3 "$M08_DIR/make_config.py" --output "$TMP/allow.toml" --mode functional \
    "${COMMON[@]}"
write_config "$TMP/allow.toml"
runuser -u angara -- "$BIN" check --config /etc/angara/angara.toml \
    || fail "G1 config is not readable/valid for angara"
reset_failed
if ! systemctl restart angara.service; then
    systemctl status angara.service --no-pager >&2 || true
    journalctl -u angara.service -n 80 --no-pager >&2 || true
    fail "systemctl restart with G1 config failed"
fi
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
PID=$(systemctl show -p MainPID --value angara.service)

# Same keep-alive connection: allowed G1, then denied G2 after reload.
python3 "$M08_DIR/keepalive.py" --proxy-port 3128 --origin-port 18080 \
    --wait-file "$TMP/keepalive.marker" >"$TMP/keepalive.out" 2>"$TMP/keepalive.err" &
KEEPALIVE_PID=$!
for _ in $(seq 1 100); do
    grep -q 'first=200' "$TMP/keepalive.out" 2>/dev/null && break
    sleep 0.1
done
grep -q 'first=200' "$TMP/keepalive.out" || fail "keep-alive first request failed"
python3 "$M08_DIR/make_config.py" --output "$TMP/deny.toml" --mode functional \
    "${COMMON[@]}" --deny
write_config "$TMP/deny.toml"
OUT=$(reload_event reload_applied)
printf '%s\n' "$OUT" >"$TMP/reload-allow-to-deny.txt"
touch "$TMP/keepalive.marker"
if ! wait "$KEEPALIVE_PID"; then
    cat "$TMP/keepalive.out" "$TMP/keepalive.err" >&2
    fail "keep-alive reload probe failed"
fi
grep -q 'second=403' "$TMP/keepalive.out"

# Invalid file and restart-required change leave the running process intact.
PID=$(systemctl show -p MainPID --value angara.service)
python3 "$M08_DIR/make_config.py" --output "$TMP/invalid.toml" --mode invalid
write_config "$TMP/invalid.toml"
OUT=$(reload_event reload_rejected)
printf '%s\n' "$OUT" >"$TMP/reload-invalid.txt"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$PID" "invalid reload PID"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 403

python3 "$M08_DIR/make_config.py" --output "$TMP/restart.toml" --mode default \
    --http-port 3130 --shutdown-ms 10000 --reload-ms 5000 \
    --metrics-interval 1000
write_config "$TMP/restart.toml"
OUT=$(reload_event reload_rejected restart_required)
printf '%s\n' "$OUT" >"$TMP/reload-restart.txt"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$PID" "restart-required PID"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 403
if ss -ltn | grep -q ':3130'; then
    fail "restart-required reload opened the new listener"
fi

# Restore allowed G1 and exercise the bounded SIGHUP coalescer.
write_config "$TMP/allow.toml"
reload_event reload_applied >/dev/null
CURSOR=$(journalctl -u angara.service -n 0 --show-cursor --no-pager 2>/dev/null \
    | sed -n 's/^-- cursor: //p')
for _ in $(seq 1 20); do
    kill -HUP "$PID"
done
sleep 3
EVENTS=$(journalctl -u angara.service --after-cursor "$CURSOR" -o cat --no-pager \
    | grep -c '"event":"reload_applied"' || true)
[ "$EVENTS" -ge 1 ] && [ "$EVENTS" -le 3 ] || fail "SIGHUP storm produced $EVENTS reload events"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$PID" "storm PID"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

# JSON log shape and bounded records.
sleep 2
journal_recent >"$TMP/journal.jsonl"
grep -q '"event":"service_started"' "$TMP/journal.jsonl"
grep -q '"event":"request_finished"' "$TMP/journal.jsonl"
grep -q '"event":"reload_applied"' "$TMP/journal.jsonl"
grep -q '"event":"reload_rejected"' "$TMP/journal.jsonl"
grep -q '"event":"metrics_summary"' "$TMP/journal.jsonl"
python3 - "$TMP/journal.jsonl" <<'PY'
import json, sys
count = 0
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    assert len(line.encode()) <= 4096, len(line)
    value = json.loads(line)
    assert value["schema_version"] == 1
    assert value["event"] != ""
    count += 1
assert count > 0
PY
if grep -Eq 'alice|bob|Proxy-Authorization|Authorization|synthetic' "$TMP/journal.jsonl"; then
    fail "journal contains a username, credential or synthetic marker"
fi

# Graceful stop: a real, completable 16 MiB exchange must finish within the
# application deadline with the client receiving every byte.
python3 "$M08_DIR/make_config.py" --output "$TMP/stop.toml" --mode functional \
    "${COMMON[@]}" --shutdown-ms 15000
write_config "$TMP/stop.toml"
reload_event reload_applied >/dev/null
GRACEFUL_HASH=$(python3 "$M08_DIR/origin.py" --print-hash 16777216)
curl --noproxy '' --proxy http://127.0.0.1:3128 --limit-rate 4m \
    "http://127.0.0.1:18080/download?bytes=16777216" \
    -o "$TMP/slow.bin" >"$TMP/slow.out" 2>"$TMP/slow.err" &
SLOW_PID=$!
for _ in $(seq 1 100); do
    [ -s "$TMP/slow.bin" ] && break
    sleep 0.1
done
[ -s "$TMP/slow.bin" ] || fail "graceful download did not start"
START_MS=$(date +%s%3N)
systemctl stop angara.service
END_MS=$(date +%s%3N)
ELAPSED=$((END_MS - START_MS))
[ "$ELAPSED" -le 16000 ] || fail "graceful stop took ${ELAPSED}ms"
set +e
wait "$SLOW_PID"
SLOW_CODE=$?
set -e
SLOW_PID=
wait_service_inactive 20
assert_eq "$SLOW_CODE" "0" "graceful client exit"
assert_eq "$(wc -c <"$TMP/slow.bin")" "16777216" "graceful client bytes"
assert_eq "$(sha256 "$TMP/slow.bin")" "$GRACEFUL_HASH" "graceful client hash"
assert_eq "$(systemctl show -p Result --value angara.service)" "success" "graceful stop result"
assert_eq "$(systemctl show -p ExecMainStatus --value angara.service)" "0" "graceful stop status"
if ss -ltn | grep -q ':3128'; then fail "graceful stop left the listener open"; fi
reset_failed
systemctl start angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

# Forced shutdown with a client that never reads the response.
python3 "$M08_DIR/make_config.py" --output "$TMP/force.toml" --mode functional \
    "${COMMON[@]}" --shutdown-ms 500
write_config "$TMP/force.toml"
reload_event reload_applied >/dev/null
python3 - 127.0.0.1 3128 18080 <<'PY' >"$TMP/stall.out" 2>"$TMP/stall.err" &
import re
import socket
import sys
import time

proxy, port, origin = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sock = socket.create_connection((proxy, port), timeout=5)
sock.sendall((
    f"GET http://127.0.0.1:{origin}/download?bytes=268435456&delay_ms=1 HTTP/1.1\r\n"
    f"Host: 127.0.0.1:{origin}\r\n\r\n"
).encode())
# Do not read while the test stops the service.  After the force deadline the
# client itself must observe reset/EOF and an incomplete body.
time.sleep(2)
sock.settimeout(5)
data = b""
cap = 32 * 1024 * 1024
eof = False
try:
    while len(data) < cap:
        chunk = sock.recv(65536)
        if not chunk:
            eof = True
            break
        data += chunk
except (ConnectionResetError, BrokenPipeError):
    print("reset")
    raise SystemExit(0)
except socket.timeout:
    print("timeout")
    raise SystemExit(3)
except OSError as error:
    print(f"error:{error}")
    raise SystemExit(3)
if not eof:
    try:
        extra = sock.recv(1)
        if not extra:
            eof = True
    except (ConnectionResetError, BrokenPipeError):
        print("reset")
        raise SystemExit(0)
    except socket.timeout:
        pass
if b"\r\n\r\n" not in data:
    print("short")
    raise SystemExit(0)
header, body = data.split(b"\r\n\r\n", 1)
match = re.search(rb"(?i)Content-Length:\s*(\d+)", header)
if match is None:
    print("short")
    raise SystemExit(0)
expected = int(match.group(1))
if len(body) < expected:
    if eof:
        print("short")
        raise SystemExit(0)
    print("open")
    raise SystemExit(3)
print("complete")
raise SystemExit(1)
PY
STALL_PID=$!
sleep 1
CGROUP_BEFORE=$(systemctl show -p ControlGroup --value angara.service)
[ -n "$CGROUP_BEFORE" ] || fail "forced stop has no cgroup before stop"
FORCE_CURSOR=$(journalctl -u angara.service -n 0 --show-cursor --no-pager 2>/dev/null \
    | sed -n 's/^-- cursor: //p')
START_MS=$(date +%s%3N)
systemctl stop angara.service
END_MS=$(date +%s%3N)
ELAPSED=$((END_MS - START_MS))
[ "$ELAPSED" -le 3000 ] || fail "forced stop took ${ELAPSED}ms"
CLIENT_DONE=0
for _ in $(seq 1 100); do
    if ! kill -0 "$STALL_PID" 2>/dev/null; then
        CLIENT_DONE=1
        break
    fi
    sleep 0.1
done
if [ "$CLIENT_DONE" -ne 1 ]; then
    kill "$STALL_PID" 2>/dev/null || true
    wait "$STALL_PID" 2>/dev/null || true
    STALL_PID=
    fail "forced client did not observe shutdown within 10s"
fi
set +e
wait "$STALL_PID"
STALL_CODE=$?
set -e
STALL_PID=
[ "$STALL_CODE" -eq 0 ] \
    || fail "forced client did not observe interruption (exit $STALL_CODE)"
grep -Eq '^(reset|short)$' "$TMP/stall.out" \
    || { cat "$TMP/stall.out" >&2; fail "forced client result was not reset/short"; }
wait_service_inactive 20
assert_eq "$(systemctl show -p Result --value angara.service)" "success" "forced stop result"
assert_eq "$(systemctl show -p ExecMainStatus --value angara.service)" "0" "forced stop status"
if ss -ltn | grep -q ':3128'; then fail "forced stop left the listener open"; fi
if pgrep -f '[/]opt/angara/.*/bin/angara serve' >/dev/null 2>&1; then
    fail "a serve process survived forced shutdown"
fi
CGROUP_AFTER=$(systemctl show -p ControlGroup --value angara.service)
if [ -n "$CGROUP_AFTER" ] \
    && [ -e "/sys/fs/cgroup$CGROUP_AFTER/cgroup.procs" ] \
    && [ -s "/sys/fs/cgroup$CGROUP_AFTER/cgroup.procs" ]; then
    fail "forced stop left processes in $CGROUP_AFTER (before: $CGROUP_BEFORE)"
fi
if journalctl -u angara.service --after-cursor "$FORCE_CURSOR" -o cat --no-pager 2>/dev/null \
    | grep -Eq 'Killing process|status=9/KILL|signal=KILL'; then
    fail "systemd had to SIGKILL the forced shutdown"
fi
reset_failed
systemctl start angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

# Crash restart and intentional stop.
reset_failed
PID=$(systemctl show -p MainPID --value angara.service)
kill -KILL "$PID"
for _ in $(seq 1 100); do
    NEW_PID=$(systemctl show -p MainPID --value angara.service)
    if [ "$NEW_PID" != "0" ] && [ "$NEW_PID" != "$PID" ] \
        && systemctl is-active --quiet angara.service; then
        break
    fi
    sleep 0.1
done
NEW_PID=$(systemctl show -p MainPID --value angara.service)
[ "$NEW_PID" != "0" ] && [ "$NEW_PID" != "$PID" ] || fail "service did not restart after crash"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
systemctl stop angara.service
wait_service_inactive 20
sleep 3
if systemctl is-active --quiet angara.service; then
    fail "intentional stop was restarted"
fi

# Configuration error reaches the start limit; recovery uses reset-failed.
reset_failed
python3 "$M08_DIR/make_config.py" --output "$TMP/invalid.toml" --mode invalid
write_config "$TMP/invalid.toml"
set +e
systemctl start angara.service
START_INVALID=$?
set -e
[ "$START_INVALID" -ne 0 ] || fail "invalid config start unexpectedly succeeded"
for _ in $(seq 1 120); do
    systemctl is-failed --quiet angara.service && break
    sleep 0.1
done
systemctl is-failed --quiet angara.service || fail "invalid config did not reach start limit"
systemctl reset-failed angara.service
write_config "$TMP/allow.toml"
systemctl start angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

# Occupied port fails startup; after freeing it the same unit starts.
systemctl stop angara.service
wait_service_inactive 20
python3 - 3128 <<'PY' >"$TMP/occupier.out" 2>"$TMP/occupier.err" &
import socket, sys, time
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.listen(1)
time.sleep(30)
PY
OCCUPIER_PID=$!
wait_port 127.0.0.1 3128
set +e
systemctl start angara.service
START_OCCUPIED=$?
set -e
# Type=exec may report success once the process was exec'd even if the process
# immediately fails to bind.  Readiness is separate from the start job result.
for _ in $(seq 1 120); do
    if systemctl is-failed --quiet angara.service; then
        break
    fi
    if ! systemctl is-active --quiet angara.service && \
        [ "$(systemctl show -p ActiveState --value angara.service)" = "inactive" ]; then
        break
    fi
    sleep 0.1
done
if systemctl is-active --quiet angara.service; then
    fail "occupied-port service stayed active (start exit $START_OCCUPIED)"
fi
systemctl is-failed --quiet angara.service || \
    [ "$(systemctl show -p ActiveState --value angara.service)" = "inactive" ] || \
    fail "occupied port did not reach a failed/inactive state"
systemctl reset-failed angara.service
kill "$OCCUPIER_PID" 2>/dev/null || true
wait "$OCCUPIER_PID" 2>/dev/null || true
systemctl start angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200

# Final state is valid and enabled.
systemctl is-enabled --quiet angara.service || fail "service is not enabled"
assert_eq "$(systemctl show -p Restart --value angara.service)" "on-failure" "Restart policy"
log "systemd checks passed"
