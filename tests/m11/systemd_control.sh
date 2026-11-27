#!/usr/bin/env bash
# M11 acceptance: installed angara-control.service, peer rights, atomic writes,
# crash restart and explicit restart/stop.
set -euo pipefail
source "$(dirname -- "$0")/../m08/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
CLIENT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/control_client.py"
CONTROL_SERVICE=angara-control.service
PUBLIC=/run/angara/control.sock
PRIVATE=/run/angara/control-read.sock
READER=m11-reader
ADMIN=m11-admin
NEW_USER=m11-first
NEW_PASSWORD='M11-synthetic-password-71'
ORIGIN_PORT=18080
PROXY_PORT=3128
TMP=$(mktemp -d)
CLIENT_TMP=$(mktemp /tmp/m11-control-client.XXXXXX.py)
ORIGIN_PID=
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

journal_dump() {
    systemctl status angara.service "$CONTROL_SERVICE" --no-pager >&2 2>&1 || true
    journalctl -u angara.service -u "$CONTROL_SERVICE" --since "$START_TIME" \
        --no-pager >&2 2>&1 || true
}

cleanup() {
    [ -z "$ORIGIN_PID" ] || kill "$ORIGIN_PID" 2>/dev/null || true
    systemctl stop "$CONTROL_SERVICE" angara.service 2>/dev/null || true
    userdel "$READER" >/dev/null 2>&1 || true
    userdel "$ADMIN" >/dev/null 2>&1 || true
    rm -f "$CLIENT_TMP"
    rm -rf "$TMP"
}
trap 'rc=$?; if [ "$rc" -ne 0 ]; then journal_dump; fi; cleanup' EXIT HUP INT TERM

fail_control() {
    printf 'M11 FAIL: %s\n' "$*" >&2
    journal_dump
    exit 1
}

json_field() {
    python3 -c '
import json, sys
value = json.load(sys.stdin)
for part in sys.argv[1].split("."):
    value = value[part]
print(value)
' "$1"
}

active() {
    systemctl is-active --quiet angara.service \
        && systemctl is-active --quiet "$CONTROL_SERVICE"
}

wait_both_active() {
    local i
    for i in $(seq 1 200); do
        active && return 0
        sleep 0.1
    done
    fail_control "angara.service and $CONTROL_SERVICE did not become active"
}

wait_snapshot() {
    local i output
    for i in $(seq 1 100); do
        output=$(python3 "$CLIENT" --socket "$PUBLIC" --op snapshot 2>/dev/null || true)
        if printf '%s' "$output" | grep -q '"ok":true'; then
            printf '%s' "$output"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

call_as() {
    local user=$1 op=$2 payload=${3:-}
    if [ -n "$payload" ]; then
        printf '%s' "$payload" | sudo -u "$user" python3 "$CLIENT" --socket "$PUBLIC" --op "$op"
    else
        printf '' | sudo -u "$user" python3 "$CLIENT" --socket "$PUBLIC" --op "$op"
    fi
}

expect_error() {
    local response=$1 code=$2
    [ "$(printf '%s' "$response" | json_field ok)" = "False" ] \
        || fail_control "expected error $code, got $response"
    [ "$(printf '%s' "$response" | json_field error.code)" = "$code" ] \
        || fail_control "expected error $code, got $response"
}

proxy_code() {
    curl --noproxy '' --proxy "http://127.0.0.1:$PROXY_PORT" \
        --config "$TMP/curl.conf" --connect-timeout 3 --max-time 10 \
        -sS -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$ORIGIN_PORT/" 2>/dev/null || true
}

write_config() {
    local temp
    temp=$(mktemp /etc/angara/.m11.XXXXXX)
    cp "$1" "$temp"
    chown root:angara "$temp"
    chmod 0640 "$temp"
    mv -f "$temp" /etc/angara/angara.toml
}

[ -x "$BIN" ] || fail_control "installed binary is missing: $BIN"
[ -f "$CLIENT" ] || fail_control "control client is missing: $CLIENT"
install -m 0755 "$CLIENT" "$CLIENT_TMP"
CLIENT=$CLIENT_TMP

# Fresh synthetic accounts.  The reader has only the proxy group; the admin
# has angara-admin as primary group and angara as a supplementary group.
userdel "$READER" >/dev/null 2>&1 || true
userdel "$ADMIN" >/dev/null 2>&1 || true
useradd --system --gid angara --home-dir /nonexistent \
    --shell /usr/sbin/nologin --no-create-home "$READER"
useradd --system --gid angara --groups angara-admin --home-dir /nonexistent \
    --shell /usr/sbin/nologin --no-create-home "$ADMIN"
id -nG "$READER" | grep -qw angara || fail_control "reader lacks the angara group"
id -nG "$ADMIN" | grep -qw angara-admin || fail_control "administrator lacks angara-admin"
id -nG "$ADMIN" | grep -qw angara || fail_control "administrator lacks the angara socket group"

cat >"$TMP/angara.toml" <<'EOF'
schema_version = 1

[runtime]
worker_threads = 1

[limits]
max_connections = 16
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 5000
idle_timeout_ms = 30000
shutdown_timeout_ms = 5000

[operations]
reload_timeout_ms = 5000

[[listeners]]
id = "m11"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"

[auth]
users_file = "/etc/angara/users.toml"
max_verifying = 2
verify_timeout_ms = 30000

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
EOF
printf 'version = 1\nusers = []\n' >"$TMP/users.toml"
install -m 0640 -o root -g angara "$TMP/users.toml" /etc/angara/users.toml
write_config "$TMP/angara.toml"
runuser -u angara -- "$BIN" check --config /etc/angara/angara.toml >/dev/null \
    || fail_control "installed config does not pass check as angara"

python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port "$ORIGIN_PORT" \
    --log "$TMP/origin.log" >"$TMP/origin.out" 2>"$TMP/origin.err" &
ORIGIN_PID=$!
wait_port 127.0.0.1 "$ORIGIN_PORT"

systemctl stop "$CONTROL_SERVICE" angara.service >/dev/null 2>&1 || true
systemctl reset-failed angara.service "$CONTROL_SERVICE" >/dev/null 2>&1 || true
log "M11 setup: starting angara.service and $CONTROL_SERVICE"
systemctl start angara.service "$CONTROL_SERVICE"
wait_both_active
log "M11 setup: units active, waiting for control snapshot"
wait_server_ready() {
    local i
    for i in $(seq 1 3); do
        if wait_snapshot >/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    log "control diagnostics: socket directory"
    ls -l /run/angara >&2 || true
    log "control diagnostics: environment"
    systemctl show -p Environment angara.service >&2 || true
    log "control diagnostics: admin hello"
    call_as "$ADMIN" hello >&2 || true
    log "control diagnostics: admin snapshot"
    call_as "$ADMIN" snapshot >&2 || true
    fail_control "proxy/control did not become ready"
}
wait_server_ready

log "M11 step 1: units and socket ownership"
# 1. Units and socket ownership.
assert_eq "$(systemctl is-active angara.service)" "active" "angara.service active"
assert_eq "$(systemctl is-active "$CONTROL_SERVICE")" "active" "control active"
assert_eq "$(stat -c '%U:%G %a' "$PUBLIC")" "root:angara 660" "public socket"
assert_eq "$(stat -c '%U:%G %a' "$PRIVATE")" "angara:angara 600" "private socket"

log "M11 step 2: read-only angara group"
# 2. Group angara only: read works, write is denied, file is unchanged.
BEFORE=$(sha256 /etc/angara/users.toml)
HELLO=$(call_as "$READER" hello)
[ "$(printf '%s' "$HELLO" | json_field ok)" = "True" ] \
    || fail_control "reader hello failed: $HELLO"
SNAPSHOT=$(call_as "$READER" snapshot)
[ "$(printf '%s' "$SNAPSHOT" | json_field ok)" = "True" ] \
    || fail_control "reader snapshot failed: $SNAPSHOT"
VERSION=$(printf '%s' "$SNAPSHOT" | json_field result.users_version)
DENIED=$(call_as "$READER" user.add "{\"username\":\"$NEW_USER\",\"password\":\"$NEW_PASSWORD\",\"password_confirm\":\"$NEW_PASSWORD\",\"operation_id\":\"reader-denied\",\"expected_version\":\"$VERSION\"}")
expect_error "$DENIED" unauthorized
AFTER=$(sha256 /etc/angara/users.toml)
assert_eq "$AFTER" "$BEFORE" "reader write must not change users.toml"

log "M11 step 3: user outside both groups is denied"
# 3. A user outside both groups cannot connect.
if sudo -u nobody python3 "$CLIENT" --socket "$PUBLIC" --op hello >/dev/null 2>&1; then
    fail_control "nobody unexpectedly connected to control.sock"
fi

log "M11 step 4: authorized writer add/block/clear"
# 4. Authorized writer: add a fresh account and use it.
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
ADD=$(call_as "$ADMIN" user.add "{\"username\":\"$NEW_USER\",\"password\":\"$NEW_PASSWORD\",\"password_confirm\":\"$NEW_PASSWORD\",\"operation_id\":\"admin-add\",\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$ADD" | json_field result.state)" "applied" "user.add"
printf 'proxy-user = "%s:%s"\n' "$NEW_USER" "$NEW_PASSWORD" >"$TMP/curl.conf"
chmod 0600 "$TMP/curl.conf"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 200 \
    --config "$TMP/curl.conf"
printf 'proxy-user = "%s:%s"\n' "$NEW_USER" "$NEW_PASSWORD" >"$TMP/curl.conf"
assert_eq "$(proxy_code)" "200" "new account request"

assert_eq "$(stat -c '%U:%G %a' /etc/angara/users.toml)" "root:angara 640" "users metadata"
USERS_TEXT=$(cat /etc/angara/users.toml)
printf '%s' "$USERS_TEXT" | grep -q '\[\[users\]\]' \
    || fail_control "users file has no [[users]] after first add"

DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
BLOCK=$(call_as "$ADMIN" block.set "{\"username\":\"$NEW_USER\",\"permanent\":true,\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$BLOCK" | json_field result.state)" "applied" "block.set"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 407 \
    --config "$TMP/curl.conf"
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
CLEAR=$(call_as "$ADMIN" block.clear "{\"username\":\"$NEW_USER\",\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$CLEAR" | json_field result.state)" "applied" "block.clear"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 200 \
    --config "$TMP/curl.conf"

log "M11 step 5: crash restart keeps the public socket"
# 5. Crash restart: the public writer socket must survive the proxy restart.
OLD_PID=$(systemctl show -p MainPID --value angara.service)
OLD_INSTANCE=$(wait_snapshot | json_field result.instance_id)
kill -9 "$OLD_PID"
NEW_PID=
for _ in $(seq 1 300); do
    CANDIDATE=$(systemctl show -p MainPID --value angara.service 2>/dev/null || true)
    if [ -n "$CANDIDATE" ] && [ "$CANDIDATE" != "0" ] \
        && [ "$CANDIDATE" != "$OLD_PID" ] && active; then
        NEW_PID=$CANDIDATE
        break
    fi
    sleep 0.1
done
[ -n "$NEW_PID" ] || fail_control "proxy did not restart after kill -9"
wait_server_ready
assert_eq "$(test -S "$PUBLIC" && echo yes || echo no)" "yes" "public socket after crash"
NEW_INSTANCE=$(wait_snapshot | json_field result.instance_id)
[ "$NEW_INSTANCE" != "$OLD_INSTANCE" ] \
    || fail_control "instance_id did not change after crash restart"
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
BLOCK2=$(call_as "$ADMIN" block.set "{\"username\":\"$NEW_USER\",\"permanent\":true,\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$BLOCK2" | json_field result.state)" "applied" "post-crash block.set"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 407 \
    --config "$TMP/curl.conf"
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
CLEAR2=$(call_as "$ADMIN" block.clear "{\"username\":\"$NEW_USER\",\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$CLEAR2" | json_field result.state)" "applied" "post-crash block.clear"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 200 \
    --config "$TMP/curl.conf"

log "M11 step 6: explicit restart propagates to the writer"
# 6. Explicit restart propagates to the writer through PartOf=.
systemctl restart angara.service
wait_both_active
wait_server_ready
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 200 \
    --config "$TMP/curl.conf"
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
BLOCK3=$(call_as "$ADMIN" block.set "{\"username\":\"$NEW_USER\",\"permanent\":true,\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$BLOCK3" | json_field result.state)" "applied" "restart block.set"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 407 \
    --config "$TMP/curl.conf"
DISK_VERSION=$(call_as "$ADMIN" config | json_field result.disk_users_version)
CLEAR3=$(call_as "$ADMIN" block.clear "{\"username\":\"$NEW_USER\",\"expected_version\":\"$DISK_VERSION\"}")
assert_eq "$(printf '%s' "$CLEAR3" | json_field result.state)" "applied" "restart block.clear"
wait_http_code "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$ORIGIN_PORT/" 200 \
    --config "$TMP/curl.conf"

log "M11 step 7: stop removes both units and sockets"
# 7. Stop removes both units and both sockets.
systemctl stop angara.service
for _ in $(seq 1 200); do
    if ! systemctl is-active --quiet angara.service \
        && ! systemctl is-active --quiet "$CONTROL_SERVICE"; then
        break
    fi
    sleep 0.1
done
if systemctl is-active --quiet angara.service \
    || systemctl is-active --quiet "$CONTROL_SERVICE"; then
    fail_control "stop left a unit active"
fi
[ ! -e "$PUBLIC" ] || fail_control "public socket survived stop"
[ ! -e "$PRIVATE" ] || fail_control "private socket survived stop"

# Secrets must not reach either unit journal.
LOG=$(journalctl -u angara.service -u "$CONTROL_SERVICE" --since "$START_TIME" -o cat --no-pager 2>/dev/null || true)
if printf '%s' "$LOG" | grep -Fq "$NEW_PASSWORD"; then
    fail_control "password marker found in journal"
fi
if printf '%s' "$LOG" | grep -Fq '$argon2id$'; then
    fail_control "PHC marker found in journal"
fi

printf 'M11 systemd control checks passed\n'
