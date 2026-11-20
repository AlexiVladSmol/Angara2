#!/usr/bin/env bash
# Shared helpers for the M08 Linux stand tests.
set -euo pipefail
set -E
trap 'm08_rc=$?; case $- in *e*) printf "M08 FAIL: %s:%s: '\''%s'\'' exited %s\n" "${BASH_SOURCE[0]}" "$LINENO" "$BASH_COMMAND" "$m08_rc" >&2 ;; esac' ERR

M08_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$M08_DIR/../.." && pwd)

fail() {
    printf 'M08 FAIL: %s\n' "$*" >&2
    if command -v systemctl >/dev/null 2>&1 \
        && [ -f /etc/systemd/system/angara.service ]; then
        systemctl status angara.service --no-pager >&2 2>&1 || true
        journalctl -u angara.service -n 60 --no-pager >&2 2>&1 || true
    fi
    exit 1
}

log() {
    printf 'M08 %s\n' "$*"
}

assert_eq() {
    [ "$1" = "$2" ] || fail "expected '$2', got '$1' ($3)"
}

require_root() {
    [ "$(id -u)" -eq 0 ] || fail "this test requires root"
}

wait_file() {
    local path=$1 attempts=${2:-100}
    local i
    for i in $(seq 1 "$attempts"); do
        [ -s "$path" ] && return 0
        sleep 0.1
    done
    fail "file did not appear: $path"
}

wait_port() {
    local host=$1 port=$2 attempts=${3:-100}
    local i
    for i in $(seq 1 "$attempts"); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        sleep 0.1
    done
    fail "port did not open: $host:$port"
}

wait_http_code() {
    local proxy=$1 url=$2 expected=$3
    shift 3
    local attempts=100
    if [ "$#" -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
        attempts=$1
        shift
    fi
    local i code
    for i in $(seq 1 "$attempts"); do
        code=$(curl --noproxy '' --proxy "$proxy" --connect-timeout 1 \
            --max-time 3 -sS -o /dev/null -w '%{http_code}' "$@" "$url" 2>/dev/null || true)
        [ "$code" = "$expected" ] && return 0
        sleep 0.1
    done
    fail "HTTP code did not become $expected for $url (last $code)"
}

http_code() {
    local proxy=$1 url=$2
    shift 2
    curl --noproxy '' --proxy "$proxy" --connect-timeout 3 --max-time 10 \
        -sS -o /dev/null -w '%{http_code}' "$@" "$url" 2>/dev/null || true
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

line_count() {
    if [ -f "$1" ]; then
        wc -l <"$1"
    else
        echo 0
    fi
}

journal_cursor() {
    journalctl -u angara.service -n 0 --show-cursor --no-pager 2>/dev/null \
        | sed -n 's/^-- cursor: //p'
}

wait_journal_event() {
    local event=$1 since=${2:-30 seconds ago} attempts=${3:-100}
    local i output
    for i in $(seq 1 "$attempts"); do
        output=$(journalctl -u angara.service --since "$since" -o cat --no-pager 2>/dev/null || true)
        if printf '%s\n' "$output" | grep -q "\"event\":\"$event\""; then
            printf '%s\n' "$output"
            return 0
        fi
        sleep 0.1
    done
    fail "journal event not observed: $event"
}

wait_service_active() {
    local attempts=${1:-100}
    local i
    for i in $(seq 1 "$attempts"); do
        systemctl is-active --quiet angara.service && return 0
        sleep 0.1
    done
    systemctl status angara.service --no-pager >&2 || true
    fail "angara.service did not become active"
}

wait_service_inactive() {
    local attempts=${1:-100}
    local i
    for i in $(seq 1 "$attempts"); do
        systemctl is-active --quiet angara.service || return 0
        sleep 0.1
    done
    fail "angara.service did not become inactive"
}

stop_service() {
    systemctl stop angara.service 2>/dev/null || true
    wait_service_inactive 50
}
