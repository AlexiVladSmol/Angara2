#!/usr/bin/env bash
# Compare 1/2/4 Tokio workers on the installed service with an HTTP-only load.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
REPORT_DIR=${M08_REPORT_DIR:-"$PWD/m08-reports"}
mkdir -p "$REPORT_DIR"
TMP=$(mktemp -d)
ORIGIN_PID=
cleanup() {
    [ -z "$ORIGIN_PID" ] || kill "$ORIGIN_PID" 2>/dev/null || true
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin.log" >"$TMP/origin.out" 2>"$TMP/origin.err" &
ORIGIN_PID=$!
wait_port 127.0.0.1 18080

CPUS=$(nproc)
CPU_LIST=$(python3 - <<'PY'
import os
try:
    print(sorted(os.sched_getaffinity(0)))
except Exception:
    print([])
PY
)
printf 'workers_test host_cpus=%s affinity=%s\n' "$CPUS" "$CPU_LIST" | tee "$REPORT_DIR/workers.txt"
systemctl show -p CPUAffinity -p AllowedCPUs -p CPUQuotaPerSecUSec angara.service \
    >>"$REPORT_DIR/workers.txt" 2>&1 || true

for workers in 1 2 4; do
    if [ "$workers" -eq 4 ] && [ "$CPUS" -lt 4 ]; then
        printf 'workers=%s skipped: only %s CPUs available\n' "$workers" "$CPUS" \
            | tee -a "$REPORT_DIR/workers.txt"
        continue
    fi
    python3 "$M08_DIR/make_config.py" --output "$TMP/$workers.toml" --mode functional \
        --http-port 3128 --https-port 0 --extra-port 0 --workers "$workers" \
        --shutdown-ms 10000 --reload-ms 5000 --idle-ms 60000 --metrics-interval 1000
    TMPCONF=$(mktemp /etc/angara/.workers.XXXXXX)
    cp "$TMP/$workers.toml" "$TMPCONF"
    chown root:angara "$TMPCONF"
    chmod 0640 "$TMPCONF"
    mv -f "$TMPCONF" /etc/angara/angara.toml
    systemctl restart angara.service
    wait_service_active
    wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
    "$BIN" check --config /etc/angara/angara.toml >"$TMP/check-$workers.txt"
    grep -q "worker_threads=$workers" "$TMP/check-$workers.txt"
    PID=$(systemctl show -p MainPID --value angara.service)
    printf 'workers=%s pid=%s configured_threads=%s\n' "$workers" "$PID" "$(cat "$TMP/check-$workers.txt")" \
        | tee -a "$REPORT_DIR/workers.txt"
    python3 "$M08_DIR/load.py" \
        --clients 10 --duration 20 --warmup 3 --mix http \
        --proxy-http http://127.0.0.1:3128 --origin-port 18080 \
        --pid "$PID" --report "$REPORT_DIR/load-http-workers-$workers.json" \
        --after-wait 20 >"$TMP/load-$workers.txt"
    cat "$TMP/load-$workers.txt" | tee -a "$REPORT_DIR/workers.txt"
    ps -L -p "$PID" -o tid=,pcpu=,time=,comm= >"$REPORT_DIR/threads-$workers.txt" 2>/dev/null || true
    cat "$REPORT_DIR/threads-$workers.txt" | tee -a "$REPORT_DIR/workers.txt"
done

log "worker comparison complete: $REPORT_DIR/workers.txt"
