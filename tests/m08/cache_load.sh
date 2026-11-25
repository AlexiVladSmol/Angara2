#!/usr/bin/env bash
# M10 cache load evidence on the installed Linux binary.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
REPORT_DIR=${M08_REPORT_DIR:-"$PWD/m08-reports"}
mkdir -p "$REPORT_DIR"
python3 "$M08_DIR/cache_load.py" \
    --bin "$BIN" \
    --report-dir "$REPORT_DIR" \
    --proxy-port 3130 \
    --origin-port 18081 \
    --requests 200
log "cache load evidence complete: $REPORT_DIR/cache-load.json"
