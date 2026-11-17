#!/usr/bin/env bash
# Hour-scale soak stand on the installed systemd service.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
DURATION=${M08_SOAK_SECONDS:-3600}
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

PASSWORD='M08-SOAK-SYNTHETIC'
python3 "$M08_DIR/pki.py" --dir "$TMP/pki"
"$M08_DIR/make_users.sh" "$BIN" "$TMP/users.toml" "$PASSWORD"
printf '%s\n' "$PASSWORD" >"$TMP/password"
chmod 0600 "$TMP/password"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin-http.log" >"$TMP/http.out" 2>"$TMP/http.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18443 \
    --cert "$TMP/pki/site_chain.pem" --key "$TMP/pki/site_key.pem" \
    --log "$TMP/origin-site.log" >"$TMP/site.out" 2>"$TMP/site.err" &
PIDS="$PIDS $!"
wait_port 127.0.0.1 18080
wait_port 127.0.0.1 18443

install -d -m 0750 -o root -g angara /etc/angara/tls
install -m 0640 -o root -g angara "$TMP/users.toml" /etc/angara/users.toml
install -m 0640 -o root -g angara "$TMP/pki/proxy_chain.pem" /etc/angara/tls/proxy-chain.pem
install -m 0640 -o root -g angara "$TMP/pki/proxy_key.pem" /etc/angara/tls/proxy-key.pem
python3 "$M08_DIR/make_config.py" --output "$TMP/angara.toml" --mode functional \
    --http-port 3128 --https-port 3129 --https2-port 0 --site-port 18443 \
    --extra-port 0 --allow-ports 18080,18443 \
    --users-file /etc/angara/users.toml \
    --tls-cert /etc/angara/tls/proxy-chain.pem \
    --tls-key /etc/angara/tls/proxy-key.pem \
    --workers 2 --https-users alice,bob --max-verifying 16 \
    --shutdown-ms 10000 --reload-ms 5000 \
    --idle-ms 60000 --metrics-interval 1000 \
    --max-connections 512 --max-client-connections 256
TMPCONF=$(mktemp /etc/angara/.soak.XXXXXX)
cp "$TMP/angara.toml" "$TMPCONF"
chown root:angara "$TMPCONF"
chmod 0640 "$TMPCONF"
mv -f "$TMPCONF" /etc/angara/angara.toml
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/ 200
PID=$(systemctl show -p MainPID --value angara.service)
unset NO_PROXY no_proxy
printf 'soak stand pid=%s duration=%s nproc=%s NO_PROXY=%s\n' \
    "$PID" "$DURATION" "$(nproc)" "${NO_PROXY:-unset}" \
    | tee "$REPORT_DIR/soak-stand.txt"
systemctl show -p CPUAffinity -p AllowedCPUs -p CPUQuotaPerSecUSec angara.service \
    >>"$REPORT_DIR/soak-stand.txt" 2>&1 || true
journalctl -u angara.service -n 0 --show-cursor --no-pager 2>/dev/null \
    | sed -n 's/^-- cursor: //p' >"$TMP/cursor"
mkdir -p "$TMP/soak"

python3 "$M08_DIR/soak.py" \
    --duration "$DURATION" --batch-seconds 300 --clients 20 \
    --warmup-seconds 120 --warmup-idle 30 \
    --proxy-http http://127.0.0.1:3128 \
    --proxy-https https://127.0.0.1:3129 \
    --proxy-ca "$TMP/pki/proxy_ca.pem" \
    --site https://127.0.0.1:18443 \
    --site-ca "$TMP/pki/site_ca.pem" \
    --password-file "$TMP/password" \
    --origin-port 18080 --site-port 18443 \
    --connect-log "$TMP/origin-site.log" \
    --pid "$PID" --report "$REPORT_DIR/soak.json" \
    --workdir "$TMP/soak" | tee "$REPORT_DIR/soak.txt"

CURSOR=$(cat "$TMP/cursor")
if [ -n "$CURSOR" ]; then
    journalctl -u angara.service --after-cursor "$CURSOR" -o cat --no-pager \
        | grep '"event":"metrics_summary"' >"$REPORT_DIR/soak-metrics.jsonl" || true
else
    journalctl -u angara.service --since '90 minutes ago' -o cat --no-pager \
        | grep '"event":"metrics_summary"' >"$REPORT_DIR/soak-metrics.jsonl" || true
fi
angaractl status >"$REPORT_DIR/soak-status.txt" 2>&1 || true
log "soak complete: $REPORT_DIR/soak.json"
