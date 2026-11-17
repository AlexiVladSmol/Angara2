#!/usr/bin/env bash
# Two veth/network-namespace paths plus DNS/IPv6 through the installed unit.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
command -v ip >/dev/null 2>&1 || fail "iproute2 is required"

TMP=$(mktemp -d)
ORIGIN_A_PID=
ORIGIN_B_PID=
ORIGIN_B2_PID=
ORIGIN_V4_PID=
ORIGIN_V6_PID=
NS_A="anga-a-$$"
NS_B="anga-b-$$"
LINK_A="anga0$$"
LINK_B="anga1$$"
LINK_C="anga2$$"
cleanup() {
    for pid in "$ORIGIN_A_PID" "$ORIGIN_B_PID" "$ORIGIN_B2_PID" \
        "$ORIGIN_V4_PID" "$ORIGIN_V6_PID"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
    systemctl stop angara.service 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip link del "$LINK_A" 2>/dev/null || true
    ip link del "$LINK_B" 2>/dev/null || true
    ip link del "$LINK_C" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$LINK_A" type veth peer name "${LINK_A}p"
ip link add "$LINK_B" type veth peer name "${LINK_B}p"
ip link add "$LINK_C" type veth peer name "${LINK_C}p"
ip link set "${LINK_A}p" netns "$NS_A"
ip link set "${LINK_B}p" netns "$NS_B"
ip link set "${LINK_C}p" netns "$NS_B"
ip addr add 10.241.1.1/24 dev "$LINK_A"
ip addr add 10.241.2.1/24 dev "$LINK_B"
ip addr add 10.241.3.1/24 dev "$LINK_C"
ip link set "$LINK_A" up
ip link set "$LINK_B" up
ip link set "$LINK_C" up
ip netns exec "$NS_A" ip addr add 10.241.1.2/24 dev "${LINK_A}p"
ip netns exec "$NS_A" ip link set "${LINK_A}p" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip addr add 10.241.2.2/24 dev "${LINK_B}p"
ip netns exec "$NS_B" ip addr add 10.241.3.2/24 dev "${LINK_C}p"
ip netns exec "$NS_B" ip link set "${LINK_B}p" up
ip netns exec "$NS_B" ip link set "${LINK_C}p" up
ip netns exec "$NS_B" ip link set lo up

ip netns exec "$NS_A" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18080 \
    --log "$TMP/origin-a.log" --accept-log "$TMP/accept-a.log" \
    >"$TMP/origin-a.out" 2>"$TMP/origin-a.err" &
ORIGIN_A_PID=$!
ip netns exec "$NS_B" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18080 \
    --log "$TMP/origin-b.log" --accept-log "$TMP/accept-b.log" \
    >"$TMP/origin-b.out" 2>"$TMP/origin-b.err" &
ORIGIN_B_PID=$!
ip netns exec "$NS_B" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18081 \
    --log "$TMP/origin-b2.log" --accept-log "$TMP/accept-b2.log" \
    >"$TMP/origin-b2.out" 2>"$TMP/origin-b2.err" &
ORIGIN_B2_PID=$!
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18082 \
    --log "$TMP/origin-v4.log" --accept-log "$TMP/accept-v4.log" \
    >"$TMP/origin-v4.out" 2>"$TMP/origin-v4.err" &
ORIGIN_V4_PID=$!
python3 "$M08_DIR/origin.py" --host ::1 --port 18082 \
    --log "$TMP/origin-v6.log" --accept-log "$TMP/accept-v6.log" \
    >"$TMP/origin-v6.out" 2>"$TMP/origin-v6.err" &
ORIGIN_V6_PID=$!
wait_port 10.241.1.2 18080
wait_port 10.241.2.2 18080
wait_port 10.241.2.2 18081
wait_port 127.0.0.1 18082
for _ in $(seq 1 100); do
    python3 - <<'PY' >/dev/null 2>&1 && break
import socket
sock = socket.create_connection(("::1", 18082), timeout=1)
sock.close()
PY
    sleep 0.1
done

python3 "$M08_DIR/make_config.py" --output "$TMP/network.toml" --mode network \
    --http-bind 127.0.0.1 --http-port 3128 \
    --http2-bind 127.0.0.2 --http2-port 3128 \
    --v6-bind ::1 --v6-port 3130 \
    --site-port 18080 --allow-ports 18080,18081,18082 --extra-port 0 \
    --egress-a 10.241.1.1 --egress-b 10.241.2.1 \
    --ip-networks 127.0.0.0/8,10.241.0.0/16,::1/128 \
    --workers 2
TMPCONF=$(mktemp /etc/angara/.network.XXXXXX)
cp "$TMP/network.toml" "$TMPCONF"
chown root:angara "$TMPCONF"
chmod 0640 "$TMPCONF"
mv -f "$TMPCONF" /etc/angara/angara.toml
systemctl restart angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:18080/health 200
wait_port 127.0.0.2 3128
for _ in $(seq 1 100); do
    if curl --noproxy '' --proxy 'http://[::1]:3130' --connect-timeout 1 \
        --max-time 2 -sS -o /dev/null http://127.0.0.1:18082/health 2>/dev/null; then
        break
    fi
    sleep 0.1
done
PID=$(systemctl show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "network service has no PID"
assert_eq "$(ps -o uid= -p "$PID" | tr -d ' ')" "$(id -u angara)" \
    "network service UID"
case "$(readlink -f "/proc/$PID/exe")" in
    *"/releases/"*"/bin/angara") ;;
    *) fail "network service exe is not a release binary" ;;
esac

TX_A_BEFORE=$(cat "/sys/class/net/$LINK_A/statistics/tx_bytes")
TX_B_BEFORE=$(cat "/sys/class/net/$LINK_B/statistics/tx_bytes")
CODE_A=$(http_code http://127.0.0.1:3128 http://10.241.1.2:18080/health)
CODE_B=$(http_code http://127.0.0.2:3128 http://10.241.2.2:18080/health)
assert_eq "$CODE_A" "200" "listener A path"
assert_eq "$CODE_B" "200" "listener B path"
grep -q '^10.241.1.1' "$TMP/origin-a.log" || fail "origin A did not see egress A source"
grep -q '^10.241.2.1' "$TMP/origin-b.log" || fail "origin B did not see egress B source"

# DNS/NSS and IPv6 through the installed unit, not a root foreground process.
CODE_DNS=$(http_code 'http://[::1]:3130' http://localhost:18082/health)
CODE_V6=$(http_code 'http://[::1]:3130' 'http://[::1]:18082/health')
assert_eq "$CODE_DNS" "200" "DNS/NSS path through service"
assert_eq "$CODE_V6" "200" "IPv6 path through service"
printf 'M08 NET DNS=%s IPv6=%s\n' "$CODE_DNS" "$CODE_V6" | tee -a "$TMP/report.txt"

TX_A_AFTER=$(cat "/sys/class/net/$LINK_A/statistics/tx_bytes")
TX_B_AFTER=$(cat "/sys/class/net/$LINK_B/statistics/tx_bytes")
[ "$TX_A_AFTER" -gt "$TX_A_BEFORE" ] || fail "interface A counter did not increase"
[ "$TX_B_AFTER" -gt "$TX_B_BEFORE" ] || fail "interface B counter did not increase"

# Remove the selected egress address.  Origin B2 remains reachable from the
# alternate host route, but the selected egress profile must fail explicitly.
ip addr del 10.241.2.1/24 dev "$LINK_B"
# Keep B2 reachable through the independent third link so a silent egress
# fallback would still reach it.  The route uses a gateway in namespace B; the
# selected egress profile, however, must still fail because its bind address
# is gone.
ip route add 10.241.2.2/32 via 10.241.3.2 dev "$LINK_C"
# Positive control: B2 is still reachable from the host through the alternate
# interface.  The accept caused by this control is part of the baseline.
wait_port 10.241.2.2 18081
B2_ACCEPT_BEFORE=$(line_count "$TMP/accept-b2.log")
CODE_REMOVED=$(http_code http://127.0.0.2:3128 http://10.241.2.2:18081/health)
case "$CODE_REMOVED" in
    502|503|504) ;;
    *) fail "removed egress address returned unexpected HTTP $CODE_REMOVED" ;;
esac
sleep 0.3
B2_ACCEPT_AFTER=$(line_count "$TMP/accept-b2.log")
assert_eq "$B2_ACCEPT_AFTER" "$B2_ACCEPT_BEFORE" "removed-egress TCP accepts"
printf 'M08 NET removed egress: code=%s origin_b_accepts=%s->%s\n' \
    "$CODE_REMOVED" "$B2_ACCEPT_BEFORE" "$B2_ACCEPT_AFTER" | tee -a "$TMP/report.txt"

# The other path is still healthy after the selected address is removed.
wait_http_code http://127.0.0.1:3128 http://10.241.1.2:18080/health 200
log "network checks passed namespaces=$NS_A,$NS_B links=$LINK_A,$LINK_B pid=$PID"
