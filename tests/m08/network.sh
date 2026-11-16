#!/usr/bin/env bash
# Two veth/network-namespace paths with observable source addresses.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
BIN=${M08_BIN:-/usr/local/bin/angara}
[ -x "$BIN" ] || fail "installed binary is missing: $BIN"
command -v ip >/dev/null 2>&1 || fail "iproute2 is required"

TMP=$(mktemp -d)
PROXY_PID=
ORIGIN_A_PID=
ORIGIN_B_PID=
ORIGIN_B2_PID=
NS_A="anga-a-$$"
NS_B="anga-b-$$"
LINK_A="anga0$$"
LINK_B="anga1$$"
cleanup() {
    for pid in "$PROXY_PID" "$ORIGIN_A_PID" "$ORIGIN_B_PID" "$ORIGIN_B2_PID"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip link del "$LINK_A" 2>/dev/null || true
    ip link del "$LINK_B" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$LINK_A" type veth peer name "${LINK_A}p"
ip link add "$LINK_B" type veth peer name "${LINK_B}p"
ip link set "${LINK_A}p" netns "$NS_A"
ip link set "${LINK_B}p" netns "$NS_B"
ip addr add 10.241.1.1/24 dev "$LINK_A"
ip addr add 10.241.2.1/24 dev "$LINK_B"
ip link set "$LINK_A" up
ip link set "$LINK_B" up
ip netns exec "$NS_A" ip addr add 10.241.1.2/24 dev "${LINK_A}p"
ip netns exec "$NS_A" ip link set "${LINK_A}p" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip addr add 10.241.2.2/24 dev "${LINK_B}p"
ip netns exec "$NS_B" ip link set "${LINK_B}p" up
ip netns exec "$NS_B" ip link set lo up

ip netns exec "$NS_A" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18080 \
    --log "$TMP/origin-a.log" >"$TMP/origin-a.out" 2>"$TMP/origin-a.err" &
ORIGIN_A_PID=$!
ip netns exec "$NS_B" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18080 \
    --log "$TMP/origin-b.log" >"$TMP/origin-b.out" 2>"$TMP/origin-b.err" &
ORIGIN_B_PID=$!
ip netns exec "$NS_B" python3 "$M08_DIR/origin.py" --host 0.0.0.0 --port 18081 \
    --log "$TMP/origin-b2.log" >"$TMP/origin-b2.out" 2>"$TMP/origin-b2.err" &
ORIGIN_B2_PID=$!
wait_port 10.241.1.2 18080
wait_port 10.241.2.2 18080
wait_port 10.241.2.2 18081

python3 "$M08_DIR/make_config.py" --output "$TMP/network.toml" --mode network \
    --http-bind 127.0.0.1 --http-port 3128 \
    --http2-bind 127.0.0.2 --http2-port 3128 \
    --site-port 18080 --allow-ports 18080 --extra-port 0 \
    --egress-a 10.241.1.1 --egress-b 10.241.2.1 \
    --ip-networks 127.0.0.0/8,10.241.0.0/16 \
    --workers 2
"$BIN" check --config "$TMP/network.toml" >/dev/null
"$BIN" serve --config "$TMP/network.toml" 2>"$TMP/proxy.err" &
PROXY_PID=$!
wait_port 127.0.0.1 3128
wait_port 127.0.0.2 3128

TX_A_BEFORE=$(cat "/sys/class/net/$LINK_A/statistics/tx_bytes")
TX_B_BEFORE=$(cat "/sys/class/net/$LINK_B/statistics/tx_bytes")
CODE_A=$(http_code http://127.0.0.1:3128 http://10.241.1.2:18080/health)
CODE_B=$(http_code http://127.0.0.2:3128 http://10.241.2.2:18080/health)
assert_eq "$CODE_A" "200" "listener A path"
assert_eq "$CODE_B" "200" "listener B path"
grep -q '^10.241.1.1' "$TMP/origin-a.log" || fail "origin A did not see egress A source"
grep -q '^10.241.2.1' "$TMP/origin-b.log" || fail "origin B did not see egress B source"
TX_A_AFTER=$(cat "/sys/class/net/$LINK_A/statistics/tx_bytes")
TX_B_AFTER=$(cat "/sys/class/net/$LINK_B/statistics/tx_bytes")
[ "$TX_A_AFTER" -gt "$TX_A_BEFORE" ] || fail "interface A counter did not increase"
[ "$TX_B_AFTER" -gt "$TX_B_BEFORE" ] || fail "interface B counter did not increase"
printf 'M08 NET sources: A=%s B=%s txA=%s->%s txB=%s->%s\n' \
    "$(head -n1 "$TMP/origin-a.log" | cut -f1)" \
    "$(head -n1 "$TMP/origin-b.log" | cut -f1)" \
    "$TX_A_BEFORE" "$TX_A_AFTER" "$TX_B_BEFORE" "$TX_B_AFTER"

# Remove the selected egress address and force a new connection.  The request
# must fail explicitly and must not fall back through the other interface.
ip addr del 10.241.2.1/24 dev "$LINK_B"
B2_BEFORE=$(wc -l <"$TMP/origin-b2.log" 2>/dev/null || echo 0)
CODE_REMOVED=$(http_code http://127.0.0.2:3128 http://10.241.2.2:18081/health)
case "$CODE_REMOVED" in
    502|503|504) ;;
    *) fail "removed egress address returned unexpected HTTP $CODE_REMOVED" ;;
esac
sleep 0.3
B2_AFTER=$(wc -l <"$TMP/origin-b2.log" 2>/dev/null || echo 0)
assert_eq "$B2_AFTER" "$B2_BEFORE" "removed-egress origin connections"
TX_A_REMOVED=$(cat "/sys/class/net/$LINK_A/statistics/tx_bytes")
assert_eq "$TX_A_REMOVED" "$TX_A_AFTER" "removed-egress fallback traffic on A"
printf 'M08 NET removed egress: code=%s origin_b_accepts=%s->%s\n' \
    "$CODE_REMOVED" "$B2_BEFORE" "$B2_AFTER"

# The other path is still healthy after the selected address is removed.
wait_http_code http://127.0.0.1:3128 http://10.241.1.2:18080/health 200

log "network checks passed namespaces=$NS_A,$NS_B links=$LINK_A,$LINK_B"
