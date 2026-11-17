#!/usr/bin/env bash
# A -> B -> A with distinguishable A metadata, real allowed traffic, preflight
# failures, post-switch failure/recovery and foreign-listener readiness.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
ARCHIVE_A=${M08_ARCHIVE_A:-}
SHA_A=${M08_SHA256_A:-}
ARCHIVE_B=${M08_ARCHIVE_B:-}
SHA_B=${M08_SHA256_B:-}
[ -n "$ARCHIVE_A" ] || fail "M08_ARCHIVE_A is not set"
[ -n "$ARCHIVE_B" ] || fail "M08_ARCHIVE_B is not set"
[ -f "$ARCHIVE_A" ] || fail "A archive missing: $ARCHIVE_A"
[ -f "$ARCHIVE_B" ] || fail "B archive missing: $ARCHIVE_B"
[ -n "$SHA_A" ] || SHA_A=$(sha256sum "$ARCHIVE_A" | awk '{print $1}')
[ -n "$SHA_B" ] || SHA_B=$(sha256sum "$ARCHIVE_B" | awk '{print $1}')
printf '%s  %s\n' "$SHA_A" "$ARCHIVE_A" | sha256sum -c - >/dev/null
printf '%s  %s\n' "$SHA_B" "$ARCHIVE_B" | sha256sum -c - >/dev/null

ANGARACTL=/usr/local/sbin/angaractl
TMP=$(mktemp -d)
PIDS=
FOREIGN_PID=
cleanup() {
    [ -z "$FOREIGN_PID" ] || kill "$FOREIGN_PID" 2>/dev/null || true
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    systemctl stop angara.service 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

mkdir -p "$TMP/b"
tar -xzf "$ARCHIVE_B" -C "$TMP/b" --no-same-owner --same-permissions
B_TOP=$(find "$TMP/b" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$B_TOP" ] || fail "B archive has no top-level directory"
python3 "$B_TOP/verify_manifest.py" --root "$B_TOP" >"$TMP/b-manifest.txt"

mkdir -p "$TMP/a"
tar -xzf "$ARCHIVE_A" -C "$TMP/a" --no-same-owner --same-permissions
A_ORIGINAL_TOP=$(find "$TMP/a" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$A_ORIGINAL_TOP" ] || fail "A archive has no top-level directory"
python3 "$A_ORIGINAL_TOP/verify_manifest.py" --root "$A_ORIGINAL_TOP" \
    >"$TMP/a-manifest.txt"
A_SOURCE=$(sed -n 's/^source_sha=//p' "$TMP/a-manifest.txt")
A_CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/a-manifest.txt")
B_SOURCE=$(sed -n 's/^source_sha=//p' "$TMP/b-manifest.txt")
B_CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/b-manifest.txt")
[ "$A_SOURCE" != "$B_SOURCE" ] || fail "A and B source SHAs are identical"

# Build a test A with distinguishable unit/helper metadata; the source and
# binary stay the accepted M07 release.
mkdir -p "$TMP/a-variant"
A_VARIANT_TOP="$TMP/a-variant/$(basename "$A_ORIGINAL_TOP")"
cp -R "$A_ORIGINAL_TOP" "$A_VARIANT_TOP"
printf '\n# A variant marker\n' >>"$A_VARIANT_TOP/systemd/angara.service"
printf '# A variant marker\n' >>"$A_VARIANT_TOP/angaractl"
python3 - "$A_VARIANT_TOP/manifest.json" "$A_VARIANT_TOP" <<'PY'
import hashlib, json, os, stat, sys
manifest_path, root = sys.argv[1], sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
for entry in data["files"]:
    relative = entry["path"]
    if relative not in ("systemd/angara.service", "angaractl"):
        continue
    path = os.path.join(root, relative)
    entry["size"] = os.path.getsize(path)
    entry["mode"] = f"{stat.S_IMODE(os.stat(path).st_mode):04o}"
    entry["sha256"] = hashlib.sha256(open(path, "rb").read()).hexdigest()
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
A_VARIANT="$TMP/angara-a-variant.tar.gz"
tar -czf "$A_VARIANT" -C "$TMP/a-variant" "$(basename "$A_VARIANT_TOP")"
SHA_A=$(sha256sum "$A_VARIANT" | awk '{print $1}')
python3 "$A_VARIANT_TOP/verify_manifest.py" --root "$A_VARIANT_TOP" --quiet

# Origins and a real TLS/Basic/ACL configuration.
python3 "$M08_DIR/pki.py" --dir "$TMP/pki"
"$M08_DIR/make_users.sh" "$B_TOP/bin/angara" "$TMP/users.toml" \
    'M08-UPGRADE-SYNTHETIC'
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18080 \
    --log "$TMP/origin.log" --accept-log "$TMP/accept.log" \
    >"$TMP/http.out" 2>"$TMP/http.err" &
PIDS="$PIDS $!"
python3 "$M08_DIR/origin.py" --host 127.0.0.1 --port 18443 \
    --cert "$TMP/pki/site_chain.pem" --key "$TMP/pki/site_key.pem" \
    --log "$TMP/site.log" >"$TMP/site.out" 2>"$TMP/site.err" &
PIDS="$PIDS $!"
wait_port 127.0.0.1 18080
wait_port 127.0.0.1 18443

python3 "$M08_DIR/make_config.py" --output "$TMP/angara.toml" --mode functional \
    --http-port 3128 --https-port 3129 --https2-port 0 --site-port 18443 \
    --extra-port 0 --users-file /etc/angara/users.toml \
    --tls-cert /etc/angara/tls/proxy-chain.pem \
    --tls-key /etc/angara/tls/proxy-key.pem \
    --workers 2 --https-users alice --shutdown-ms 5000 --reload-ms 5000 \
    --idle-ms 60000 --metrics-interval 1000
cat >"$TMP/https.conf" <<EOF
silent
show-error
noproxy = ""
proxy = "https://127.0.0.1:3129"
proxy-cacert = "$TMP/pki/proxy_ca.pem"
proxy-user = "alice:M08-UPGRADE-SYNTHETIC"
cacert = "$TMP/pki/site_ca.pem"
EOF

log "upgrade stage: install A"
"$B_TOP/install.sh" --archive "$A_VARIANT" --sha256 "$SHA_A" \
    --expected-source-sha "$A_SOURCE" >"$TMP/install-a.txt"
install -d -m 0750 -o root -g angara /etc/angara/tls
install -m 0640 -o root -g angara "$TMP/users.toml" /etc/angara/users.toml
install -m 0640 -o root -g angara "$TMP/pki/proxy_chain.pem" \
    /etc/angara/tls/proxy-chain.pem
install -m 0640 -o root -g angara "$TMP/pki/proxy_key.pem" \
    /etc/angara/tls/proxy-key.pem
install -m 0640 -o root -g angara "$TMP/angara.toml" /etc/angara/angara.toml
runuser -u angara -- /opt/angara/current/bin/angara check \
    --config /etc/angara/angara.toml >/dev/null
systemctl reset-failed angara.service >/dev/null 2>&1 || true
systemctl start angara.service
wait_service_active
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
A_PID=$(systemctl show -p MainPID --value angara.service)
A_EXE=$(readlink -f "/proc/$A_PID/exe")
case "$A_EXE" in *"/releases/$A_CANDIDATE/"*) ;; *) fail "A exe is not in A release: $A_EXE" ;; esac
grep -q 'A variant marker' /etc/systemd/system/angara.service \
    || fail "A unit variant is not active"
grep -q 'A variant marker' /usr/local/sbin/angaractl \
    || fail "A helper variant is not active"
A_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
ACCEPT_BEFORE=$(line_count "$TMP/accept.log")
printf 'A candidate=%s source=%s exe=%s\n' "$A_CANDIDATE" "$A_SOURCE" "$A_EXE"

# Preflight failure must not touch A, its unit/helper or allowed traffic.
log "upgrade stage: preflight failure"
cp /etc/angara/angara.toml "$TMP/angara.saved"
chmod 0600 /etc/angara/users.toml
chown root:root /etc/angara/users.toml
set +e
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/preflight.out" 2>"$TMP/preflight.err"
PREFLIGHT_CODE=$?
set -e
[ "$PREFLIGHT_CODE" -ne 0 ] || fail "unreadable users file did not fail preflight"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$A_PID" "preflight PID"
grep -q 'A variant marker' /etc/systemd/system/angara.service \
    || fail "preflight changed A unit"
grep -q 'A variant marker' /usr/local/sbin/angaractl \
    || fail "preflight changed A helper"
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
chown root:angara /etc/angara/users.toml
chmod 0640 /etc/angara/users.toml

# Corrupt archive / wrong hash fail before A stops.
cp "$ARCHIVE_B" "$TMP/corrupt.tar.gz"
printf 'x' >>"$TMP/corrupt.tar.gz"
set +e
"$ANGARACTL" upgrade --archive "$TMP/corrupt.tar.gz" \
    --sha256 "$(sha256sum "$TMP/corrupt.tar.gz" | awk '{print $1}')" --confirm \
    >"$TMP/corrupt.out" 2>"$TMP/corrupt.err"
CORRUPT_CODE=$?
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" \
    --sha256 "0000000000000000000000000000000000000000000000000000000000000000" --confirm \
    >"$TMP/wrong-sha.out" 2>"$TMP/wrong-sha.err"
WRONG_SHA_CODE=$?
set -e
[ "$CORRUPT_CODE" -ne 0 ] || fail "corrupt archive was accepted"
[ "$WRONG_SHA_CODE" -ne 0 ] || fail "wrong archive SHA was accepted"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$A_PID" "rejected archive PID"
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"

# A -> B: distinguishable metadata, allowed traffic and preserved config.
log "upgrade stage: A -> B"
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/upgrade.out" 2>"$TMP/upgrade.err"
cat "$TMP/upgrade.out"
wait_service_active
B_PID=$(systemctl show -p MainPID --value angara.service)
[ "$B_PID" != "$A_PID" ] || fail "upgrade did not replace the process"
B_EXE=$(readlink -f "/proc/$B_PID/exe")
case "$B_EXE" in *"/releases/$B_CANDIDATE/"*) ;; *) fail "B exe is not in B release: $B_EXE" ;; esac
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$B_CANDIDATE" "B current"
assert_eq "$(readlink /opt/angara/previous)" "/opt/angara/releases/$A_CANDIDATE" "B previous"
if grep -q 'A variant marker' /etc/systemd/system/angara.service; then
    fail "B unit still contains A variant"
fi
if grep -q 'A variant marker' /usr/local/sbin/angaractl; then
    fail "B helper still contains A variant"
fi
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
ACCEPT_AFTER=$(line_count "$TMP/accept.log")
[ "$ACCEPT_AFTER" -gt "$ACCEPT_BEFORE" ] || fail "allowed A->B traffic did not reach origin"
B_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_eq "$B_CONFIG_HASH" "$A_CONFIG_HASH" "config hashes after A->B"
printf 'B candidate=%s source=%s exe=%s\n' "$B_CANDIDATE" "$B_SOURCE" "$B_EXE"

# B -> A rollback restores the distinguishable A metadata.
log "upgrade stage: B -> A"
"$ANGARACTL" rollback --confirm >"$TMP/rollback.out" 2>"$TMP/rollback.err"
cat "$TMP/rollback.out"
wait_service_active
A2_PID=$(systemctl show -p MainPID --value angara.service)
A2_EXE=$(readlink -f "/proc/$A2_PID/exe")
case "$A2_EXE" in *"/releases/$A_CANDIDATE/"*) ;; *) fail "rollback exe is not A: $A2_EXE" ;; esac
grep -q 'A variant marker' /etc/systemd/system/angara.service \
    || fail "rollback did not restore A unit"
grep -q 'A variant marker' /usr/local/sbin/angaractl \
    || fail "rollback did not restore A helper"
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$A_CANDIDATE" "A current after rollback"
assert_eq "$(readlink /opt/angara/previous)" "/opt/angara/releases/$B_CANDIDATE" "B previous after rollback"
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
A2_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_eq "$A2_CONFIG_HASH" "$A_CONFIG_HASH" "config hashes after B->A"

# Post-switch failure: B check passes, start fails, and A is recovered after
# restoring the consistent functional config.
log "upgrade stage: post-switch failure"
python3 "$M08_DIR/make_config.py" --output "$TMP/unbindable.toml" --mode unbindable \
    --http-port 3128 --https-port 0 --extra-port 0 --workers auto
install -m 0640 -o root -g angara "$TMP/unbindable.toml" /etc/angara/angara.toml
set +e
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/post-switch.out" 2>"$TMP/post-switch.err"
POST_SWITCH_CODE=$?
set -e
[ "$POST_SWITCH_CODE" -ne 0 ] || fail "unbindable post-switch start was accepted"
if grep -q 'readiness=ok' "$TMP/post-switch.out"; then
    fail "post-switch failure reported readiness"
fi
if grep -q 'rollback_command=angaractl rollback' "$TMP/post-switch.err"; then
    fail "post-switch failure suggested the wrong rollback direction"
fi
cp "$TMP/angara.saved" /etc/angara/angara.toml
chown root:angara /etc/angara/angara.toml
chmod 0640 /etc/angara/angara.toml
systemctl reset-failed angara.service >/dev/null 2>&1 || true
log "upgrade stage: recover"
"$ANGARACTL" recover >"$TMP/recover.out" 2>"$TMP/recover.err"
cat "$TMP/recover.out"
wait_service_active
grep -q 'A variant marker' /etc/systemd/system/angara.service \
    || fail "recover did not restore A unit"
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$A_CANDIDATE" "recovered current"

# Foreign listener returning an accepted readiness code must not make B ready.
log "upgrade stage: foreign readiness"
systemctl stop angara.service
wait_service_inactive 20
cat >"$TMP/foreign.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(407)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
HTTPServer(("127.0.0.1", 3128), Handler).serve_forever()
PY
python3 "$TMP/foreign.py" >"$TMP/foreign.out" 2>"$TMP/foreign.err" &
FOREIGN_PID=$!
wait_port 127.0.0.1 3128
set +e
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/foreign-upgrade.out" 2>"$TMP/foreign-upgrade.err"
FOREIGN_CODE=$?
set -e
[ "$FOREIGN_CODE" -ne 0 ] || fail "upgrade accepted a foreign readiness server"
if grep -q 'readiness=ok' "$TMP/foreign-upgrade.out"; then
    fail "foreign server confirmed readiness"
fi
kill "$FOREIGN_PID" 2>/dev/null || true
wait "$FOREIGN_PID" 2>/dev/null || true
FOREIGN_PID=
systemctl reset-failed angara.service >/dev/null 2>&1 || true
"$ANGARACTL" recover >"$TMP/foreign-recover.out" 2>"$TMP/foreign-recover.err"
wait_service_active
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$A_CANDIDATE" "foreign-recovered current"

# Repeat upgrade after recovery works.
log "upgrade stage: repeat upgrade"
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/upgrade-again.out" 2>"$TMP/upgrade-again.err"
wait_service_active
wait_http_code https://127.0.0.1:3129 http://127.0.0.1:18080/ 200 \
    --config "$TMP/https.conf"
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$B_CANDIDATE" "second upgrade current"

log "upgrade checks passed A=$A_CANDIDATE B=$B_CANDIDATE sha256_A=$SHA_A sha256_B=$SHA_B"
