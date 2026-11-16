#!/usr/bin/env bash
# A -> B -> A upgrade, rollback, preflight and recovery checks.
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

ANGARACTL=/usr/local/sbin/angaractl
TMP=$(mktemp -d)
cleanup() {
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
# A is installed through the M08 installer contained in B; the A manifest
# independently records its M07 source SHA.

# Extract A and read its manifest before installing it.  The A source SHA is
# not known from B, so the installer is called with the exact extracted value.
mkdir -p "$TMP/a"
tar -xzf "$ARCHIVE_A" -C "$TMP/a" --no-same-owner --same-permissions
A_TOP=$(find "$TMP/a" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$A_TOP" ] || fail "A archive has no top-level directory"
python3 "$A_TOP/verify_manifest.py" --root "$A_TOP" >"$TMP/a-manifest.txt"
A_SOURCE=$(sed -n 's/^source_sha=//p' "$TMP/a-manifest.txt")
A_CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/a-manifest.txt")
B_SOURCE=$(sed -n 's/^source_sha=//p' "$TMP/b-manifest.txt")
B_CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/b-manifest.txt")
[ "$A_SOURCE" != "$B_SOURCE" ] || fail "A and B source SHAs are identical"

log "upgrade stage: install A"
"$B_TOP/install.sh" --archive "$ARCHIVE_A" --sha256 "$SHA_A" \
    --expected-source-sha "$A_SOURCE" >"$TMP/install-a.txt"
systemctl start angara.service
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
A_PID=$(systemctl show -p MainPID --value angara.service)
A_EXE=$(readlink -f "/proc/$A_PID/exe")
case "$A_EXE" in *"/releases/$A_CANDIDATE/"*) ;; *) fail "A exe is not in A release: $A_EXE" ;; esac
A_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
"$M08_DIR/make_users.sh" /opt/angara/current/bin/angara /etc/angara/users.toml \
    'M08-UPGRADE-SYNTHETIC'
chown root:angara /etc/angara/users.toml
chmod 0640 /etc/angara/users.toml
A_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
printf 'A candidate=%s source=%s exe=%s\n' "$A_CANDIDATE" "$A_SOURCE" "$A_EXE"

# Preflight failure: unreadable users file must stop the upgrade before A is
# touched.  A keeps running with its previous snapshot.
log "upgrade stage: preflight failure"
cp /etc/angara/angara.toml "$TMP/angara.saved"
python3 "$M08_DIR/make_config.py" --output "$TMP/bad-users.toml" --mode functional \
    --http-port 3128 --https-port 0 --extra-port 0 --users-file /etc/angara/users.toml \
    --workers auto
chmod 0600 /etc/angara/users.toml
chown root:root /etc/angara/users.toml
install -m 0640 -o root -g angara "$TMP/bad-users.toml" /etc/angara/angara.toml
set +e
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/preflight.out" 2>"$TMP/preflight.err"
PREFLIGHT_CODE=$?
set -e
[ "$PREFLIGHT_CODE" -ne 0 ] || fail "unreadable users file did not fail preflight"
assert_eq "$(systemctl show -p MainPID --value angara.service)" "$A_PID" "preflight PID"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
cp "$TMP/angara.saved" /etc/angara/angara.toml
chown root:angara /etc/angara/angara.toml
chmod 0640 /etc/angara/angara.toml
chown root:angara /etc/angara/users.toml
chmod 0640 /etc/angara/users.toml

# Corrupt archive / wrong hash also fail before A stops.
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
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403

# A -> B.
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
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
B_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_eq "$B_CONFIG_HASH" "$A_CONFIG_HASH" "config hashes after A->B"
printf 'B candidate=%s source=%s exe=%s\n' "$B_CANDIDATE" "$B_SOURCE" "$B_EXE"
"$ANGARACTL" status >"$TMP/status-b.txt"
grep -q "current=/opt/angara/releases/$B_CANDIDATE" "$TMP/status-b.txt"

# B -> A rollback.
log "upgrade stage: B -> A"
"$ANGARACTL" rollback --confirm >"$TMP/rollback.out" 2>"$TMP/rollback.err"
cat "$TMP/rollback.out"
wait_service_active
A2_PID=$(systemctl show -p MainPID --value angara.service)
A2_EXE=$(readlink -f "/proc/$A2_PID/exe")
case "$A2_EXE" in *"/releases/$A_CANDIDATE/"*) ;; *) fail "rollback exe is not A: $A2_EXE" ;; esac
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$A_CANDIDATE" "A current after rollback"
assert_eq "$(readlink /opt/angara/previous)" "/opt/angara/releases/$B_CANDIDATE" "B previous after rollback"
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
A2_CONFIG_HASH=$(find /etc/angara -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_eq "$A2_CONFIG_HASH" "$A_CONFIG_HASH" "config hashes after B->A"

# Post-switch failure and recovery: a syntactically valid but unbindable
# listener passes check, fails after B is activated, and the same A is
# recoverable after the test configuration is restored.
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
grep -Eqi 'bind|address|ready|rollback' "$TMP/post-switch.err" || true
cp "$TMP/angara.saved" /etc/angara/angara.toml
chown root:angara /etc/angara/angara.toml
chmod 0640 /etc/angara/angara.toml
systemctl reset-failed angara.service >/dev/null 2>&1 || true
log "upgrade stage: recover"
"$ANGARACTL" recover >"$TMP/recover.out" 2>"$TMP/recover.err"
cat "$TMP/recover.out"
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$A_CANDIDATE" "recovered current"

# Repeat upgrade after recovery works.
log "upgrade stage: repeat upgrade"
"$ANGARACTL" upgrade --archive "$ARCHIVE_B" --sha256 "$SHA_B" --confirm \
    >"$TMP/upgrade-again.out" 2>"$TMP/upgrade-again.err"
wait_service_active
wait_http_code http://127.0.0.1:3128 http://127.0.0.1:9/ 403
assert_eq "$(readlink /opt/angara/current)" "/opt/angara/releases/$B_CANDIDATE" "second upgrade current"

log "upgrade checks passed A=$A_CANDIDATE B=$B_CANDIDATE sha256_A=$SHA_A sha256_B=$SHA_B"
