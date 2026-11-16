#!/usr/bin/env bash
# Boot a minimal Ubuntu 24.04 systemd container from the installed archive.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
ARCHIVE=${M08_ARCHIVE:-}
SHA=${M08_SHA256:-}
[ -n "$ARCHIVE" ] || fail "M08_ARCHIVE is not set"
[ -f "$ARCHIVE" ] || fail "archive does not exist: $ARCHIVE"
[ -n "$SHA" ] || SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
command -v systemd-nspawn >/dev/null 2>&1 || fail "systemd-nspawn is required (systemd-container)"
command -v debootstrap >/dev/null 2>&1 || fail "debootstrap is required"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"

TMP=$(mktemp -d)
MACHINE="angara-boot-$$"
NSPAWN_PID=
cleanup() {
    if [ -n "$NSPAWN_PID" ] && kill -0 "$NSPAWN_PID" 2>/dev/null; then
        machinectl terminate "$MACHINE" >/dev/null 2>&1 || true
        kill "$NSPAWN_PID" 2>/dev/null || true
        wait "$NSPAWN_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
umask 077

printf '%s  %s\n' "$SHA" "$ARCHIVE" | sha256sum -c - >/dev/null
mkdir -p "$TMP/release"
tar -xzf "$ARCHIVE" -C "$TMP/release" --no-same-owner --same-permissions
TOP=$(find "$TMP/release" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$TOP" ] || fail "archive has no top-level directory"
SOURCE_SHA=$(python3 "$TOP/verify_manifest.py" --root "$TOP" | sed -n 's/^source_sha=//p')
[ -n "$SOURCE_SHA" ] || fail "manifest source SHA is missing"

ROOT="$TMP/rootfs"
log "debootstrap noble rootfs (this takes several minutes)"
debootstrap --variant=minbase \
    --include=systemd,systemd-sysv,dbus,iproute2,procps,curl,ca-certificates,python3-minimal \
    noble "$ROOT" http://archive.ubuntu.com/ubuntu/ \
    >"$TMP/debootstrap.log" 2>&1 \
    || fail "debootstrap failed; see $TMP/debootstrap.log"

install -d -m 0755 "$ROOT/tmp/release"
cp -a "$TOP/." "$ROOT/tmp/release/"
chroot "$ROOT" /tmp/release/install.sh \
    --source-dir /tmp/release \
    --expected-source-sha "$SOURCE_SHA" \
    --no-systemd >"$TMP/install.txt"
cat "$TMP/install.txt"
systemctl --root="$ROOT" enable angara.service >/dev/null
[ -L "$ROOT/etc/systemd/system/multi-user.target.wants/angara.service" ] \
    || fail "angara.service was not enabled in the rootfs"

log "booting $MACHINE"
systemd-nspawn -D "$ROOT" --machine="$MACHINE" --boot --network-veth \
    >"$TMP/nspawn.log" 2>&1 &
NSPAWN_PID=$!

for _ in $(seq 1 180); do
    if systemctl -M "$MACHINE" is-system-running >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$NSPAWN_PID" 2>/dev/null; then
        cat "$TMP/nspawn.log" >&2
        fail "systemd-nspawn exited before boot"
    fi
    sleep 1
done
systemctl -M "$MACHINE" is-system-running >/dev/null 2>&1 \
    || { cat "$TMP/nspawn.log" >&2; fail "container systemd did not become ready"; }

for _ in $(seq 1 120); do
    systemctl -M "$MACHINE" is-active --quiet angara.service && break
    sleep 0.5
done
systemctl -M "$MACHINE" is-active --quiet angara.service \
    || { systemctl -M "$MACHINE" status angara.service --no-pager >&2 || true; fail "angara.service did not autostart"; }
assert_eq "$(systemctl -M "$MACHINE" is-enabled angara.service)" "enabled" "boot enable state"

assert_eq "$(systemd-run --machine="$MACHINE" --quiet --pipe --wait --collect /bin/cat /proc/1/comm)" \
    "systemd" "container PID 1"
PID=$(systemctl -M "$MACHINE" show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "container service has no main PID"
EXE=$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)
printf 'boot service pid=%s exe=%s\n' "$PID" "$EXE"
case "$EXE" in
    *"/releases/"*"/bin/angara") ;;
    *) fail "booted service executable is not a release binary: $EXE" ;;
esac
assert_eq "$(systemd-run --machine="$MACHINE" --quiet --pipe --wait --collect /bin/bash -c \
    'curl --noproxy "" --proxy http://127.0.0.1:3128 -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:9/')" \
    "403" "boot readiness request"

CGROUP=$(systemctl -M "$MACHINE" show -p ControlGroup --value angara.service)
[ -n "$CGROUP" ] || fail "booted service has no cgroup"
systemctl -M "$MACHINE" poweroff >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
    kill -0 "$NSPAWN_PID" 2>/dev/null || break
    sleep 0.5
done
wait "$NSPAWN_PID" 2>/dev/null || true
NSPAWN_PID=
log "boot checks passed machine=$MACHINE cgroup=$CGROUP"
