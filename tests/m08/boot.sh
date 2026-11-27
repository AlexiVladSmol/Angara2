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
command -v timeout >/dev/null 2>&1 || fail "timeout is required"

resolve_mirror_uri() {
    local uri=$1 target
    case "$uri" in
        http://*|https://*)
            printf '%s\n' "$uri"
            ;;
        mirror+file:*)
            target=${uri#mirror+file:}
            if [ -f "$target" ]; then
                awk '!/^[[:space:]]*#/ && NF { print $1; exit }' "$target"
            fi
            ;;
    esac
}

detect_ubuntu_mirror() {
    local mirror= candidate=
    if [ -n "${M08_UBUNTU_MIRROR:-}" ]; then
        printf '%s\n' "$M08_UBUNTU_MIRROR"
        return 0
    fi
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
        while IFS= read -r candidate; do
            mirror=$(resolve_mirror_uri "$candidate")
            [ -n "$mirror" ] && break
        done < <(awk '$1 == "URIs:" {
            for (i = 2; i <= NF; i++) print $i
        }' /etc/apt/sources.list.d/ubuntu.sources)
    fi
    if [ -z "$mirror" ] && [ -f /etc/apt/sources.list ]; then
        mirror=$(awk '$1 == "deb" {
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^https?:\/\//) {
                    print $i
                    exit
                }
            }
        }' /etc/apt/sources.list)
    fi
    if [ -z "$mirror" ]; then
        mirror=http://archive.ubuntu.com/ubuntu/
    fi
    printf '%s\n' "$mirror"
}

UBUNTU_MIRROR=$(detect_ubuntu_mirror)
DEBOOTSTRAP_TIMEOUT=${M08_DEBOOTSTRAP_TIMEOUT:-900}
WGET_READ_TIMEOUT=${M08_WGET_READ_TIMEOUT:-60}
BOOT_TIMEOUT=${M08_BOOT_TIMEOUT:-180}
SERVICE_TIMEOUT=${M08_SERVICE_TIMEOUT:-60}
case "$DEBOOTSTRAP_TIMEOUT" in
    ''|*[!0-9]*) fail "M08_DEBOOTSTRAP_TIMEOUT must be a positive integer" ;;
esac
[ "$DEBOOTSTRAP_TIMEOUT" -gt 0 ] \
    || fail "M08_DEBOOTSTRAP_TIMEOUT must be a positive integer"
case "$WGET_READ_TIMEOUT" in
    ''|*[!0-9]*) fail "M08_WGET_READ_TIMEOUT must be a positive integer" ;;
esac
[ "$WGET_READ_TIMEOUT" -gt 0 ] \
    || fail "M08_WGET_READ_TIMEOUT must be a positive integer"
case "$BOOT_TIMEOUT" in
    ''|*[!0-9]*) fail "M08_BOOT_TIMEOUT must be a positive integer" ;;
esac
[ "$BOOT_TIMEOUT" -gt 0 ] \
    || fail "M08_BOOT_TIMEOUT must be a positive integer"
[ "$BOOT_TIMEOUT" -le 180 ] \
    || fail "M08_BOOT_TIMEOUT must not exceed 180 seconds"
case "$SERVICE_TIMEOUT" in
    ''|*[!0-9]*) fail "M08_SERVICE_TIMEOUT must be a positive integer" ;;
esac
[ "$SERVICE_TIMEOUT" -gt 0 ] \
    || fail "M08_SERVICE_TIMEOUT must be a positive integer"

TMP=$(mktemp -d)
ROOT="$TMP/rootfs"
cat >"$TMP/wgetrc" <<EOF
read_timeout = ${WGET_READ_TIMEOUT}
connect_timeout = 20
dns_timeout = 20
tries = 3
waitretry = 2
EOF
MACHINE="angara-boot-$$"
NSPAWN_PID=
DEBOOTSTRAP_PID=
CLEANED=0
cleanup() {
    trap '' HUP INT TERM
    [ "$CLEANED" -eq 0 ] || return 0
    CLEANED=1
    if [ -n "$NSPAWN_PID" ] && kill -0 "$NSPAWN_PID" 2>/dev/null; then
        machinectl terminate "$MACHINE" >/dev/null 2>&1 || true
        kill "$NSPAWN_PID" 2>/dev/null || true
        wait "$NSPAWN_PID" 2>/dev/null || true
    fi
    if [ -n "$DEBOOTSTRAP_PID" ] \
        && kill -0 "$DEBOOTSTRAP_PID" 2>/dev/null; then
        kill -TERM "$DEBOOTSTRAP_PID" 2>/dev/null || true
        wait "$DEBOOTSTRAP_PID" 2>/dev/null || true
    fi
    DEBOOTSTRAP_PID=
    if [ -d "$ROOT" ] && command -v findmnt >/dev/null 2>&1; then
        while IFS= read -r target; do
            [ -n "$target" ] || continue
            umount "$target" 2>/dev/null \
                || umount -l "$target" 2>/dev/null \
                || true
        done < <(findmnt -rn -o TARGET | awk -v root="$ROOT/" \
            'index($0, root) == 1 { print length($0), $0 }' \
            | sort -rn | cut -d' ' -f2-)
    fi
    rm -rf --one-file-system "$TMP" 2>/dev/null || true
    if [ -e "$TMP" ]; then
        printf 'warning: cleanup left temporary path: %s\n' "$TMP" >&2
    fi
    return 0
}
on_signal() {
    local code=$1
    trap - EXIT
    trap '' HUP INT TERM
    cleanup
    exit "$code"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
umask 077

printf '%s  %s\n' "$SHA" "$ARCHIVE" | sha256sum -c - >/dev/null
mkdir -p "$TMP/release"
tar -xzf "$ARCHIVE" -C "$TMP/release" --no-same-owner --same-permissions
TOP=$(find "$TMP/release" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$TOP" ] || fail "archive has no top-level directory"
SOURCE_SHA=$(python3 "$TOP/verify_manifest.py" --root "$TOP" | sed -n 's/^source_sha=//p')
[ -n "$SOURCE_SHA" ] || fail "manifest source SHA is missing"

log "ubuntu mirror: $UBUNTU_MIRROR"
log "wget read timeout: ${WGET_READ_TIMEOUT}s"
DEBOOTSTRAP_ATTEMPTS=${M08_DEBOOTSTRAP_ATTEMPTS:-3}
DEBOOTSTRAP_RETRY_DELAY=${M08_DEBOOTSTRAP_RETRY_DELAY:-3}
# CI seam: stop after a successful debootstrap to exercise retry paths
# without installing and booting the rootfs.
DEBOOTSTRAP_ONLY=${M08_DEBOOTSTRAP_ONLY:-0}
case "$DEBOOTSTRAP_ATTEMPTS" in
    ''|*[!0-9]*) fail "M08_DEBOOTSTRAP_ATTEMPTS must be an integer from 1 to 5" ;;
esac
[ "$DEBOOTSTRAP_ATTEMPTS" -ge 1 ] && [ "$DEBOOTSTRAP_ATTEMPTS" -le 5 ] \
    || fail "M08_DEBOOTSTRAP_ATTEMPTS must be an integer from 1 to 5"
case "$DEBOOTSTRAP_RETRY_DELAY" in
    ''|*[!0-9]*) fail "M08_DEBOOTSTRAP_RETRY_DELAY must be a non-negative integer" ;;
esac
case "$DEBOOTSTRAP_ONLY" in
    0|1) ;;
    *) fail "M08_DEBOOTSTRAP_ONLY must be 0 or 1" ;;
esac

unmount_root_paths() {
    [ -d "$ROOT" ] && command -v findmnt >/dev/null 2>&1 || return 0
    while IFS= read -r target; do
        [ -n "$target" ] || continue
        umount "$target" 2>/dev/null \
            || umount -l "$target" 2>/dev/null \
            || true
    done < <(findmnt -rn -o TARGET | awk -v root="$ROOT/" \
        'index($0, root) == 1 { print length($0), $0 }' \
        | sort -rn | cut -d' ' -f2-)
}

root_mode() {
    stat -c '%a' "$ROOT" 2>/dev/null || printf 'missing\n'
}

assert_root_mode() {
    local mode
    mode=$(root_mode)
    log "rootfs directory mode: $mode"
    [ "$mode" = "755" ] \
        || fail "rootfs directory mode is $mode, expected 755"
}

print_boot_diagnostics() {
    local state=$1
    printf 'boot diagnostics: system state=%s\n' "${state:-unknown}" >&2
    printf 'rootfs directory mode: %s\n' "$(root_mode)" >&2
    if command -v journalctl >/dev/null 2>&1; then
        printf '%s\n' '--- angara/dbus journal from rootfs ---' >&2
        journalctl --root="$ROOT" --no-pager -n 200 \
            -u angara.service -u dbus.service >&2 || true
    fi
    printf '%s\n' '--- failed units ---' >&2
    timeout 5 systemctl -M "$MACHINE" --failed --no-pager >&2 || true
    if [ -f "$TMP/nspawn.log" ]; then
        printf '%s\n' '--- nspawn.log ---' >&2
        cat "$TMP/nspawn.log" >&2
    fi
}

DEBOOTSTRAP_CACHE_DIR="$TMP/debootstrap-cache"
install -d -m 0755 "$DEBOOTSTRAP_CACHE_DIR"
DEBOOTSTRAP_START=$(date +%s)
DEBOOTSTRAP_CODE=1
DEBOOTSTRAP_ATTEMPT=0
DEBOOTSTRAP_LAST_LOG="$TMP/debootstrap.log"
for attempt in $(seq 1 "$DEBOOTSTRAP_ATTEMPTS"); do
    DEBOOTSTRAP_ATTEMPT=$attempt
    unmount_root_paths
    rm -rf --one-file-system "$ROOT" 2>/dev/null || true
    # A previous version created $ROOT with mkdir -p under umask 077, which
    # left it at 0700 and system services could not start.  debootstrap itself
    # creates the target with 0755; create it explicitly to keep the mode
    # deterministic and keep the package cache outside the rootfs.
    install -d -m 0755 "$ROOT"
    DEBOOTSTRAP_LAST_LOG="$TMP/debootstrap-${attempt}.log"
    set +e
    WGETRC="$TMP/wgetrc" timeout --kill-after=30 "$DEBOOTSTRAP_TIMEOUT" debootstrap \
        --variant=minbase \
        --cache-dir="$DEBOOTSTRAP_CACHE_DIR" \
        --include=systemd,systemd-sysv,dbus,iproute2,procps,curl,ca-certificates,python3 \
        noble "$ROOT" "$UBUNTU_MIRROR" \
        >"$DEBOOTSTRAP_LAST_LOG" 2>&1 &
    DEBOOTSTRAP_PID=$!
    log "debootstrap noble rootfs attempt ${attempt}/${DEBOOTSTRAP_ATTEMPTS} (timeout ${DEBOOTSTRAP_TIMEOUT}s)"
    wait "$DEBOOTSTRAP_PID"
    DEBOOTSTRAP_CODE=$?
    DEBOOTSTRAP_PID=
    set -e
    if [ "$DEBOOTSTRAP_CODE" -eq 0 ]; then
        break
    fi
    if [ "$DEBOOTSTRAP_CODE" -eq 124 ] || [ "$DEBOOTSTRAP_CODE" -eq 137 ]; then
        break
    fi
    if [ "$attempt" -lt "$DEBOOTSTRAP_ATTEMPTS" ]; then
        log "debootstrap attempt ${attempt}/${DEBOOTSTRAP_ATTEMPTS} failed with exit code ${DEBOOTSTRAP_CODE}; retrying in ${DEBOOTSTRAP_RETRY_DELAY}s"
        sleep "$DEBOOTSTRAP_RETRY_DELAY"
    fi
done
DEBOOTSTRAP_ELAPSED=$(($(date +%s) - DEBOOTSTRAP_START))
if [ "$DEBOOTSTRAP_CODE" -ne 0 ]; then
    tail -n 100 "$DEBOOTSTRAP_LAST_LOG" >&2 || true
    if [ "$DEBOOTSTRAP_CODE" -eq 124 ]; then
        fail "debootstrap timed out after ${DEBOOTSTRAP_TIMEOUT}s (SIGTERM)"
    fi
    if [ "$DEBOOTSTRAP_CODE" -eq 137 ]; then
        fail "debootstrap timed out after ${DEBOOTSTRAP_TIMEOUT}s (SIGKILL)"
    fi
    fail "debootstrap failed with exit code ${DEBOOTSTRAP_CODE} after ${DEBOOTSTRAP_ATTEMPT} attempt(s)"
fi
log "debootstrap completed in ${DEBOOTSTRAP_ELAPSED}s on attempt ${DEBOOTSTRAP_ATTEMPT}"
assert_root_mode
if [ "$DEBOOTSTRAP_ONLY" -eq 1 ]; then
    log "debootstrap-only mode; skipping archive install and boot"
    exit 0
fi

install -d -m 0755 "$ROOT/tmp/release"
cp -a "$TOP/." "$ROOT/tmp/release/"
chroot "$ROOT" env ANGARA_INTERNAL_STAGED_TREE=1 /tmp/release/install.sh \
    --source-dir /tmp/release \
    --expected-source-sha "$SOURCE_SHA" \
    --no-systemd >"$TMP/install.txt"
cat "$TMP/install.txt"
systemctl --root="$ROOT" enable angara.service >/dev/null
[ -L "$ROOT/etc/systemd/system/multi-user.target.wants/angara.service" ] \
    || fail "angara.service was not enabled in the rootfs"

assert_root_mode

log "booting $MACHINE"
systemd-nspawn -D "$ROOT" --machine="$MACHINE" --boot --network-veth \
    >"$TMP/nspawn.log" 2>&1 &
NSPAWN_PID=$!

BOOT_DEADLINE=$(($(date +%s) + BOOT_TIMEOUT))
SYSTEM_STATE=
while [ "$(date +%s)" -lt "$BOOT_DEADLINE" ]; do
    SYSTEM_STATE=$(timeout 5 systemctl -M "$MACHINE" is-system-running 2>/dev/null || true)
    if [ "$SYSTEM_STATE" = "running" ]; then
        break
    fi
    if ! kill -0 "$NSPAWN_PID" 2>/dev/null; then
        print_boot_diagnostics "$SYSTEM_STATE"
        fail "systemd-nspawn exited before boot"
    fi
    sleep 1
done
if [ "$SYSTEM_STATE" != "running" ]; then
    print_boot_diagnostics "$SYSTEM_STATE"
    fail "container systemd did not become ready (state=${SYSTEM_STATE:-unknown}) within ${BOOT_TIMEOUT}s"
fi

SERVICE_DEADLINE=$(($(date +%s) + SERVICE_TIMEOUT))
while [ "$(date +%s)" -lt "$SERVICE_DEADLINE" ]; do
    if systemctl -M "$MACHINE" is-active --quiet angara.service; then
        break
    fi
    sleep 0.5
done
if ! systemctl -M "$MACHINE" is-active --quiet angara.service; then
    print_boot_diagnostics "$SYSTEM_STATE"
    systemctl -M "$MACHINE" status angara.service --no-pager >&2 || true
    fail "angara.service did not autostart within ${SERVICE_TIMEOUT}s"
fi
assert_eq "$(systemctl -M "$MACHINE" is-enabled angara.service)" "enabled" "boot enable state"

assert_eq "$(systemd-run --machine="$MACHINE" --quiet --pipe --wait --collect /bin/cat /proc/1/comm)" \
    "systemd" "container PID 1"
PID=$(systemctl -M "$MACHINE" show -p MainPID --value angara.service)
[ "$PID" != "0" ] || fail "container service has no main PID"
EXE=$(systemd-run --machine="$MACHINE" --quiet --pipe --wait --collect \
    /bin/bash -c "readlink -f /proc/$PID/exe")
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
