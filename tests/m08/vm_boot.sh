#!/usr/bin/env bash
# Boot a disposable Ubuntu 24.04 cloud VM twice: install/enable on the first
# boot, then verify autostart and the initial 403 on the second boot.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

require_root
ARCHIVE=${M08_ARCHIVE:-}
SHA=${M08_SHA256:-}
SOURCE_SHA=${M08_SOURCE_SHA:-}
[ -n "$ARCHIVE" ] || fail "M08_ARCHIVE is not set"
[ -f "$ARCHIVE" ] || fail "archive does not exist: $ARCHIVE"
[ -n "$SHA" ] || SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
printf '%s  %s\n' "$SHA" "$ARCHIVE" | sha256sum -c - >/dev/null
[ -n "$SOURCE_SHA" ] || fail "M08_SOURCE_SHA is not set"
for command in qemu-system-x86_64 qemu-img cloud-localds curl; do
    command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

TMP=$(mktemp -d)
HTTP_PID=
cleanup() {
    [ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
BASE="$TMP/noble-base.img"
printf 'vm image: %s\n' "$IMAGE_URL" | tee "$TMP/vm.txt"
curl -fL --retry 3 --retry-delay 5 --connect-timeout 30 --max-time 900 \
    "$IMAGE_URL" -o "$BASE"
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$TMP/disk.qcow2" 8G >/dev/null

SERVE="$TMP/serve"
mkdir -p "$SERVE"
cp "$ARCHIVE" "$SERVE/angara.tar.gz"
python3 -m http.server 18088 --bind 0.0.0.0 --directory "$SERVE" \
    >"$TMP/http.out" 2>"$TMP/http.err" &
HTTP_PID=$!
sleep 1

VM_SCRIPT="$TMP/m08-vm-check.sh"
cat >"$VM_SCRIPT" <<EOF
#!/bin/bash
set -euo pipefail
if ! command -v curl >/dev/null 2>&1; then
    echo M08_VM_RESULT=FAIL_NO_CURL >/dev/console
    poweroff
    exit 1
fi
if [ ! -e /var/lib/m08-vm-installed ]; then
    for _ in \$(seq 1 120); do
        if curl -fsS http://10.0.2.2:18088/angara.tar.gz -o /tmp/angara.tar.gz; then
            break
        fi
        sleep 2
    done
    echo "$SHA  /tmp/angara.tar.gz" | sha256sum -c -
    mkdir -p /tmp/angara
    tar -xzf /tmp/angara.tar.gz -C /tmp/angara
    TOP=\$(find /tmp/angara -mindepth 1 -maxdepth 1 -type d -print -quit)
    "\$TOP/install.sh" --archive /tmp/angara.tar.gz --sha256 "$SHA" \\
        --expected-source-sha "$SOURCE_SHA"
    systemctl enable angara.service
    touch /var/lib/m08-vm-installed
    sync
    echo M08_VM_INSTALLED=1 >/dev/console
    systemctl reboot
    exit 0
fi
for _ in \$(seq 1 60); do
    systemctl is-active --quiet angara.service && break
    sleep 2
done
if ! systemctl is-enabled --quiet angara.service; then
    echo M08_VM_RESULT=FAIL_ENABLED >/dev/console
    poweroff
    exit 1
fi
if ! systemctl is-active --quiet angara.service; then
    echo M08_VM_RESULT=FAIL_ACTIVE >/dev/console
    poweroff
    exit 1
fi
CODE=\$(curl --noproxy '' --proxy http://127.0.0.1:3128 -sS -o /dev/null \\
    -w '%{http_code}' http://127.0.0.1:9/ || true)
if [ "\$CODE" = "403" ]; then
    echo M08_VM_RESULT=PASS >/dev/console
else
    echo "M08_VM_RESULT=FAIL_CODE_\$CODE" >/dev/console
fi
sync
poweroff
EOF
chmod 0755 "$VM_SCRIPT"

cat >"$TMP/user-data" <<EOF
#cloud-config
ssh_pwauth: false
disable_root: false
write_files:
  - path: /usr/local/sbin/m08-vm-check.sh
    permissions: '0755'
    content: |
$(sed 's/^/      /' "$VM_SCRIPT")
  - path: /etc/systemd/system/m08-vm-check.service
    permissions: '0644'
    content: |
      [Unit]
      Description=M08 disposable VM boot check
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/m08-vm-check.sh
      StandardOutput=journal+console
      StandardError=journal+console
      TimeoutStartSec=900
      [Install]
      WantedBy=multi-user.target
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, --now, m08-vm-check.service ]
EOF
cat >"$TMP/meta-data" <<EOF
instance-id: m08-vm-boot
local-hostname: m08-boot
EOF
cloud-localds "$TMP/seed.iso" "$TMP/user-data" "$TMP/meta-data"

run_qemu() {
    local log=$1 timeout_seconds=$2
    set +e
    timeout "$timeout_seconds" qemu-system-x86_64 \
        -machine q35,accel=tcg -cpu max -m 2048 -smp 2 -nographic -no-reboot \
        -drive "file=$TMP/disk.qcow2,format=qcow2,if=virtio" \
        -drive "file=$TMP/seed.iso,format=raw,if=virtio" \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        >"$log" 2>&1
    local status=$?
    set -e
    printf 'qemu %s exit=%s\n' "$log" "$status" | tee -a "$TMP/vm.txt"
}

run_qemu "$TMP/first.log" 900
if ! grep -q 'M08_VM_INSTALLED=1' "$TMP/first.log"; then
    tail -100 "$TMP/first.log" >&2 || true
    fail "first VM boot did not install/enable the archive"
fi
run_qemu "$TMP/second.log" 600
if ! grep -q 'M08_VM_RESULT=PASS' "$TMP/second.log"; then
    tail -100 "$TMP/second.log" >&2 || true
    fail "second VM boot did not confirm autostart and readiness"
fi
printf 'M08 VM boot checks passed (two boots)\n' | tee -a "$TMP/vm.txt"
