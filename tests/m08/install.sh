#!/usr/bin/env bash
# Release archive, manifest, safe extraction and DESTDIR installer checks.
set -euo pipefail
source "$(dirname -- "$0")/common.sh"

ARCHIVE=${M08_ARCHIVE:-}
ARCHIVE_SHA=${M08_SHA256:-}
if [ -z "$ARCHIVE" ]; then
    ARCHIVE=$(find "$REPO_DIR/target/release-artifacts" -maxdepth 1 -name 'angara-*.tar.gz' \
        -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)
fi
[ -n "$ARCHIVE" ] || fail "M08_ARCHIVE is not set and no archive was found"
[ -f "$ARCHIVE" ] || fail "archive does not exist: $ARCHIVE"
if [ -z "$ARCHIVE_SHA" ]; then
    ARCHIVE_SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
fi
SHA_FILE=$(dirname "$ARCHIVE")/SHA256SUMS
[ -f "$SHA_FILE" ] || fail "external SHA256SUMS is missing"
(cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$SHA_FILE")")
assert_eq "$(sha256sum "$ARCHIVE" | awk '{print $1}')" "$ARCHIVE_SHA" "archive SHA"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
umask 077

# Extract once for manifest and content checks.
mkdir -p "$TMP/root"
tar -xzf "$ARCHIVE" -C "$TMP/root" --no-same-owner --no-same-permissions
TOP=$(find "$TMP/root" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$TOP" ] || fail "archive has no top-level directory"
[ "$(find "$TMP/root" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ] || fail "archive has multiple top-level entries"
python3 "$TOP/verify_manifest.py" --root "$TOP"
grep -q '^candidate_id=' <(python3 "$TOP/verify_manifest.py" --root "$TOP")
grep -q '^source_sha=' <(python3 "$TOP/verify_manifest.py" --root "$TOP")
file "$TOP/bin/angara" | grep -q 'ELF 64-bit.*x86-64'
grep -q 'Type=exec' "$TOP/systemd/angara.service"
grep -q '^User=angara$' "$TOP/systemd/angara.service"
grep -q '^Group=angara$' "$TOP/systemd/angara.service"
grep -q '^NoNewPrivileges=true$' "$TOP/systemd/angara.service"
grep -q '^LimitNOFILE=16384$' "$TOP/systemd/angara.service"
grep -q '^TasksMax=512$' "$TOP/systemd/angara.service"
grep -q '^KillMode=control-group$' "$TOP/systemd/angara.service"
grep -q '^TimeoutStopSec=315s$' "$TOP/systemd/angara.service"
grep -q 'ANGARA_PATCH' "$TOP/licenses/THIRD_PARTY_NOTICES.md"

# No operator material or recoverable secrets in the archive.
if tar -tzf "$ARCHIVE" | grep -E '(^|/)(users\.toml|m05-users\.local\.toml|angara\.toml|.*\.pem|.*\.key|.*\.p12|.*\.pfx|proxy\.log|target/)' \
    | grep -vE '/config/angara\.toml\.default$' >/dev/null; then
    fail "archive contains operator material or a secret-looking path"
fi

# Tampered manifest content is rejected.
cp -R "$TOP" "$TMP/tampered"
printf 'x' >>"$TMP/tampered/bin/angara"
if python3 "$TMP/tampered/verify_manifest.py" --root "$TMP/tampered" --quiet 2>/dev/null; then
    fail "tampered binary passed manifest verification"
fi
rm -rf "$TMP/tampered"

# Wrong external hash is rejected before activation.
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    --destdir "$TMP/bad-hash" >/dev/null 2>&1; then
    fail "wrong archive SHA was accepted"
fi
[ ! -e "$TMP/bad-hash" ] || fail "wrong SHA created a staging tree"

# Path traversal and symlink entries are rejected.
python3 - "$TMP/traversal.tar.gz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as archive:
    info = tarfile.TarInfo("angara/../../escape")
    data = b"x"
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
PY
if "$TOP/install.sh" --archive "$TMP/traversal.tar.gz" \
    --sha256 "$(sha256sum "$TMP/traversal.tar.gz" | awk '{print $1}')" \
    --destdir "$TMP/traversal" >/dev/null 2>&1; then
    fail "path traversal archive was accepted"
fi
[ ! -e "$TMP/escape" ] || fail "path traversal escaped the staging root"
python3 - "$TMP/symlink.tar.gz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as archive:
    directory = tarfile.TarInfo("angara")
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    archive.addfile(directory)
    link = tarfile.TarInfo("angara/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    archive.addfile(link)
PY
if "$TOP/install.sh" --archive "$TMP/symlink.tar.gz" \
    --sha256 "$(sha256sum "$TMP/symlink.tar.gz" | awk '{print $1}')" \
    --destdir "$TMP/symlink" >/dev/null 2>&1; then
    fail "symlink archive was accepted"
fi

# Unprivileged DESTDIR install and repeat-install preservation.
DEST="$TMP/stage"
"$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$DEST" | tee "$TMP/install-1.txt"
CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/install-1.txt")
[ -n "$CANDIDATE" ] || fail "installer did not print candidate_id"
[ -f "$DEST/opt/angara/releases/$CANDIDATE/bin/angara" ] || fail "release binary missing"
[ -L "$DEST/opt/angara/current" ] || fail "current symlink missing"
assert_eq "$(readlink "$DEST/opt/angara/current")" \
    "/opt/angara/releases/$CANDIDATE" "current symlink target"
[ -L "$DEST/usr/local/bin/angara" ] || fail "CLI symlink missing"
assert_eq "$(readlink "$DEST/usr/local/bin/angara")" \
    "/opt/angara/current/bin/angara" "CLI symlink target"
[ -f "$DEST/etc/angara/angara.toml" ] || fail "initial config missing"
assert_eq "$(stat -c '%a' "$DEST/etc/angara/angara.toml")" "640" "config mode"
[ -f "$DEST/usr/local/sbin/angaractl" ] || fail "angaractl missing"
[ -f "$DEST/etc/systemd/system/angara.service" ] || fail "unit missing"
printf '\n# local marker\n' >>"$DEST/etc/angara/angara.toml"
"$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$DEST" | tee "$TMP/install-2.txt"
grep -q 'config_preserved=1' "$TMP/install-2.txt"
grep -q '# local marker' "$DEST/etc/angara/angara.toml"

# DESTDIR must not touch host paths.
[ ! -e /etc/angara/angara.toml ] || fail "DESTDIR test unexpectedly touched /etc/angara"
[ ! -e /opt/angara/current ] || fail "DESTDIR test unexpectedly touched /opt/angara"

# Unbindable configuration passes check but fails serve; useful for the
# upgrade failure path and for the "check is not a bind" contract.
python3 "$M08_DIR/make_config.py" --output "$TMP/unbindable.toml" --mode unbindable
"$TOP/bin/angara" check --config "$TMP/unbindable.toml" >/dev/null
set +e
"$TOP/bin/angara" serve --config "$TMP/unbindable.toml" \
    >"$TMP/unbindable.out" 2>"$TMP/unbindable.err"
UNBINDABLE_CODE=$?
set -e
[ "$UNBINDABLE_CODE" -ne 0 ] || fail "serve unexpectedly bound a TEST-NET address"
grep -Eqi 'bind|address|error' "$TMP/unbindable.err"

log "install checks passed candidate=$CANDIDATE"
