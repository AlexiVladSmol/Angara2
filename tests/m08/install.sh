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
tar -xzf "$ARCHIVE" -C "$TMP/root" \
    --no-same-owner --same-permissions --delay-directory-restore
TOP=$(find "$TMP/root" -mindepth 1 -maxdepth 1 -type d -printf '%p\n')
[ -n "$TOP" ] || fail "archive has no top-level directory"
[ "$(find "$TMP/root" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ] || fail "archive has multiple top-level entries"
python3 "$TOP/verify_manifest.py" --root "$TOP"
grep -q '^candidate_id=' <(python3 "$TOP/verify_manifest.py" --root "$TOP")
grep -q '^source_sha=' <(python3 "$TOP/verify_manifest.py" --root "$TOP")
file "$TOP/bin/angara" | grep -q 'ELF 64-bit.*x86-64'
grep -q '^# Managed by Angara package' "$TOP/systemd/angara.service"
grep -q '^# Managed by Angara package' "$TOP/angaractl"
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
CANDIDATE=$(sed -n 's/^candidate_id=//p' "$TMP/install-1.txt" | tail -n1)
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

# Existing release/reuse must match the incoming manifest identity and content.
R1_DEST="$TMP/r1-stage"
"$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$R1_DEST" >/dev/null
R1_CANDIDATE=$CANDIDATE
R1_MANIFEST="$R1_DEST/opt/angara/releases/$R1_CANDIDATE/manifest.json"
cp "$R1_MANIFEST" "$TMP/r1-manifest.saved"
python3 - "$R1_MANIFEST" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
data["source_sha"] = "1" * 40
data["candidate_id"] = "0.1.0-111111111111"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$R1_DEST" >/dev/null 2>&1; then
    fail "existing release with a different manifest was reused"
fi
cp "$TMP/r1-manifest.saved" "$R1_MANIFEST"

# R2: a symlink in a parent component must not redirect writes outside DESTDIR.
mkdir -p "$TMP/escape-target" "$TMP/escape-stage"
ln -s "$TMP/escape-target" "$TMP/escape-stage/opt"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$TMP/escape-stage" >/dev/null 2>&1; then
    fail "parent symlink escaped DESTDIR"
fi
[ -z "$(find "$TMP/escape-target" -mindepth 1 -print -quit)" ] \
    || fail "parent symlink wrote outside DESTDIR"

# R2: a symlink in the DESTDIR path itself must be rejected before mkdir.
mkdir -p "$TMP/symlink-parent-target"
ln -s "$TMP/symlink-parent-target" "$TMP/symlink-parent"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$TMP/symlink-parent/new" >/dev/null 2>&1; then
    fail "DESTDIR path through a symlink was accepted"
fi
[ ! -e "$TMP/symlink-parent-target/new" ] \
    || fail "DESTDIR path through a symlink escaped the requested tree"

# R2: a pre-existing candidate temp directory is foreign data, not scratch.
SENTINEL_STAGE="$TMP/sentinel-stage"
mkdir -p "$SENTINEL_STAGE/opt/angara/releases/.tmp-$CANDIDATE"
printf 'sentinel\n' >"$SENTINEL_STAGE/opt/angara/releases/.tmp-$CANDIDATE/sentinel"
"$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$SENTINEL_STAGE" >/dev/null
assert_eq "$(cat "$SENTINEL_STAGE/opt/angara/releases/.tmp-$CANDIDATE/sentinel")" \
    "sentinel" "pre-existing candidate temp data preserved"
[ -d "$SENTINEL_STAGE/opt/angara/releases/$CANDIDATE" ] \
    || fail "sentinel install did not create the release directory"

# R2: a foreign unit must not be overwritten.
FOREIGN="$TMP/foreign-stage"
mkdir -p "$FOREIGN/etc/systemd/system"
printf 'foreign unit\n' >"$FOREIGN/etc/systemd/system/angara.service"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$FOREIGN" >/dev/null 2>&1; then
    fail "foreign unit was accepted"
fi
assert_eq "$(cat "$FOREIGN/etc/systemd/system/angara.service")" "foreign unit" \
    "foreign unit content preserved"

FOREIGN_HELPER="$TMP/foreign-helper-stage"
mkdir -p "$FOREIGN_HELPER/usr/local/sbin"
printf 'foreign helper\n' >"$FOREIGN_HELPER/usr/local/sbin/angaractl"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$FOREIGN_HELPER" >/dev/null 2>&1; then
    fail "foreign helper was accepted"
fi
assert_eq "$(cat "$FOREIGN_HELPER/usr/local/sbin/angaractl")" "foreign helper" \
    "foreign helper content preserved"

FOREIGN_CURRENT="$TMP/foreign-current-stage"
mkdir -p "$FOREIGN_CURRENT/opt/angara"
printf 'foreign current\n' >"$FOREIGN_CURRENT/opt/angara/current"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$FOREIGN_CURRENT" >/dev/null 2>&1; then
    fail "foreign current path was accepted"
fi
assert_eq "$(cat "$FOREIGN_CURRENT/opt/angara/current")" "foreign current" \
    "foreign current preserved"

FOREIGN_BIN="$TMP/foreign-bin-stage"
mkdir -p "$FOREIGN_BIN/usr/local/bin"
printf 'foreign bin\n' >"$FOREIGN_BIN/usr/local/bin/angara"
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$FOREIGN_BIN" >/dev/null 2>&1; then
    fail "foreign CLI path was accepted"
fi
assert_eq "$(cat "$FOREIGN_BIN/usr/local/bin/angara")" "foreign bin" \
    "foreign CLI preserved"

# R4: --candidate-only must not write active metadata or symlinks.
CANDIDATE_STAGE="$TMP/candidate-stage"
"$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$CANDIDATE_STAGE" --candidate-only >/dev/null
[ -d "$CANDIDATE_STAGE/opt/angara/releases/$CANDIDATE" ] \
    || fail "candidate-only did not install the release directory"
for absent in \
    "$CANDIDATE_STAGE/opt/angara/current" \
    "$CANDIDATE_STAGE/etc/angara/angara.toml" \
    "$CANDIDATE_STAGE/etc/systemd/system/angara.service" \
    "$CANDIDATE_STAGE/usr/local/bin/angara" \
    "$CANDIDATE_STAGE/usr/local/sbin/angaractl"
do
    [ ! -e "$absent" ] || fail "candidate-only wrote active metadata: $absent"
done

# R2: configured paths with .. are rejected before writes.
if "$TOP/install.sh" --archive "$ARCHIVE" --sha256 "$ARCHIVE_SHA" \
    --destdir "$TMP/dotdot-stage" --prefix "/opt/../evil" >/dev/null 2>&1; then
    fail "path containing .. was accepted"
fi

# R3: service-account validation with fake NSS records.
FAKE="$TMP/fakebin"
mkdir -p "$FAKE"
cat >"$FAKE/getent" <<'EOF'
#!/bin/sh
case "$1 $2" in
  "passwd angara")
    [ "${FAKE_MODE:-}" = "absent" ] && exit 1
    [ "${FAKE_MODE:-}" = "group_shared" ] && exit 1
    case "${FAKE_MODE:-}" in
      uid0) printf 'angara:x:0:999::/nonexistent:/usr/sbin/nologin\n' ;;
      *) printf 'angara:x:999:999::/nonexistent:/usr/sbin/nologin\n' ;;
    esac
    ;;
  "passwd ")
    case "${FAKE_MODE:-}" in
      shared_gid)
        printf 'angara:x:999:999::/nonexistent:/usr/sbin/nologin\n'
        printf 'outsider:x:1001:999::/nonexistent:/usr/sbin/nologin\n'
        ;;
      group_shared)
        printf 'outsider:x:1001:999::/nonexistent:/usr/sbin/nologin\n'
        ;;
      *)
        printf 'angara:x:999:999::/nonexistent:/usr/sbin/nologin\n'
        ;;
    esac
    ;;
  "group angara")
    [ "${FAKE_MODE:-}" = "absent" ] && exit 1
    case "${FAKE_MODE:-}" in
      member) printf 'angara:x:999:unrelated\n' ;;
      gid0) printf 'angara:x:0:\n' ;;
      *) printf 'angara:x:999:\n' ;;
    esac
    ;;
  *) exit 1 ;;
esac
EOF
cat >"$FAKE/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-nG" ]; then
  case "${FAKE_MODE:-}" in
    supplementary) printf 'angara sudo\n' ;;
    *) printf 'angara\n' ;;
  esac
  exit 0
fi
exit 1
EOF
chmod 0755 "$FAKE/getent" "$FAKE/id"
if PATH="$FAKE:$PATH" FAKE_MODE=member "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "group with a foreign member was accepted"
fi
if PATH="$FAKE:$PATH" FAKE_MODE=supplementary "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "supplementary service-user group was accepted"
fi
if PATH="$FAKE:$PATH" FAKE_MODE=uid0 "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "service user with UID 0 was accepted"
fi
if PATH="$FAKE:$PATH" FAKE_MODE=gid0 "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "service group with GID 0 was accepted"
fi
if PATH="$FAKE:$PATH" FAKE_MODE=shared_gid "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "service group shared as another user's primary GID was accepted"
fi
if PATH="$FAKE:$PATH" FAKE_MODE=group_shared "$TOP/install.sh" \
    --check-service-user >/dev/null 2>&1; then
    fail "existing group shared as another user's primary GID was accepted"
fi
PATH="$FAKE:$PATH" FAKE_MODE=valid "$TOP/install.sh" --check-service-user \
    | grep -q 'service_user=valid'

# R1: replace the source archive after its hash check.  The installer must
# still use the verified private copy, not the swapped path.
cp -R "$TOP" "$TMP/replacement"
mv "$TMP/replacement" "$TMP/angara-0.1.0-linux-x86_64-111111111111"
python3 - "$TMP/angara-0.1.0-linux-x86_64-111111111111/manifest.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
data["source_sha"] = "1" * 40
data["candidate_id"] = "0.1.0-111111111111"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
tar -czf "$TMP/replacement.tar.gz" -C "$TMP" \
    angara-0.1.0-linux-x86_64-111111111111
cp "$ARCHIVE" "$TMP/race.tar.gz"
RACE_SHA=$(sha256sum "$TMP/race.tar.gz" | awk '{print $1}')
REAL_TAR=$(command -v tar)
TAR_FAKE="$TMP/faketar"
mkdir -p "$TAR_FAKE"
cat >"$TAR_FAKE/tar" <<EOF
#!/bin/sh
if [ ! -e "$TMP/race-swapped" ]; then
  cp "$TMP/replacement.tar.gz" "$TMP/race.tar.gz"
  touch "$TMP/race-swapped"
fi
exec "$REAL_TAR" "\$@"
EOF
chmod 0755 "$TAR_FAKE/tar"
PATH="$TAR_FAKE:$PATH" "$TOP/install.sh" --archive "$TMP/race.tar.gz" \
    --sha256 "$RACE_SHA" --destdir "$TMP/race-stage" >/dev/null
assert_eq "$(readlink "$TMP/race-stage/opt/angara/current")" \
    "/opt/angara/releases/$CANDIDATE" "race archive used the verified private copy"

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
