#!/usr/bin/env bash
# Install a verified Angara release archive.
#
# The archive is verified with an external SHA-256 before any file is used.
# All writes in --destdir mode stay below the staging directory and no
# useradd/systemctl calls are made.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=/opt/angara
SYSCONFDIR=/etc/angara
UNIT_DIR=/etc/systemd/system
BINDIR=/usr/local/bin
SBINDIR=/usr/local/sbin
VARLIB=/var/lib/angara
DESTDIR=
ARCHIVE=
ARCHIVE_SHA=
SOURCE_DIR=
EXPECTED_SOURCE_SHA=
EXPECTED_CANDIDATE=
CANDIDATE_ONLY=0
NO_SYSTEMD=0
FORCE=0
NO_OWNER=0
SERVICE=angara.service
SERVICE_USER=angara
WORKDIR=
STAGED_SOURCE=

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
Usage: install.sh --archive <archive.tar.gz> --sha256 <sha256> [options]

Options:
  --destdir <dir>          Stage the whole tree below dir; no host changes.
  --prefix <dir>           Release root (default: /opt/angara).
  --sysconfdir <dir>       Configuration root (default: /etc/angara).
  --unit-dir <dir>         systemd unit directory (default: /etc/systemd/system).
  --bindir <dir>           CLI symlink directory (default: /usr/local/bin).
  --sbindir <dir>          Maintenance command directory (default: /usr/local/sbin).
  --varlib <dir>           Private state/backup root (default: /var/lib/angara).
  --source-dir <dir>       Use an already extracted tree (no archive hash check).
  --expected-source-sha <sha>  Refuse a different source commit.
  --expected-candidate <id>    Refuse a different candidate id.
  --candidate-only         Install the release but do not activate it.
  --no-systemd             Do not call systemctl daemon-reload.
  --force                  Allow a managed path/symlink replacement.
  -h, --help               Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --archive) [ "$#" -ge 2 ] || die "--archive needs a value"; ARCHIVE=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || die "--sha256 needs a value"; ARCHIVE_SHA=$2; shift 2 ;;
        --source-dir) [ "$#" -ge 2 ] || die "--source-dir needs a value"; SOURCE_DIR=$2; shift 2 ;;
        --destdir) [ "$#" -ge 2 ] || die "--destdir needs a value"; DESTDIR=$2; shift 2 ;;
        --prefix) [ "$#" -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
        --sysconfdir) [ "$#" -ge 2 ] || die "--sysconfdir needs a value"; SYSCONFDIR=$2; shift 2 ;;
        --unit-dir) [ "$#" -ge 2 ] || die "--unit-dir needs a value"; UNIT_DIR=$2; shift 2 ;;
        --bindir) [ "$#" -ge 2 ] || die "--bindir needs a value"; BINDIR=$2; shift 2 ;;
        --sbindir) [ "$#" -ge 2 ] || die "--sbindir needs a value"; SBINDIR=$2; shift 2 ;;
        --varlib) [ "$#" -ge 2 ] || die "--varlib needs a value"; VARLIB=$2; shift 2 ;;
        --expected-source-sha) [ "$#" -ge 2 ] || die "--expected-source-sha needs a value"; EXPECTED_SOURCE_SHA=$2; shift 2 ;;
        --expected-candidate) [ "$#" -ge 2 ] || die "--expected-candidate needs a value"; EXPECTED_CANDIDATE=$2; shift 2 ;;
        --candidate-only) CANDIDATE_ONLY=1; shift ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        --force) FORCE=1; shift ;;
        --no-owner) NO_OWNER=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if [ -n "$DESTDIR" ]; then
    case "$DESTDIR" in
        /) die "--destdir / is not a staging directory" ;;
    esac
    mkdir -p "$DESTDIR"
    DESTDIR=$(CDPATH= cd -- "$DESTDIR" && pwd)
    case "$DESTDIR" in
        /|'') die "--destdir must not resolve to /" ;;
    esac
    # A staging tree is deliberately owner-neutral: it may be built by an
    # unprivileged packager and inspected before a root install.
    NO_OWNER=1
else
    [ "$(id -u)" -eq 0 ] || die "real installation requires root; use --destdir for a staging check"
fi

if [ -n "$SOURCE_DIR" ]; then
    [ -z "$ARCHIVE" ] || die "choose either --archive or --source-dir"
    STAGED_SOURCE=$(CDPATH= cd -- "$SOURCE_DIR" && pwd)
    [ -f "$STAGED_SOURCE/manifest.json" ] || die "source tree has no manifest.json"
    printf 'warning: using an already extracted tree without rechecking an archive SHA-256\n' >&2
else
    [ -n "$ARCHIVE" ] || die "--archive or --source-dir is required"
    [ -n "$ARCHIVE_SHA" ] || die "--sha256 is required with --archive"
    [ -f "$ARCHIVE" ] || die "archive does not exist: $ARCHIVE"
    case "$ARCHIVE_SHA" in
        *[!0-9a-f]*|'') die "SHA-256 must be 64 lowercase hex characters" ;;
    esac
    [ "${#ARCHIVE_SHA}" -eq 64 ] || die "SHA-256 must be 64 characters"
    printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE" | sha256sum -c - >/dev/null \
        || die "archive SHA-256 mismatch"
    WORKDIR=$(mktemp -d)
    chmod 0700 "$WORKDIR"
    # Reject absolute paths, parent traversal, backslashes and links before
    # extracting anything. The release tree only contains regular files and
    # directories.
    tar -tzf "$ARCHIVE" >"$WORKDIR/list.txt"
    while IFS= read -r entry; do
        case "$entry" in
            ''|/*|*\\*|..|../*|*/..|*/../*|*//*)
                die "unsafe archive path: $entry"
                ;;
        esac
        case "/$entry/" in
            */../*) die "unsafe archive path: $entry" ;;
        esac
    done <"$WORKDIR/list.txt"
    tar -tvzf "$ARCHIVE" >"$WORKDIR/types.txt"
    while IFS= read -r line; do
        mode=${line%% *}
        case "$mode" in
            -*) ;;
            d*) ;;
            *) die "archive contains a link or special file: $line" ;;
        esac
    done <"$WORKDIR/types.txt"
    mkdir -p "$WORKDIR/root"
    tar -xzf "$ARCHIVE" -C "$WORKDIR/root" \
        --no-same-owner --same-permissions --delay-directory-restore
    mapfile -t top < <(find "$WORKDIR/root" -mindepth 1 -maxdepth 1 -printf '%f\n')
    [ "${#top[@]}" -eq 1 ] || die "archive must contain exactly one top-level directory"
    STAGED_SOURCE="$WORKDIR/root/${top[0]}"
    [ -d "$STAGED_SOURCE" ] || die "archive top-level entry is not a directory"
fi

[ -f "$STAGED_SOURCE/verify_manifest.py" ] || die "release is missing verify_manifest.py"
command -v python3 >/dev/null 2>&1 || die "python3 is required to verify the release manifest"
VERIFY_OUTPUT=$(python3 "$STAGED_SOURCE/verify_manifest.py" --root "$STAGED_SOURCE")
printf '%s\n' "$VERIFY_OUTPUT"
CANDIDATE=$(printf '%s\n' "$VERIFY_OUTPUT" | sed -n 's/^candidate_id=//p')
SOURCE_SHA=$(printf '%s\n' "$VERIFY_OUTPUT" | sed -n 's/^source_sha=//p')
[ -n "$CANDIDATE" ] || die "manifest did not provide a candidate id"
[ -n "$SOURCE_SHA" ] || die "manifest did not provide a source SHA"
if [ -n "$EXPECTED_SOURCE_SHA" ] && [ "$SOURCE_SHA" != "$EXPECTED_SOURCE_SHA" ]; then
    die "source SHA mismatch: expected $EXPECTED_SOURCE_SHA, got $SOURCE_SHA"
fi
if [ -n "$EXPECTED_CANDIDATE" ] && [ "$CANDIDATE" != "$EXPECTED_CANDIDATE" ]; then
    die "candidate mismatch: expected $EXPECTED_CANDIDATE, got $CANDIDATE"
fi

path() {
    if [ -n "$DESTDIR" ]; then
        printf '%s%s' "$DESTDIR" "$1"
    else
        printf '%s' "$1"
    fi
}

ensure_dir() {
    local target=$1 mode=$2 owner=$3 group=$4
    install -d -m "$mode" "$target"
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown "$owner:$group" "$target"
    fi
}

ensure_service_user() {
    [ -z "$DESTDIR" ] || return 0
    [ "$NO_OWNER" -eq 0 ] || return 0
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        local shell home
        shell=$(getent passwd "$SERVICE_USER" | cut -d: -f7)
        home=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
        case "$shell" in
            */nologin|*/false) ;;
            *) die "user $SERVICE_USER already exists with an interactive shell ($shell); refusing to adopt it" ;;
        esac
        case "$home" in
            /nonexistent|/var/lib/angara|/var/lib/angara/*) ;;
            *) die "user $SERVICE_USER already exists with unexpected home ($home); refusing to adopt it" ;;
        esac
        getent group "$SERVICE_USER" >/dev/null 2>&1 \
            || die "user $SERVICE_USER has no matching group; refusing to adopt it"
    else
        if getent group "$SERVICE_USER" >/dev/null 2>&1; then
            useradd --system --gid "$SERVICE_USER" --home-dir /nonexistent \
                --shell /usr/sbin/nologin --no-create-home --comment "Angara proxy" \
                "$SERVICE_USER"
        else
            useradd --system --user-group --home-dir /nonexistent \
                --shell /usr/sbin/nologin --no-create-home --comment "Angara proxy" \
                "$SERVICE_USER"
        fi
    fi
}

check_managed_path() {
    local target=$1
    if [ -L "$target" ]; then
        die "managed path is a symlink: $target"
    fi
    if [ -e "$target" ] && [ ! -d "$target" ]; then
        die "managed path is not a directory: $target"
    fi
}

for managed in "$(path "$PREFIX")" "$(path "$SYSCONFDIR")" "$(path "$UNIT_DIR")" "$(path "$VARLIB"/backups)"; do
    check_managed_path "$managed"
done

ensure_service_user
ensure_dir "$(path "$PREFIX")" 0755 root root
ensure_dir "$(path "$PREFIX/releases")" 0755 root root
ensure_dir "$(path "$PREFIX/state")" 0755 root root
ensure_dir "$(path "$SYSCONFDIR")" 0750 root "$SERVICE_USER"
ensure_dir "$(path "$SYSCONFDIR/tls")" 0750 root "$SERVICE_USER"
ensure_dir "$(path "$VARLIB")" 0700 root root
ensure_dir "$(path "$VARLIB/backups")" 0700 root root

RELEASE_LINK="$PREFIX/releases/$CANDIDATE"
RELEASE_DIR=$(path "$RELEASE_LINK")
if [ -e "$RELEASE_DIR" ]; then
    [ -d "$RELEASE_DIR" ] || die "release path is not a directory: $RELEASE_DIR"
    python3 "$STAGED_SOURCE/verify_manifest.py" --root "$RELEASE_DIR" --quiet \
        || die "existing release directory is not a valid $CANDIDATE tree"
else
    TMP_RELEASE=$(path "$PREFIX/releases/.tmp-$CANDIDATE")
    rm -rf "$TMP_RELEASE"
    mkdir -p "$TMP_RELEASE"
    cp -R "$STAGED_SOURCE/." "$TMP_RELEASE/"
    rm -f "$TMP_RELEASE/manifest.json"
    cp "$STAGED_SOURCE/manifest.json" "$TMP_RELEASE/manifest.json"
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown -R root:root "$TMP_RELEASE"
    fi
    find "$TMP_RELEASE" -type d -exec chmod 0755 {} +
    find "$TMP_RELEASE" -type f -exec chmod 0644 {} +
    chmod 0755 "$TMP_RELEASE/bin/angara" "$TMP_RELEASE/install.sh" \
        "$TMP_RELEASE/angaractl" "$TMP_RELEASE/verify_manifest.py"
    python3 "$TMP_RELEASE/verify_manifest.py" --root "$TMP_RELEASE" --quiet \
        || die "staged release failed manifest verification"
    mv "$TMP_RELEASE" "$RELEASE_DIR"
fi

OLD_CURRENT=
if [ -L "$(path "$PREFIX/current")" ]; then
    OLD_CURRENT=$(readlink -f "$(path "$PREFIX/current")" || true)
fi

UNIT_TARGET=$(path "$UNIT_DIR/$SERVICE")
mkdir -p "$(dirname "$UNIT_TARGET")"
install -m 0644 "$RELEASE_DIR/systemd/angara.service" "$UNIT_TARGET.new"
UNIT_CHANGED=0
if [ -e "$UNIT_TARGET" ] && cmp -s "$UNIT_TARGET" "$UNIT_TARGET.new"; then
    rm -f "$UNIT_TARGET.new"
else
    if [ -e "$UNIT_TARGET" ]; then
        install -m 0644 "$UNIT_TARGET" "$(path "$PREFIX/state/angara.service.previous")"
    fi
    mv -f "$UNIT_TARGET.new" "$UNIT_TARGET"
    UNIT_CHANGED=1
fi
if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
    chown root:root "$UNIT_TARGET"
fi

CONFIG_TARGET=$(path "$SYSCONFDIR/angara.toml")
CONFIG_PRESERVED=0
if [ -e "$CONFIG_TARGET" ]; then
    CONFIG_PRESERVED=1
    MODE=$(stat -c '%a' "$CONFIG_TARGET")
    case "$MODE" in
        400|440|600|640) ;;
        *) die "existing $CONFIG_TARGET has unsafe mode $MODE (expected 0400, 0440, 0600 or 0640)" ;;
    esac
    "$RELEASE_DIR/bin/angara" check --config "$CONFIG_TARGET" >/dev/null \
        || die "existing $CONFIG_TARGET does not validate; it was not overwritten"
    if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ]; then
        runuser -u "$SERVICE_USER" -- test -r "$CONFIG_TARGET" \
            || die "the service user cannot read $CONFIG_TARGET"
    fi
else
    install -m 0640 "$RELEASE_DIR/config/angara.toml.default" "$CONFIG_TARGET"
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown root:"$SERVICE_USER" "$CONFIG_TARGET"
    fi
fi

if [ "$CANDIDATE_ONLY" -eq 0 ]; then
    CURRENT=$(path "$PREFIX/current")
    ln -sfn "$RELEASE_LINK" "$CURRENT.tmp"
    mv -Tf "$CURRENT.tmp" "$CURRENT"
    if [ -n "$OLD_CURRENT" ] && [ "$OLD_CURRENT" != "$RELEASE_DIR" ] && [ -d "$OLD_CURRENT" ]; then
        OLD_CURRENT_LINK=${OLD_CURRENT#"$DESTDIR"}
        ln -sfn "$OLD_CURRENT_LINK" "$(path "$PREFIX/previous").tmp"
        mv -Tf "$(path "$PREFIX/previous").tmp" "$(path "$PREFIX/previous")"
    fi

    BIN_LINK=$(path "$BINDIR/angara")
    mkdir -p "$(dirname "$BIN_LINK")"
    if [ -e "$BIN_LINK" ] && [ ! -L "$BIN_LINK" ]; then
        [ "$FORCE" -eq 1 ] || die "$BIN_LINK already exists and is not a managed symlink"
    fi
    ln -sfn "$PREFIX/current/bin/angara" "$BIN_LINK.tmp"
    mv -Tf "$BIN_LINK.tmp" "$BIN_LINK"
fi

SBIN_TARGET=$(path "$SBINDIR/angaractl")
mkdir -p "$(dirname "$SBIN_TARGET")"
install -m 0755 "$RELEASE_DIR/angaractl" "$SBIN_TARGET"
if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
    chown root:root "$SBIN_TARGET"
fi

if [ "$NO_SYSTEMD" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$UNIT_CHANGED" -eq 1 ]; then
    systemctl daemon-reload
fi

printf 'candidate_id=%s\n' "$CANDIDATE"
printf 'release_dir=%s\n' "$RELEASE_DIR"
printf 'config_preserved=%s\n' "$CONFIG_PRESERVED"
printf 'unit_changed=%s\n' "$UNIT_CHANGED"
if [ -n "$DESTDIR" ]; then
    printf 'staged_under=%s\n' "$DESTDIR"
else
    printf 'next: systemctl enable %s\n' "$SERVICE"
    printf 'next: systemctl start %s\n' "$SERVICE"
fi
