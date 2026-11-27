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
DESTDIR_INPUT=
ARCHIVE=
ARCHIVE_SHA=
SOURCE_DIR=
EXPECTED_SOURCE_SHA=
EXPECTED_CANDIDATE=
CANDIDATE_ONLY=0
NO_SYSTEMD=0
NO_OWNER=0
CHECK_SERVICE_USER=0
SERVICE=angara.service
CONTROL_SERVICE=angara-control.service
SERVICE_USER=angara
ADMIN_GROUP=angara-admin
WORKDIR=
STAGING_RELEASE=
STAGED_SOURCE=

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

reject_unsafe_components() {
    local value=$1 part
    local IFS=/
    for part in $value; do
        case "$part" in
            '..'|.) die "path contains an unsafe component: $value" ;;
        esac
    done
}

# Validate the DESTDIR input lexically and, for every existing component,
# reject symlinks before mkdir can follow them.  Resolving only after mkdir
# would let a caller redirect writes into a sibling tree.
assert_destdir_input_safe() {
    local value=$1 part prefix
    case "$value" in
        /*) ;;
        *) value="$(pwd -P)/$value" ;;
    esac
    case "$value" in
        ''|/) die "--destdir must not be the filesystem root" ;;
        *\\*|*//*) die "--destdir contains an unsafe separator: $value" ;;
    esac
    reject_unsafe_components "$value"
    local IFS=/
    prefix=
    for part in ${value#/}; do
        [ -n "$part" ] || continue
        prefix="$prefix/$part"
        if [ -L "$prefix" ]; then
            die "--destdir component is a symlink: $prefix"
        fi
        if [ -e "$prefix" ] && [ ! -d "$prefix" ]; then
            die "--destdir component is not a directory: $prefix"
        fi
    done
    printf '%s\n' "$value"
}

# The primary GID is also an access grant: another passwd entry with the same
# primary group would read root:angara 0640 users/TLS files even when the
# group member list is empty.
gid_has_other_users() {
    local gid=$1 name passwd uid ugid rest
    while IFS=: read -r name passwd uid ugid rest; do
        [ "$name" = "$SERVICE_USER" ] && continue
        [ "$ugid" = "$gid" ] && return 0
    done < <(getent passwd 2>/dev/null || true)
    return 1
}

# Read-only validation of an existing service account.  The account must be a
# dedicated, non-interactive system account whose only group is the dedicated
# `angara` group.  A group member, a shared primary GID or an extra
# supplementary group could read root:angara 0640 users/TLS files, so all are
# rejected.
validate_service_user() {
    local user_entry group_entry user_uid user_gid group_gid shell home members groups
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        user_entry=$(getent passwd "$SERVICE_USER")
        user_uid=$(printf '%s\n' "$user_entry" | cut -d: -f3)
        user_gid=$(printf '%s\n' "$user_entry" | cut -d: -f4)
        home=$(printf '%s\n' "$user_entry" | cut -d: -f6)
        shell=$(printf '%s\n' "$user_entry" | cut -d: -f7)
        [ "$user_uid" -ne 0 ] \
            || die "user $SERVICE_USER must not be UID 0"
        case "$shell" in
            */nologin|*/false) ;;
            *) die "user $SERVICE_USER exists with an interactive shell ($shell); refusing to adopt it" ;;
        esac
        case "$home" in
            /nonexistent|/var/lib/angara|/var/lib/angara/*) ;;
            *) die "user $SERVICE_USER exists with unexpected home ($home); refusing to adopt it" ;;
        esac
        getent group "$SERVICE_USER" >/dev/null 2>&1 \
            || die "user $SERVICE_USER has no matching $SERVICE_USER group; refusing to adopt it"
        group_entry=$(getent group "$SERVICE_USER")
        group_gid=$(printf '%s\n' "$group_entry" | cut -d: -f3)
        members=$(printf '%s\n' "$group_entry" | cut -d: -f4)
        [ "$group_gid" -ne 0 ] \
            || die "group $SERVICE_USER must not be GID 0"
        [ "$user_gid" = "$group_gid" ] \
            || die "user $SERVICE_USER primary GID $user_gid does not match group GID $group_gid"
        [ -z "$members" ] \
            || die "group $SERVICE_USER has unexpected members ($members); refusing to adopt it"
        if gid_has_other_users "$group_gid"; then
            die "group $SERVICE_USER GID $group_gid is the primary group of another passwd entry; refusing to adopt it"
        fi
        groups=$(id -nG "$SERVICE_USER" 2>/dev/null || true)
        [ "$groups" = "$SERVICE_USER" ] \
            || die "user $SERVICE_USER has supplementary groups ($groups); refusing to adopt it"
    else
        if getent group "$SERVICE_USER" >/dev/null 2>&1; then
            group_entry=$(getent group "$SERVICE_USER")
            group_gid=$(printf '%s\n' "$group_entry" | cut -d: -f3)
            members=$(printf '%s\n' "$group_entry" | cut -d: -f4)
            [ "$group_gid" -ne 0 ] \
                || die "group $SERVICE_USER must not be GID 0"
            [ -z "$members" ] \
                || die "group $SERVICE_USER exists with members ($members); refusing to adopt it"
            if gid_has_other_users "$group_gid"; then
                die "existing group $SERVICE_USER GID $group_gid is the primary group of a passwd entry; refusing to adopt it"
            fi
        fi
    fi
}

cleanup() {
    if [ -n "$STAGING_RELEASE" ] && [ -d "$STAGING_RELEASE" ]; then
        rm -rf "$STAGING_RELEASE"
    fi
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
  --source-dir <dir>       Internal verified angaractl staging only; requires
                           ANGARA_INTERNAL_STAGED_TREE=1.
  --expected-source-sha <sha>  Refuse a different source commit.
  --expected-candidate <id>    Refuse a different candidate id.
  --candidate-only         Install only the release directory; do not touch
                           the active unit, helper, config or symlinks.
  --no-systemd             Do not call systemctl daemon-reload.
  --check-service-user     Validate an existing angara user/group and exit.
  -h, --help               Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --archive) [ "$#" -ge 2 ] || die "--archive needs a value"; ARCHIVE=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || die "--sha256 needs a value"; ARCHIVE_SHA=$2; shift 2 ;;
        --source-dir) [ "$#" -ge 2 ] || die "--source-dir needs a value"; SOURCE_DIR=$2; shift 2 ;;
        --destdir) [ "$#" -ge 2 ] || die "--destdir needs a value"; DESTDIR_INPUT=$2; shift 2 ;;
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
        --no-owner) NO_OWNER=1; shift ;;
        --check-service-user) CHECK_SERVICE_USER=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if [ "$CHECK_SERVICE_USER" -eq 1 ]; then
    validate_service_user
    printf 'service_user=valid\n'
    exit 0
fi

if [ -n "$DESTDIR_INPUT" ]; then
    case "$DESTDIR_INPUT" in
        /) die "--destdir / is not a staging directory" ;;
    esac
    # Check the caller-supplied path before mkdir can follow a symlink.  The
    # archive hash and manifest are still verified before the directory exists.
    DESTDIR_INPUT=$(assert_destdir_input_safe "$DESTDIR_INPUT")
    NO_OWNER=1
else
    [ "$(id -u)" -eq 0 ] || die "real installation requires root; use --destdir for a staging check"
fi

if [ -n "$SOURCE_DIR" ]; then
    [ "${ANGARA_INTERNAL_STAGED_TREE:-0}" = "1" ] \
        || die "--source-dir is reserved for the verified angaractl staging path; use --archive"
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
    WORKDIR=$(mktemp -d)
    chmod 0700 "$WORKDIR"
    # Read the archive exactly once into a private copy, then verify and use
    # that copy for every subsequent operation.  Reopening the operator-supplied
    # path after the hash check would allow a swap between check and tar.
    ARCHIVE_COPY="$WORKDIR/archive.tar.gz"
    cat -- "$ARCHIVE" >"$ARCHIVE_COPY"
    chmod 0600 "$ARCHIVE_COPY"
    printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE_COPY" | sha256sum -c - >/dev/null \
        || die "archive SHA-256 mismatch"
    # Reject absolute paths, parent traversal, backslashes and links before
    # extracting anything. The release tree only contains regular files and
    # directories.
    tar -tzf "$ARCHIVE_COPY" >"$WORKDIR/list.txt"
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
    tar -tvzf "$ARCHIVE_COPY" >"$WORKDIR/types.txt"
    while IFS= read -r line; do
        mode=${line%% *}
        case "$mode" in
            -*) ;;
            d*) ;;
            *) die "archive contains a link or special file: $line" ;;
        esac
    done <"$WORKDIR/types.txt"
    mkdir -p "$WORKDIR/root"
    tar -xzf "$ARCHIVE_COPY" -C "$WORKDIR/root" \
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

if [ -n "$DESTDIR_INPUT" ]; then
    mkdir -p "$DESTDIR_INPUT"
    DESTDIR=$(CDPATH= cd -- "$DESTDIR_INPUT" && pwd -P)
    case "$DESTDIR" in
        /|'') die "--destdir must not resolve to /" ;;
    esac
    DEST_MODE=$(stat -c '%a' "$DESTDIR")
    DEST_UID=$(stat -c '%u' "$DESTDIR")
    [ "$DEST_UID" = "$(id -u)" ] \
        || die "--destdir is not owned by the invoking user: $DESTDIR"
    if (( (8#$DEST_MODE & 0022) != 0 )); then
        die "--destdir is group/world writable: $DESTDIR ($DEST_MODE)"
    fi
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
    [ "$CANDIDATE_ONLY" -eq 0 ] || return 0
    [ -z "$DESTDIR" ] || return 0
    [ "$NO_OWNER" -eq 0 ] || return 0
    validate_service_user
    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
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

ensure_admin_group() {
    [ "$CANDIDATE_ONLY" -eq 0 ] || return 0
    [ -z "$DESTDIR" ] || return 0
    [ "$NO_OWNER" -eq 0 ] || return 0
    if ! getent group "$ADMIN_GROUP" >/dev/null 2>&1; then
        groupadd --system "$ADMIN_GROUP"
    else
        local gid
        gid=$(getent group "$ADMIN_GROUP" | cut -d: -f3)
        [ "$gid" -ne 0 ] || die "group $ADMIN_GROUP must not be GID 0"
    fi
}

install_managed_unit() {
    local source_name=$1 unit_name=$2 target
    target=$(path "$UNIT_DIR/$unit_name")
    if [ -e "$target" ]; then
        [ -f "$target" ] && [ ! -L "$target" ] \
            || die "existing unit is not a regular managed file: $target"
        grep -q '^# Managed by Angara package' "$target" \
            || die "existing unit is foreign and will not be overwritten: $target"
    fi
    mkdir -p "$(dirname "$target")"
    rm -f "$target.new"
    install -m 0644 "$RELEASE_DIR/systemd/$source_name" "$target.new"
    if [ -e "$target" ] && cmp -s "$target" "$target.new"; then
        rm -f "$target.new"
    else
        if [ -e "$target" ]; then
            install -m 0644 "$target" "$(path "$PREFIX/state/$unit_name.previous")"
        fi
        mv -f "$target.new" "$target"
        UNIT_CHANGED=1
    fi
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown root:root "$target"
    fi
}

validate_managed_template() {
    local value=$1 part
    case "$value" in
        /*) ;;
        *) die "managed path must be absolute: $value" ;;
    esac
    case "$value" in
        *\\*|*//*) die "managed path contains an unsafe separator: $value" ;;
    esac
    value=${value#/}
    value=${value%/}
    [ -n "$value" ] || die "managed path must not be the filesystem root"
    local IFS=/
    for part in $value; do
        case "$part" in
            ''|.|..) die "managed path contains an unsafe component: $value" ;;
        esac
    done
}

assert_safe_managed_path() {
    local target=$1 current
    validate_managed_template "$target"
    current=$target
    while [ "$current" != "/" ]; do
        if [ -L "$current" ]; then
            die "managed path component is a symlink: $current"
        fi
        current=$(dirname -- "$current")
    done
}

check_managed_dir() {
    local target=$1 mode
    if [ -e "$target" ] && [ ! -d "$target" ]; then
        die "managed path is not a directory: $target"
    fi
    if [ -d "$target" ]; then
        mode=$(stat -c '%a' "$target")
        if (( (8#$mode & 0022) != 0 )); then
            die "managed directory is group/world writable: $target ($mode)"
        fi
    fi
}

for managed_root in "$PREFIX" "$SYSCONFDIR" "$UNIT_DIR" "$BINDIR" "$SBINDIR" "$VARLIB"; do
    validate_managed_template "$managed_root"
done

for managed in \
    "$(path "$PREFIX")" \
    "$(path "$PREFIX/releases")" \
    "$(path "$PREFIX/state")" \
    "$(path "$SYSCONFDIR")" \
    "$(path "$SYSCONFDIR/tls")" \
    "$(path "$SYSCONFDIR/angara.toml")" \
    "$(path "$UNIT_DIR")" \
    "$(path "$UNIT_DIR/$SERVICE")" \
    "$(path "$UNIT_DIR/$CONTROL_SERVICE")" \
    "$(path "$BINDIR")" \
    "$(path "$SBINDIR")" \
    "$(path "$SBINDIR/angaractl")" \
    "$(path "$VARLIB")" \
    "$(path "$VARLIB/backups")"
do
    assert_safe_managed_path "$managed"
done

for managed_dir in \
    "$(path "$PREFIX")" \
    "$(path "$PREFIX/releases")" \
    "$(path "$PREFIX/state")" \
    "$(path "$SYSCONFDIR")" \
    "$(path "$SYSCONFDIR/tls")" \
    "$(path "$UNIT_DIR")" \
    "$(path "$BINDIR")" \
    "$(path "$SBINDIR")" \
    "$(path "$VARLIB")" \
    "$(path "$VARLIB/backups")"
do
    check_managed_dir "$managed_dir"
done

preflight_managed_conflicts() {
    [ "$CANDIDATE_ONLY" -eq 0 ] || return 0
    local unit_target helper_target config_target current bin_link previous
    unit_target=$(path "$UNIT_DIR/$SERVICE")
    if [ -e "$unit_target" ]; then
        [ -f "$unit_target" ] && [ ! -L "$unit_target" ] \
            || die "existing unit is not a regular managed file: $unit_target"
        grep -q '^# Managed by Angara package' "$unit_target" \
            || die "existing unit is foreign and will not be overwritten: $unit_target"
    fi
    control_unit_target=$(path "$UNIT_DIR/$CONTROL_SERVICE")
    if [ -e "$control_unit_target" ]; then
        [ -f "$control_unit_target" ] && [ ! -L "$control_unit_target" ] \
            || die "existing control unit is not a regular managed file: $control_unit_target"
        grep -q '^# Managed by Angara package' "$control_unit_target" \
            || die "existing control unit is foreign and will not be overwritten: $control_unit_target"
    fi
    helper_target=$(path "$SBINDIR/angaractl")
    if [ -e "$helper_target" ]; then
        [ -f "$helper_target" ] && [ ! -L "$helper_target" ] \
            || die "existing helper is not a regular managed file: $helper_target"
        grep -q '^# Managed by Angara package' "$helper_target" \
            || die "existing helper is foreign and will not be overwritten: $helper_target"
    fi
    config_target=$(path "$SYSCONFDIR/angara.toml")
    if [ -L "$config_target" ]; then
        die "existing config is a symlink: $config_target"
    fi
    if [ -e "$config_target" ]; then
        [ -f "$config_target" ] || die "existing config is not a regular file: $config_target"
        local config_mode
        config_mode=$(stat -c '%a' "$config_target")
        case "$config_mode" in
            400|440|600|640) ;;
            *) die "existing $config_target has unsafe mode $config_mode" ;;
        esac
    fi
    current=$(path "$PREFIX/current")
    if [ -L "$current" ]; then
        case "$(readlink "$current")" in
            "$PREFIX"/releases/*) ;;
            *) die "current symlink points outside $PREFIX/releases" ;;
        esac
    elif [ -e "$current" ]; then
        die "$current exists and is not a managed symlink"
    fi
    previous=$(path "$PREFIX/previous")
    if [ -L "$previous" ]; then
        case "$(readlink "$previous")" in
            "$PREFIX"/releases/*) ;;
            *) die "previous symlink points outside $PREFIX/releases" ;;
        esac
    elif [ -e "$previous" ]; then
        die "$previous exists and is not a managed symlink"
    fi
    bin_link=$(path "$BINDIR/angara")
    if [ -L "$bin_link" ]; then
        [ "$(readlink "$bin_link")" = "$PREFIX/current/bin/angara" ] \
            || die "$bin_link points to a foreign target"
    elif [ -e "$bin_link" ]; then
        die "$bin_link exists and is not a managed symlink"
    fi
}

preflight_managed_conflicts

ensure_service_user
ensure_admin_group
ensure_dir "$(path "$PREFIX")" 0755 root root
ensure_dir "$(path "$PREFIX/releases")" 0755 root root
if [ "$CANDIDATE_ONLY" -eq 0 ]; then
    ensure_dir "$(path "$PREFIX/state")" 0755 root root
    ensure_dir "$(path "$SYSCONFDIR")" 0750 root "$SERVICE_USER"
    ensure_dir "$(path "$SYSCONFDIR/tls")" 0750 root "$SERVICE_USER"
    ensure_dir "$(path "$VARLIB")" 0700 root root
    ensure_dir "$(path "$VARLIB/backups")" 0700 root root
    if [ -z "$DESTDIR" ] && [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /run/angara
    fi
fi

RELEASE_LINK="$PREFIX/releases/$CANDIDATE"
RELEASE_DIR=$(path "$RELEASE_LINK")
if [ -e "$RELEASE_DIR" ]; then
    [ -d "$RELEASE_DIR" ] && [ ! -L "$RELEASE_DIR" ] \
        || die "release path is not a real directory: $RELEASE_DIR"
    # Verify the existing tree against the trusted manifest of the incoming
    # archive, not against a manifest that may have been left by another
    # version under the same candidate directory name.
    python3 "$STAGED_SOURCE/verify_manifest.py" \
        --root "$RELEASE_DIR" \
        --manifest "$STAGED_SOURCE/manifest.json" --quiet \
        || die "existing release directory does not match the incoming $CANDIDATE manifest"
    cmp -s "$RELEASE_DIR/manifest.json" "$STAGED_SOURCE/manifest.json" \
        || die "existing release manifest differs from the incoming manifest: $RELEASE_DIR"
else
    # A unique, operation-owned directory avoids deleting a pre-existing
    # candidate temp tree or following a foreign symlink.
    STAGING_RELEASE=$(mktemp -d "$(path "$PREFIX/releases/.tmp-$CANDIDATE.XXXXXX")")
    cp -R "$STAGED_SOURCE/." "$STAGING_RELEASE/"
    rm -f "$STAGING_RELEASE/manifest.json"
    cp "$STAGED_SOURCE/manifest.json" "$STAGING_RELEASE/manifest.json"
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown -R root:root "$STAGING_RELEASE"
    fi
    find "$STAGING_RELEASE" -type d -exec chmod 0755 {} +
    find "$STAGING_RELEASE" -type f -exec chmod 0644 {} +
    chmod 0755 "$STAGING_RELEASE/bin/angara" "$STAGING_RELEASE/install.sh" \
        "$STAGING_RELEASE/angaractl" "$STAGING_RELEASE/verify_manifest.py"
    python3 "$STAGING_RELEASE/verify_manifest.py" --root "$STAGING_RELEASE" --quiet \
        || die "staged release failed manifest verification"
    mv -T "$STAGING_RELEASE" "$RELEASE_DIR"
    STAGING_RELEASE=
fi

OLD_CURRENT=
if [ -L "$(path "$PREFIX/current")" ]; then
    OLD_CURRENT=$(readlink -f "$(path "$PREFIX/current")" || true)
fi

UNIT_CHANGED=0
CONFIG_PRESERVED=0
if [ "$CANDIDATE_ONLY" -eq 0 ]; then
    install_managed_unit "$SERVICE" "$SERVICE"
    install_managed_unit "$CONTROL_SERVICE" "$CONTROL_SERVICE"

    CONFIG_TARGET=$(path "$SYSCONFDIR/angara.toml")
    if [ -e "$CONFIG_TARGET" ]; then
        CONFIG_PRESERVED=1
        [ -f "$CONFIG_TARGET" ] && [ ! -L "$CONFIG_TARGET" ] \
            || die "existing config is not a regular file: $CONFIG_TARGET"
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
fi

if [ "$CANDIDATE_ONLY" -eq 0 ]; then
    CURRENT=$(path "$PREFIX/current")
    if [ -L "$CURRENT" ]; then
        CURRENT_TARGET=$(readlink "$CURRENT")
        case "$CURRENT_TARGET" in
            "$PREFIX"/releases/*) ;;
            *) die "current symlink points outside $PREFIX/releases: $CURRENT_TARGET" ;;
        esac
    elif [ -e "$CURRENT" ]; then
        die "$CURRENT exists and is not a managed symlink"
    fi
    ln -sfn "$RELEASE_LINK" "$CURRENT.tmp"
    mv -Tf "$CURRENT.tmp" "$CURRENT"
    if [ -n "$OLD_CURRENT" ] && [ "$OLD_CURRENT" != "$RELEASE_DIR" ] && [ -d "$OLD_CURRENT" ]; then
        OLD_CURRENT_LINK=${OLD_CURRENT#"$DESTDIR"}
        PREVIOUS=$(path "$PREFIX/previous")
        if [ -L "$PREVIOUS" ]; then
            PREVIOUS_TARGET=$(readlink "$PREVIOUS")
            case "$PREVIOUS_TARGET" in
                "$PREFIX"/releases/*) ;;
                *) die "previous symlink points outside $PREFIX/releases: $PREVIOUS_TARGET" ;;
            esac
        elif [ -e "$PREVIOUS" ]; then
            die "$PREVIOUS exists and is not a managed symlink"
        fi
        ln -sfn "$OLD_CURRENT_LINK" "$PREVIOUS.tmp"
        mv -Tf "$PREVIOUS.tmp" "$PREVIOUS"
    fi

    BIN_LINK=$(path "$BINDIR/angara")
    mkdir -p "$(dirname "$BIN_LINK")"
    if [ -L "$BIN_LINK" ]; then
        BIN_TARGET=$(readlink "$BIN_LINK")
        case "$BIN_TARGET" in
            "$PREFIX/current/bin/angara") ;;
            *) die "$BIN_LINK points to a foreign target: $BIN_TARGET" ;;
        esac
    elif [ -e "$BIN_LINK" ]; then
        die "$BIN_LINK already exists and is not a managed symlink"
    fi
    ln -sfn "$PREFIX/current/bin/angara" "$BIN_LINK.tmp"
    mv -Tf "$BIN_LINK.tmp" "$BIN_LINK"

    SBIN_TARGET=$(path "$SBINDIR/angaractl")
    if [ -e "$SBIN_TARGET" ]; then
        [ -f "$SBIN_TARGET" ] && [ ! -L "$SBIN_TARGET" ] \
            || die "existing helper is not a regular managed file: $SBIN_TARGET"
        grep -q '^# Managed by Angara package' "$SBIN_TARGET" \
            || die "existing helper is foreign and will not be overwritten: $SBIN_TARGET"
    fi
    mkdir -p "$(dirname "$SBIN_TARGET")"
    rm -f "$SBIN_TARGET.new"
    install -m 0755 "$RELEASE_DIR/angaractl" "$SBIN_TARGET.new"
    mv -f "$SBIN_TARGET.new" "$SBIN_TARGET"
    if [ "$NO_OWNER" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown root:root "$SBIN_TARGET"
    fi
fi

if [ "$NO_SYSTEMD" -eq 0 ] && [ -z "$DESTDIR" ] && [ "$UNIT_CHANGED" -eq 1 ]; then
    systemctl daemon-reload
fi

printf 'candidate_id=%s\n' "$CANDIDATE"
printf 'release_dir=%s\n' "$RELEASE_DIR"
printf 'config_preserved=%s\n' "$CONFIG_PRESERVED"
printf 'unit_changed=%s\n' "$UNIT_CHANGED"
printf 'candidate_only=%s\n' "$CANDIDATE_ONLY"
if [ -n "$DESTDIR" ]; then
    printf 'staged_under=%s\n' "$DESTDIR"
else
    printf 'next: systemctl enable %s %s\n' "$SERVICE" "$CONTROL_SERVICE"
    printf 'next: systemctl start %s %s\n' "$SERVICE" "$CONTROL_SERVICE"
    printf 'next: add administrators to group %s (read socket group %s)\n' "$ADMIN_GROUP" "$SERVICE_USER"
fi
