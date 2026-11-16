#!/usr/bin/env bash
# Build a deterministic Angara release archive for Ubuntu 24.04 x86_64.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE_DIR=$REPO_DIR
OUTPUT_DIR=$REPO_DIR/target/release-artifacts
TARGET=x86_64-unknown-linux-gnu
PROFILE=release
SOURCE_SHA=
PACKAGER_SHA=
NO_BUILD=0
BINARY=
VERSION=

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: packaging/build-release.sh [options]

Options:
  --source-dir <dir>      Source tree to build (default: repository root)
  --source-sha <sha>      Full source commit SHA (default: source tree HEAD)
  --packager-sha <sha>    Full M08 packager SHA (default: packager HEAD)
  --output-dir <dir>      Artifact directory (default: target/release-artifacts)
  --target <triple>       Rust target (default: x86_64-unknown-linux-gnu)
  --profile <name>        Cargo profile (default: release)
  --binary <path>         Use an already built binary and skip cargo build
  --no-build              Alias for an already built binary path
  --version <version>     Override Cargo package version
  -h, --help              Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir)
            [ "$#" -ge 2 ] || die "--source-dir needs a value"
            SOURCE_DIR=$2
            shift 2
            ;;
        --source-sha)
            [ "$#" -ge 2 ] || die "--source-sha needs a value"
            SOURCE_SHA=$2
            shift 2
            ;;
        --packager-sha)
            [ "$#" -ge 2 ] || die "--packager-sha needs a value"
            PACKAGER_SHA=$2
            shift 2
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || die "--output-dir needs a value"
            OUTPUT_DIR=$2
            shift 2
            ;;
        --target)
            [ "$#" -ge 2 ] || die "--target needs a value"
            TARGET=$2
            shift 2
            ;;
        --profile)
            [ "$#" -ge 2 ] || die "--profile needs a value"
            PROFILE=$2
            shift 2
            ;;
        --binary)
            [ "$#" -ge 2 ] || die "--binary needs a value"
            BINARY=$2
            NO_BUILD=1
            shift 2
            ;;
        --no-build)
            NO_BUILD=1
            shift
            ;;
        --version)
            [ "$#" -ge 2 ] || die "--version needs a value"
            VERSION=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

SOURCE_DIR=$(CDPATH= cd -- "$SOURCE_DIR" && pwd)
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" 2>/dev/null || { mkdir -p "$OUTPUT_DIR"; CDPATH= cd -- "$OUTPUT_DIR" && pwd; })
[ -f "$SOURCE_DIR/Cargo.toml" ] || die "source tree has no Cargo.toml: $SOURCE_DIR"
[ -f "$SOURCE_DIR/Cargo.lock" ] || die "source tree has no Cargo.lock: $SOURCE_DIR"

if [ -z "$SOURCE_SHA" ]; then
    SOURCE_SHA=$(git -C "$SOURCE_DIR" rev-parse HEAD)
fi
if [ -z "$PACKAGER_SHA" ]; then
    PACKAGER_SHA=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || git -C "$SOURCE_DIR" rev-parse HEAD)
fi
case "$SOURCE_SHA" in
    *[!0-9a-f]*|'') die "source SHA must be 40 lowercase hex characters" ;;
esac
[ "${#SOURCE_SHA}" -eq 40 ] || die "source SHA must be 40 characters"
[ "${#PACKAGER_SHA}" -eq 40 ] || die "packager SHA must be 40 characters"
if [ -z "$VERSION" ]; then
    VERSION=$(python3 - "$SOURCE_DIR/Cargo.toml" <<'PY'
import sys
import tomllib
with open(sys.argv[1], "rb") as handle:
    data = tomllib.load(handle)
print(data["package"]["version"])
PY
)
fi
CANDIDATE_ID="${VERSION}-${SOURCE_SHA:0:12}"
DIST="$OUTPUT_DIR/angara-${VERSION}-linux-x86_64-${SOURCE_SHA:0:12}"
ARCHIVE="$OUTPUT_DIR/angara-${VERSION}-linux-x86_64-${SOURCE_SHA:0:12}.tar.gz"
SUMS="$OUTPUT_DIR/SHA256SUMS"

if [ "$NO_BUILD" -eq 0 ]; then
    printf 'building %s %s\n' "$SOURCE_DIR" "$TARGET"
    (cd "$SOURCE_DIR" && cargo build --locked --profile "$PROFILE" --target "$TARGET")
    if [ "$PROFILE" = "release" ]; then
        BINARY="$SOURCE_DIR/target/$TARGET/release/angara"
    else
        BINARY="$SOURCE_DIR/target/$TARGET/$PROFILE/angara"
    fi
fi
[ -n "$BINARY" ] || die "no binary path selected"
[ -f "$BINARY" ] || die "binary does not exist: $BINARY"
[ ! -L "$BINARY" ] || die "binary must be a regular file, not a symlink"

ELF_DESCRIPTION=$(file -b "$BINARY")
case "$ELF_DESCRIPTION" in
    *"ELF 64-bit"*"x86-64"*) ;;
    *) die "binary is not x86_64 ELF: $ELF_DESCRIPTION" ;;
esac
RUSTC_VERSION=$(cd "$SOURCE_DIR" && rustc --version)
CARGO_VERSION=$(cd "$SOURCE_DIR" && cargo --version)
CARGO_LOCK_SHA=$(sha256sum "$SOURCE_DIR/Cargo.lock" | awk '{print $1}')
HYPER_PATCH="$SOURCE_DIR/vendor/hyper-1.12.0/ANGARA_PATCH.md"
[ -f "$HYPER_PATCH" ] || die "missing hyper patch description: $HYPER_PATCH"
HYPER_PATCH_SHA=$(sha256sum "$HYPER_PATCH" | awk '{print $1}')

SOURCE_DATE_EPOCH=$(git -C "$SOURCE_DIR" show -s --format=%ct "$SOURCE_SHA" 2>/dev/null || true)
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*) SOURCE_DATE_EPOCH=$(date -u +%s) ;;
esac

rm -rf "$DIST"
mkdir -p "$DIST"/{bin,systemd,config,docs,examples,licenses,provenance}
install -m 0755 "$BINARY" "$DIST/bin/angara"
install -m 0644 "$SCRIPT_DIR/angara.service" "$DIST/systemd/angara.service"
install -m 0755 "$SCRIPT_DIR/install.sh" "$DIST/install.sh"
install -m 0755 "$SCRIPT_DIR/angaractl" "$DIST/angaractl"
install -m 0755 "$SCRIPT_DIR/verify_manifest.py" "$DIST/verify_manifest.py"
install -m 0644 "$SCRIPT_DIR/angara.toml.default" "$DIST/config/angara.toml.default"
install -m 0644 "$REPO_DIR/docs/ADMIN_GUIDE.md" "$DIST/docs/ADMIN_GUIDE.md"
install -m 0644 "$REPO_DIR/docs/RELEASE.md" "$DIST/docs/RELEASE.md"
install -m 0644 "$REPO_DIR/RELEASE_CHECKLIST.md" "$DIST/RELEASE_CHECKLIST.md"
install -m 0644 "$REPO_DIR/README.md" "$DIST/README.md"
install -m 0644 "$SOURCE_DIR/Cargo.lock" "$DIST/provenance/Cargo.lock"
install -m 0644 "$HYPER_PATCH" "$DIST/provenance/ANGARA_PATCH.md"

for example in \
    minimal.toml \
    multi-listener.toml \
    m02-policy.toml \
    m02-egress-local.toml \
    m03-http-local.toml \
    m04-connect-local.toml
do
    install -m 0644 "$REPO_DIR/examples/$example" "$DIST/examples/$example"
done

python3 "$SCRIPT_DIR/generate-notices.py" \
    --manifest-path "$SOURCE_DIR/Cargo.toml" \
    --target "$TARGET" \
    --output-dir "$DIST/licenses" \
    --notices "$DIST/licenses/THIRD_PARTY_NOTICES.md" \
    --hyper-patch "$HYPER_PATCH"

LDD_OUTPUT=$(ldd "$BINARY" 2>&1 || true)
cat >"$DIST/BUILD_INFO.txt" <<EOF
candidate_id=$CANDIDATE_ID
source_sha=$SOURCE_SHA
packager_sha=$PACKAGER_SHA
target=$TARGET
profile=$PROFILE
version=$VERSION
rustc=$RUSTC_VERSION
cargo=$CARGO_VERSION
cargo_lock_sha256=$CARGO_LOCK_SHA
hyper_patch_sha256=$HYPER_PATCH_SHA
elf=$ELF_DESCRIPTION
runtime_dependencies:
$LDD_OUTPUT
EOF
chmod 0644 "$DIST/BUILD_INFO.txt"

python3 "$SCRIPT_DIR/make_manifest.py" \
    --root "$DIST" \
    --output "$DIST/manifest.json" \
    --version "$VERSION" \
    --source-sha "$SOURCE_SHA" \
    --packager-sha "$PACKAGER_SHA" \
    --target "$TARGET" \
    --profile "$PROFILE" \
    --rustc "$RUSTC_VERSION" \
    --cargo "$CARGO_VERSION" \
    --cargo-lock-sha256 "$CARGO_LOCK_SHA" \
    --hyper-patch-sha256 "$HYPER_PATCH_SHA"

python3 "$SCRIPT_DIR/verify_manifest.py" --root "$DIST" --target "$TARGET"

rm -f "$ARCHIVE"
tar --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner \
    --format=gnu \
    -cf - -C "$OUTPUT_DIR" "$(basename "$DIST")" \
    | gzip -n -9 >"$ARCHIVE"
ARCHIVE_SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
printf '%s  %s\n' "$ARCHIVE_SHA" "$(basename "$ARCHIVE")" >"$SUMS"

printf 'archive=%s\n' "$ARCHIVE"
printf 'sha256=%s\n' "$ARCHIVE_SHA"
printf 'candidate_id=%s\n' "$CANDIDATE_ID"
printf 'source_sha=%s\n' "$SOURCE_SHA"
