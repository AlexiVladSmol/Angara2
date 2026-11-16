#!/usr/bin/env bash
# Create a strict users TOML with synthetic users for stand tests.
set -euo pipefail

BIN=${1:?binary path}
OUTPUT=${2:?output path}
PASSWORD=${3:-synthetic-m08-password}

umask 077
ALICE=$(printf '%s\n' "$PASSWORD" | "$BIN" users hash --password-stdin)
BOB=$(printf '%s\n' "$PASSWORD" | "$BIN" users hash --password-stdin)
{
    printf 'version = 1\n\n'
    printf '[[users]]\nusername = "alice"\n'
    printf 'password_hash = "%s"\ndisabled = false\n\n' "$ALICE"
    printf '[[users]]\nusername = "bob"\n'
    printf 'password_hash = "%s"\ndisabled = false\n' "$BOB"
} >"$OUTPUT"
chmod 0600 "$OUTPUT"
