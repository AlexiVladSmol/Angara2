# Angara — release build and archive

This document describes the M08 release-candidate build. It is intentionally
separate from the administrator runbook.

## Build environment

- Ubuntu 24.04 x86_64.
- Rust toolchain pinned by `rust-toolchain.toml` (Rust 1.97.1).
- `python3` 3.11+ for manifest/notices generation (not required on the target).
- `tar`, `gzip`, `sha256sum`, `file`, `ldd`, `cargo-deny`.
- No operator configuration, users file, TLS key, token or password input.

## Reproducible command

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny check
packaging/build-release.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --packager-sha "$(git rev-parse HEAD)" \
  --output-dir target/release-artifacts
```

The script creates:

```
angara-0.1.0-linux-x86_64-<source-short-sha>.tar.gz
SHA256SUMS
angara-0.1.0-linux-x86_64-<source-short-sha>/
  bin/angara
  systemd/angara.service
  install.sh
  angaractl
  verify_manifest.py
  config/angara.toml.default
  docs/ADMIN_GUIDE.md
  docs/RELEASE.md
  RELEASE_CHECKLIST.md
  README.md
  examples/minimal.toml
  examples/multi-listener.toml
  examples/m02-policy.toml
  examples/m02-egress-local.toml
  examples/m03-http-local.toml
  examples/m04-connect-local.toml
  examples/m08-operations-https-basic.toml
  licenses/THIRD_PARTY_NOTICES.md
  licenses/<package>-<version>/...
  provenance/Cargo.lock
  provenance/ANGARA_PATCH.md
  BUILD_INFO.txt
  manifest.json
```

`SHA256SUMS` is external to the archive. `manifest.json` deliberately does not
list itself; the archive hash covers it. The manifest records `format_version`,
package/version, full source and packager SHAs, target/profile, rustc/Cargo
versions, Cargo.lock hash, binary hash, hyper patch hash, and every other file
with its mode/size/SHA-256.

## Deterministic packaging

The archive uses `tar --sort=name --mtime=<source commit time>` with numeric
owner/group 0, and `gzip -n`. The ordering and metadata are stable for a given
build environment. Bit-for-bit equality of independent Rust builds is only
claimed after an actual comparison; see the M08 evidence comment for the
measured result. Do not describe a single build as reproducible by itself.

## License notices

`packaging/generate-notices.py` reads `cargo metadata --locked
--filter-platform x86_64-unknown-linux-gnu`, copies LICENSE/NOTICE/COPYING
files shipped by each crate, writes a generated note when a crate ships no
separate file, and includes the local hyper patch description. Angara itself
is MIT-licensed (`LICENSE` in the repository root); the generator still skips
the `angara` package, so the archive does not ship that file yet.

## A and B builds for upgrade testing

For A→B→A, build A from the accepted M07 merge and B from the M08 head:

```sh
git worktree add ../angara-a 4656430caf034e28fc6dba9ff340d7ddde9a4711
packaging/build-release.sh \
  --source-dir ../angara-a \
  --source-sha 4656430caf034e28fc6dba9ff340d7ddde9a4711 \
  --packager-sha "$(git rev-parse HEAD)" \
  --output-dir target/release-artifacts/a
packaging/build-release.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --packager-sha "$(git rev-parse HEAD)" \
  --output-dir target/release-artifacts/b
```

The A manifest records the M07 source SHA and the M08 packager SHA. If the two
binaries happen to be byte-identical, keep both release directories and show
the actual `/proc/<pid>/exe` and `current` changes rather than claiming a
different binary.

## Verification before review

```sh
sha256sum -c target/release-artifacts/.../SHA256SUMS
python3 packaging/verify_manifest.py --root target/release-artifacts/.../angara-...
systemd-analyze verify packaging/angara.service
```

The archive is installed on the isolated Ubuntu 24.04 stand, not from the
development tree. The PR/CI evidence records the exact source SHA and archive
SHA-256. Corrupt archives, wrong hashes, unsafe paths and unreadable
configuration/users/TLS files must fail before the running version is stopped.
