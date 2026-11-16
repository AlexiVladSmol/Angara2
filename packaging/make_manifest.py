#!/usr/bin/env python3
"""Generate a deterministic manifest for an Angara release archive.

The manifest deliberately excludes itself.  The archive as a whole is covered
by the external SHA256SUMS file, so a manifest cannot contain its own hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_mode(path: Path) -> str:
    mode = stat.S_IMODE(path.lstat().st_mode)
    return f"{mode:04o}"


def collect_files(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json":
            continue
        if path.is_symlink():
            raise SystemExit(f"release tree contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit(f"release tree contains a non-regular file: {relative}")
        files.append(
            {
                "path": relative,
                "mode": file_mode(path),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--packager-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default="release")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--cargo-lock-sha256", required=True)
    parser.add_argument("--hyper-patch-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"release root is not a directory: {root}")
    if not SHA_RE.match(args.source_sha):
        raise SystemExit("source SHA must be 40 lowercase hexadecimal characters")
    if not SHA_RE.match(args.packager_sha):
        raise SystemExit("packager SHA must be 40 lowercase hexadecimal characters")
    for name in ("cargo_lock_sha256", "hyper_patch_sha256"):
        if not re.match(r"^[0-9a-f]{64}$", getattr(args, name)):
            raise SystemExit(f"{name} must be 64 lowercase hexadecimal characters")

    binary = root / "bin" / "angara"
    if not binary.is_file() or binary.is_symlink():
        raise SystemExit("release tree must contain a regular bin/angara")
    candidate_id = f"{args.version}-{args.source_sha[:12]}"
    manifest = {
        "format_version": 1,
        "package": "angara",
        "package_version": args.version,
        "candidate_id": candidate_id,
        "source_sha": args.source_sha,
        "packager_sha": args.packager_sha,
        "target": args.target,
        "profile": args.profile,
        "toolchain": {
            "rustc": args.rustc,
            "cargo": args.cargo,
        },
        "cargo_lock_sha256": args.cargo_lock_sha256,
        "hyper_patch_sha256": args.hyper_patch_sha256,
        "binary": "bin/angara",
        "binary_sha256": sha256_file(binary),
        "files": collect_files(root),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"manifest candidate_id={candidate_id}")
    print(f"manifest binary_sha256={manifest['binary_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
