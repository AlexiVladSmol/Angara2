#!/usr/bin/env python3
"""Verify an extracted Angara release tree against its manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED = {
    "bin/angara",
    "systemd/angara.service",
    "install.sh",
    "angaractl",
    "config/angara.toml.default",
    "examples/m08-operations-https-basic.toml",
    "docs/ADMIN_GUIDE.md",
    "docs/RELEASE.md",
    "licenses/THIRD_PARTY_NOTICES.md",
    "provenance/Cargo.lock",
    "provenance/ANGARA_PATCH.md",
}


def fail(message: str) -> None:
    print(f"release verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value:
        fail("manifest contains an empty or non-string path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        fail(f"unsafe manifest path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"unsafe manifest path: {value!r}")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    manifest_path = (args.manifest or (root / "manifest.json")).resolve()
    if not root.is_dir():
        fail(f"release root is not a directory: {root}")
    if not manifest_path.is_file() or manifest_path.is_symlink():
        fail("manifest.json is missing or is not a regular file")

    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read manifest: {error}")

    if not isinstance(manifest, dict):
        fail("manifest root must be an object")
    if manifest.get("format_version") != 1:
        fail("manifest format_version must be 1")
    if manifest.get("package") != "angara":
        fail("manifest package must be angara")
    version = manifest.get("package_version")
    source_sha = manifest.get("source_sha")
    packager_sha = manifest.get("packager_sha")
    if not isinstance(version, str) or not re.match(r"^[0-9A-Za-z.+_-]+$", version):
        fail("manifest package_version is invalid")
    if not isinstance(source_sha, str) or not SHA40.match(source_sha):
        fail("manifest source_sha is invalid")
    if not isinstance(packager_sha, str) or not SHA40.match(packager_sha):
        fail("manifest packager_sha is invalid")
    if manifest.get("target") != args.target:
        fail(f"manifest target is not {args.target}")
    if manifest.get("binary") != "bin/angara":
        fail("manifest binary must be bin/angara")
    candidate_id = manifest.get("candidate_id")
    if candidate_id != f"{version}-{source_sha[:12]}":
        fail("manifest candidate_id does not match version/source SHA")
    for key in ("cargo_lock_sha256", "hyper_patch_sha256", "binary_sha256"):
        value = manifest.get(key)
        if not isinstance(value, str) or not SHA64.match(value):
            fail(f"manifest {key} is invalid")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        fail("manifest files must be a non-empty array")
    expected: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail("manifest files contains a non-object entry")
        relative = safe_relative(entry.get("path"))
        if relative == "manifest.json":
            fail("manifest must not list itself")
        if relative in expected:
            fail(f"duplicate manifest path: {relative}")
        expected[relative] = entry
    missing = sorted(REQUIRED - set(expected))
    if missing:
        fail("required release files are absent from the manifest: " + ", ".join(missing))

    actual: set[str] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json":
            continue
        if path.is_symlink():
            fail(f"release tree contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"release tree contains a non-regular file: {relative}")
        actual.add(relative)
    extra = sorted(actual - set(expected))
    absent = sorted(set(expected) - actual)
    if extra:
        fail("release tree contains files not listed in the manifest: " + ", ".join(extra[:8]))
    if absent:
        fail("release tree is missing manifest files: " + ", ".join(absent[:8]))

    for relative, entry in sorted(expected.items()):
        path = root / relative
        sha = entry.get("sha256")
        size = entry.get("size")
        mode = entry.get("mode")
        if not isinstance(sha, str) or not SHA64.match(sha):
            fail(f"manifest hash is invalid for {relative}")
        if not isinstance(size, int) or size < 0:
            fail(f"manifest size is invalid for {relative}")
        if not isinstance(mode, str) or not re.match(r"^[0-7]{4}$", mode):
            fail(f"manifest mode is invalid for {relative}")
        actual_mode = f"{stat.S_IMODE(path.lstat().st_mode):04o}"
        if path.stat().st_size != size:
            fail(f"size mismatch for {relative}")
        if actual_mode != mode:
            fail(f"mode mismatch for {relative}: manifest {mode}, actual {actual_mode}")
        if sha256_file(path) != sha:
            fail(f"SHA-256 mismatch for {relative}")

    binary = root / "bin" / "angara"
    if sha256_file(binary) != manifest["binary_sha256"]:
        fail("binary_sha256 does not match bin/angara")
    lock = root / "provenance" / "Cargo.lock"
    if sha256_file(lock) != manifest["cargo_lock_sha256"]:
        fail("cargo_lock_sha256 does not match provenance/Cargo.lock")
    patch = root / "provenance" / "ANGARA_PATCH.md"
    if sha256_file(patch) != manifest["hyper_patch_sha256"]:
        fail("hyper_patch_sha256 does not match provenance/ANGARA_PATCH.md")

    if not args.quiet:
        print(f"candidate_id={candidate_id}")
        print(f"source_sha={source_sha}")
        print(f"packager_sha={packager_sha}")
        print(f"binary_sha256={manifest['binary_sha256']}")
        print(f"files={len(expected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
