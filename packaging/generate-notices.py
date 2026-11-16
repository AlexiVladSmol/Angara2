#!/usr/bin/env python3
"""Collect license/notice material for the packages in the Cargo graph."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


LICENSE_NAMES = re.compile(r"^(licen[cs]e|notice|copying|copyright)", re.IGNORECASE)


def run_metadata(manifest_path: Path, target: str) -> dict:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--manifest-path",
        str(manifest_path),
    ]
    output = subprocess.check_output(command, text=True)
    return json.loads(output)


def license_files(package_dir: Path) -> list[Path]:
    found: list[Path] = []
    if not package_dir.is_dir():
        return found
    for child in sorted(package_dir.iterdir(), key=lambda item: item.name):
        if child.is_symlink() or not child.is_file():
            continue
        if LICENSE_NAMES.search(child.name):
            found.append(child)
    return found


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-path", required=True, type=Path)
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--notices", required=True, type=Path)
    parser.add_argument("--hyper-patch", required=True, type=Path)
    args = parser.parse_args()

    metadata = run_metadata(args.manifest_path, args.target)
    packages = {package["id"]: package for package in metadata["packages"]}
    resolve = metadata.get("resolve") or {}
    nodes = resolve.get("nodes") or []
    graph_ids: set[str] = set()
    for node in nodes:
        graph_ids.add(node["id"])
        graph_ids.update(node.get("dependencies", []))
    if not graph_ids:
        graph_ids.update(packages)

    selected = []
    for package_id in sorted(graph_ids):
        package = packages.get(package_id)
        if package is None:
            continue
        if package["name"] == "angara":
            continue
        selected.append(package)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, str, str, str]] = []
    for package in selected:
        name = package["name"]
        version = package["version"]
        license_expression = package.get("license") or "UNKNOWN"
        source = package.get("repository") or package.get("source") or "vendored/path dependency"
        package_dir = Path(package["manifest_path"]).resolve().parent
        destination = args.output_dir / f"{safe_name(name)}-{safe_name(version)}"
        destination.mkdir(parents=True, exist_ok=True)
        files = license_files(package_dir)
        if files:
            for source_file in files:
                shutil.copyfile(source_file, destination / safe_name(source_file.name))
            notice_files = ", ".join(sorted(path.name for path in files))
        else:
            fallback = (
                f"Package: {name} {version}\n"
                f"License expression: {license_expression}\n"
                f"Source: {source}\n"
                "The package did not ship a separate LICENSE/NOTICE file in its "
                "crate archive. The license expression is recorded here and in "
                "Cargo metadata; consult the package source for the full text.\n"
            )
            (destination / "LICENSE.txt").write_text(fallback, encoding="utf-8", newline="\n")
            notice_files = "generated note (no license file in crate)"
        rows.append((name, version, license_expression, source, notice_files))

    patch_destination = args.output_dir / "angara-hyper-patch"
    patch_destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.hyper_patch, patch_destination / "ANGARA_PATCH.md")

    lines = [
        "# Angara third-party notices",
        "",
        "This file was generated from the locked Cargo graph for the "
        f"`{args.target}` release target. Angara itself has no license chosen "
        "yet; this file covers external dependencies only.",
        "",
        "| Package | Version | License expression | Source | Included notice files |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, version, license_expression, source, notice_files in rows:
        source_text = source.replace("|", "\\|")
        lines.append(
            f"| `{name}` | `{version}` | `{license_expression}` | {source_text} | {notice_files} |"
        )
    lines.extend(
        [
            "",
            "## Local hyper patch",
            "",
            "The release uses the Angara-limited hyper 1.12.0 patch. Its description",
            "is included at `licenses/angara-hyper-patch/ANGARA_PATCH.md` and in the",
            "release manifest (`hyper_patch_sha256`).",
            "",
        ]
    )
    args.notices.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"notices packages={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
