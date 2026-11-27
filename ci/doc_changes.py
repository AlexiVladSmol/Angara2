"""Select the CI suite and validate documentation for the checked-out revision."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


DOCS = {
    "README.md", "RELEASE_CHECKLIST.md", "AGENTS.md", "docs/ADMIN_GUIDE.md",
    "docs/RELEASE.md", "docs/ROADMAP.md", "docs/WORKFLOW.md", "docs/DECISIONS.md",
}

# Markdown inputs copied by packaging/build-release.sh, including provenance.
PACKAGED_DOCS = (
    "README.md", "RELEASE_CHECKLIST.md", "docs/ADMIN_GUIDE.md",
    "docs/RELEASE.md", "vendor/hyper-1.12.0/ANGARA_PATCH.md",
)


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def docs_in_diff(root, event, base, head):
    """Return allowed paths, or an empty list to request the regular suite."""
    if event not in {"push", "pull_request"} or not base or not head:
        return []
    try:
        if event == "pull_request":
            if git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
                return []
            bases = git(root, "merge-base", "--all", base, head).splitlines()
            if len(bases) != 1:
                return []
            base = bases[0].decode("ascii")
        # A rename appears as deletion + addition, so both names are checked.
        raw = git(root, "diff", "--no-ext-diff", "--no-renames", "--name-only",
                  "-z", base, head, "--")
    except subprocess.CalledProcessError as error:
        print(f"Cannot determine complete diff, selecting full CI: {error}", file=sys.stderr)
        return []
    if not raw or not raw.endswith(b"\0"):
        return []
    paths = [os.fsdecode(item) for item in raw[:-1].split(b"\0")]
    return paths if all(path in DOCS for path in paths) else []


def link_targets(tokens):
    for token in tokens:
        if token.type == "link_open":
            yield token.attrs["href"]
        elif token.type == "image":
            yield token.attrs["src"]
        if token.children:
            yield from link_targets(token.children)


def check_docs(root, paths):
    from markdown_it import MarkdownIt

    parser = MarkdownIt("commonmark").enable(["table", "strikethrough"])
    errors = []
    for name in PACKAGED_DOCS:
        if not (root / name).is_file():
            errors.append(f"packaging/build-release.sh: missing document {name}")
    for name in paths:
        doc = root / name
        if doc.is_symlink() or (doc.exists() and not doc.is_file()):
            errors.append(f"{name}: expected a regular Markdown file")
            continue
        if not doc.exists():  # Deleted documents have no outgoing links.
            continue
        for target in link_targets(parser.parse(doc.read_text(encoding="utf-8"))):
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            path = unquote(url.path)
            candidate = root / path.lstrip("/") if path.startswith("/") else doc.parent / path
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root) or not resolved.exists():
                errors.append(f"{name}: missing local target {target}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser("select")
    for arg in ("event", "base", "head"):
        select.add_argument(arg)
    commands.add_parser("check").add_argument("paths_json")
    args = parser.parse_args()
    root = Path.cwd()
    if args.command == "select":
        paths = docs_in_diff(root, args.event, args.base, args.head)
        mode = "docs" if paths else "full"
        print(f"Selected CI mode: {mode}")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            print(f"mode={mode}", file=output)
            print(f"paths={json.dumps(paths)}", file=output)
        return 0
    errors = check_docs(root, json.loads(args.paths_json))
    for error in errors:
        print(error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
