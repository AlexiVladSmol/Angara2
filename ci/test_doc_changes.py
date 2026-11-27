"""Regression fixtures for the pull-request and push paths in CI."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from doc_changes import DOCS, PACKAGED_DOCS, check_docs, docs_in_diff


class HistoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.base = self.commit("initial.txt")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def commit(self, path=None):
        if path:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(path, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def test_docs_across_multiple_commits(self):
        self.commit("README.md")
        head = self.commit("docs/ROADMAP.md")
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                self.assertEqual(set(docs_in_diff(self.root, event, self.base, head)),
                                 {"README.md", "docs/ROADMAP.md"})

    def test_earlier_code_change_keeps_full_suite(self):
        self.commit("src/main.rs")
        head = self.commit("README.md")
        for event in ("pull_request", "push"):
            self.assertEqual(docs_in_diff(self.root, event, self.base, head), [])

    def test_pr_uses_merge_base(self):
        self.git("switch", "-qc", "topic")
        head = self.commit("README.md")
        self.git("switch", "-q", "main")
        base_tip = self.commit("src/main.rs")
        self.assertEqual(docs_in_diff(self.root, "pull_request", base_tip, head), ["README.md"])

    def test_unknown_workflow_and_rename_both_directions(self):
        base = self.base
        for path in ("docs/new.md", ".github/workflows/ci.yml"):
            head = self.commit(path)
            self.assertEqual(docs_in_diff(self.root, "push", base, head), [])
            base = head
        for source, dest in (("docs/new.md", "README.md"), ("README.md", "elsewhere.md")):
            self.git("mv", source, dest)
            head = self.commit()
            self.assertEqual(docs_in_diff(self.root, "push", base, head), [])
            base = head

    def test_empty_unavailable_and_dispatch(self):
        self.assertEqual(docs_in_diff(self.root, "push", self.base, self.base), [])
        self.assertEqual(docs_in_diff(self.root, "push", "0" * 40, self.base), [])
        head = self.commit("README.md")
        self.assertEqual(docs_in_diff(self.root, "workflow_dispatch", self.base, head), [])


class MarkdownTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for path in DOCS.union(PACKAGED_DOCS):
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.touch()

    def test_relative_links_images_tables_references_and_code(self):
        (self.root / "docs/a b.md").touch()
        doc = "docs/ROADMAP.md"
        (self.root / doc).write_text(
            "[root](../README.md#title) ![image](a%20b.md) [web](https://example.invalid/)\n\n"
            "[reference][ref]\n\n[ref]: a%20b.md\n\n"
            "| link |\n| --- |\n| [bad](missing.md#frag) |\n\n"
            "~~~md\n[example](example-only.md)\n~~~\n\n`[x](another.md)`",
            encoding="utf-8",
        )
        self.assertEqual(check_docs(self.root, [doc]), [f"{doc}: missing local target missing.md#frag"])

    def test_deleted_documents_and_package_inputs(self):
        (self.root / "docs/ROADMAP.md").unlink()
        self.assertEqual(check_docs(self.root, ["docs/ROADMAP.md"]), [])
        (self.root / "RELEASE_CHECKLIST.md").unlink()
        self.assertEqual(check_docs(self.root, ["README.md"]),
                         ["packaging/build-release.sh: missing document RELEASE_CHECKLIST.md"])
