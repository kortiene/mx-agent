"""Tests for work_issue.py pure logic and argument validation.

These never invoke gh or git: only branch derivation, scope extraction, and the
argument-validation paths of main() are exercised.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from adw import work_issue as w


class BranchDerivationTests(unittest.TestCase):
    """Tests for branch prefix and title slugification."""

    def test_prefix_from_type_label(self) -> None:
        self.assertEqual(w.branch_prefix(["area:cli", "type:bug"]), "fix")
        self.assertEqual(w.branch_prefix(["type:docs"]), "docs")
        self.assertEqual(w.branch_prefix(["type:ci"]), "ci")
        self.assertEqual(w.branch_prefix(["type:testing"]), "test")

    def test_prefix_defaults_to_feat(self) -> None:
        self.assertEqual(w.branch_prefix(["area:daemon"]), "feat")
        self.assertEqual(w.branch_prefix([]), "feat")

    def test_slugify_strips_phase_prefix(self) -> None:
        self.assertEqual(w.slugify_title("Phase issue 7: Add Workspace Export!"), "add-workspace-export")

    def test_slugify_trims_and_caps_at_40(self) -> None:
        self.assertEqual(w.slugify_title("  Hello, World!  "), "hello-world")
        self.assertEqual(w.slugify_title("a" * 60), "a" * 40)


class ScopeExtractionTests(unittest.TestCase):
    """Tests for extracting the Backlog Entry section."""

    def test_extracts_section_and_collapses_blank_runs(self) -> None:
        body = "intro\n\n## Backlog Entry\n\nDo X\n\n\nThen Y\n"
        self.assertEqual(w.extract_scope(body), "Do X\n\nThen Y")

    def test_missing_section_returns_empty(self) -> None:
        self.assertEqual(w.extract_scope("no backlog section here"), "")


class ArgValidationTests(unittest.TestCase):
    """Tests for main() input validation (no gh/git reached)."""

    def _run(self, argv: list[str]) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return w.main(argv)

    def test_missing_issue_fails(self) -> None:
        self.assertEqual(self._run([]), 1)

    def test_non_numeric_issue_fails(self) -> None:
        self.assertEqual(self._run(["abc"]), 1)


if __name__ == "__main__":
    unittest.main()
