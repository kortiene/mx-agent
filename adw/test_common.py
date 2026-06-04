"""Tests for Agent Development Workflow helper logic."""

from __future__ import annotations

import unittest

from adw.common import AdwError, expand_issue_selectors, render_prompt, split_notes, strip_frontmatter
from adw.issues import render_args


class PromptRenderingTests(unittest.TestCase):
    """Tests for prompt loading and rendering helpers."""

    def test_strip_frontmatter_removes_yaml_header(self) -> None:
        text = "---\ndescription: demo\n---\nBody\n"
        self.assertEqual(strip_frontmatter(text), "Body\n")

    def test_strip_frontmatter_leaves_plain_text(self) -> None:
        self.assertEqual(strip_frontmatter("Body\n"), "Body\n")

    def test_render_prompt_replaces_positional_and_slices(self) -> None:
        rendered = render_prompt("implement", ["specs/demo.md", "extra", "notes"])
        self.assertIn("specs/demo.md", rendered)
        self.assertIn("extra notes", rendered)
        self.assertNotIn("$1", rendered)
        self.assertNotIn("${@:2}", rendered)

    def test_render_prompt_replaces_arguments_alias(self) -> None:
        rendered = render_prompt("plan", ["add", "feature"])
        self.assertIn("add feature", rendered)
        self.assertNotIn("$ARGUMENTS", rendered)


class IssueSelectorTests(unittest.TestCase):
    """Tests for `/issues` selector parsing."""

    def test_expands_single_ids_and_ranges(self) -> None:
        self.assertEqual(expand_issue_selectors(["10", "12-14", "20..21"]), [10, 12, 13, 14, 20, 21])

    def test_deduplicates_preserving_first_occurrence(self) -> None:
        self.assertEqual(expand_issue_selectors(["10", "10-12", "11", "14"]), [10, 11, 12, 14])

    def test_rejects_invalid_selector(self) -> None:
        with self.assertRaises(AdwError):
            expand_issue_selectors(["abc"])

    def test_rejects_descending_range(self) -> None:
        with self.assertRaises(AdwError):
            expand_issue_selectors(["14-12"])

    def test_rejects_zero_issue_id(self) -> None:
        with self.assertRaises(AdwError):
            expand_issue_selectors(["0"])

    def test_split_notes(self) -> None:
        selectors, notes = split_notes(["12", "13-14", "--", "shared", "notes"])
        self.assertEqual(selectors, ["12", "13-14"])
        self.assertEqual(notes, ["shared", "notes"])

    def test_issues_render_args_normalizes_selectors_and_notes(self) -> None:
        self.assertEqual(
            render_args(["10", "12-13", "12", "--", "shared", "notes"]),
            ["10", "12", "13", "--", "shared", "notes"],
        )

    def test_issues_render_args_requires_selector(self) -> None:
        with self.assertRaises(AdwError):
            render_args([])


if __name__ == "__main__":
    unittest.main()
