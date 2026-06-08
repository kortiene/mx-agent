"""Tests for Agent Development Workflow helper logic."""

from __future__ import annotations

import unittest

from adw.common import (
    AdwError,
    expand_issue_selectors,
    parse_json,
    partition_on_double_dash,
    render_prompt,
    split_notes,
    strip_frontmatter,
)
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


class PartitionOnDoubleDashTests(unittest.TestCase):
    """Tests for the shared `--` argv partition primitive."""

    def test_no_separator_returns_all_as_head(self) -> None:
        self.assertEqual(partition_on_double_dash(["15", "note"]), (["15", "note"], []))

    def test_splits_at_first_separator(self) -> None:
        head, tail = partition_on_double_dash(["15", "--json", "--", "--model", "x"])
        self.assertEqual(head, ["15", "--json"])
        self.assertEqual(tail, ["--model", "x"])

    def test_trailing_separator_yields_empty_tail(self) -> None:
        self.assertEqual(partition_on_double_dash(["a", "--"]), (["a"], []))

    def test_issues_render_args_normalizes_selectors_and_notes(self) -> None:
        self.assertEqual(
            render_args(["10", "12-13", "12", "--", "shared", "notes"]),
            ["10", "12", "13", "--", "shared", "notes"],
        )

    def test_issues_render_args_requires_selector(self) -> None:
        with self.assertRaises(AdwError):
            render_args([])


class ParseJsonTests(unittest.TestCase):
    """Tests for the fence/prose-tolerant JSON parser."""

    def test_raw_object(self) -> None:
        self.assertEqual(parse_json('{"a": 1}'), {"a": 1})

    def test_json_fence(self) -> None:
        text = "Here is my answer:\n```json\n{\"resolved\": 2}\n```"
        self.assertEqual(parse_json(text), {"resolved": 2})

    def test_bare_fence(self) -> None:
        text = "```\n[1, 2, 3]\n```"
        self.assertEqual(parse_json(text), [1, 2, 3])

    def test_prose_wrapped_object(self) -> None:
        text = "blah blah {\"k\": \"v\"} trailing words"
        self.assertEqual(parse_json(text), {"k": "v"})

    def test_uses_last_fenced_block(self) -> None:
        text = "```json\n{\"first\": 1}\n```\nthen\n```json\n{\"final\": 2}\n```"
        self.assertEqual(parse_json(text), {"final": 2})

    def test_garbage_raises(self) -> None:
        with self.assertRaises(AdwError):
            parse_json("no json here at all")

    def test_expect_dict_mismatch_raises(self) -> None:
        with self.assertRaises(AdwError):
            parse_json("[1, 2]", expect=dict)

    def test_expect_list_mismatch_raises(self) -> None:
        with self.assertRaises(AdwError):
            parse_json('{"a": 1}', expect=list)


if __name__ == "__main__":
    unittest.main()
