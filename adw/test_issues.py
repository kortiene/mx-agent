"""Tests for issues.py batch orchestration and rendering.

The batch-execution tests mock issue.main so no pi/claude/gh runs, and isolate
the lock file under a temporary TMPDIR.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from adw import issues as issues_mod
from adw.common import AdwError


class HelperTests(unittest.TestCase):
    """Tests for the pure batch helpers."""

    def test_apply_start_drops_earlier_issues(self) -> None:
        self.assertEqual(issues_mod.apply_start([15, 16, 17, 18], 17), [17, 18])
        self.assertEqual(issues_mod.apply_start([15, 16], 0), [15, 16])

    def test_apply_start_missing_raises(self) -> None:
        with self.assertRaises(AdwError):
            issues_mod.apply_start([15, 16], 99)

    def test_issue_flags_forwards_set_options(self) -> None:
        ns = mock.Mock(
            runner="claude", model="opus", thinking="", phases="", one_shot=False, log_dir="",
            ci_max_polls=80, ci_poll_interval=None,
        )
        self.assertEqual(
            issues_mod.issue_flags(ns, True),
            ["--runner", "claude", "--model", "opus", "--ci-max-polls", "80", "--yes"],
        )

    def test_issue_flags_forwards_phases_and_one_shot(self) -> None:
        ns = mock.Mock(
            runner="", model="", thinking="", phases="plan,implement", one_shot=True, log_dir="",
            ci_max_polls=80, ci_poll_interval=None,
        )
        self.assertEqual(
            issues_mod.issue_flags(ns, False),
            ["--phases", "plan,implement", "--one-shot", "--ci-max-polls", "80"],
        )

    def test_issue_flags_forwards_ci_budget_overrides(self) -> None:
        # A higher --ci-max-polls / custom --ci-poll-interval reach each issue.py run;
        # this is what keeps a batch's merge gate from expiring before the live suite.
        ns = mock.Mock(
            runner="", model="", thinking="", phases="", one_shot=False, log_dir="",
            ci_max_polls=120, ci_poll_interval=45,
        )
        self.assertEqual(
            issues_mod.issue_flags(ns, False),
            ["--ci-max-polls", "120", "--ci-poll-interval", "45"],
        )

    def test_issue_flags_omits_unset_ci_max_polls(self) -> None:
        # default=None means "don't forward; let issue.py keep its own default".
        ns = mock.Mock(
            runner="", model="", thinking="", phases="", one_shot=False, log_dir="",
            ci_max_polls=None, ci_poll_interval=None,
        )
        self.assertEqual(issues_mod.issue_flags(ns, False), [])


class RenderAndDryRunTests(unittest.TestCase):
    """Tests for --print-prompt rendering and --dry-run planning."""

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = issues_mod.main(argv)
        return code, out.getvalue()

    def test_print_prompt_renders_normalized_selectors(self) -> None:
        code, out = self._run(["12", "13-14", "--print-prompt"])
        self.assertEqual(code, 0)
        self.assertIn("12 13 14", out)

    def test_dry_run_prints_plan(self) -> None:
        code, out = self._run(["18-19", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("python adw/issue.py 18", out)
        self.assertIn("python adw/issue.py 19", out)

    def test_descending_range_rejected(self) -> None:
        code, _ = self._run(["20-18", "--dry-run"])
        self.assertEqual(code, 1)


class BatchExecutionTests(unittest.TestCase):
    """Tests that drive run_batch with issue.main mocked out."""

    def _run(self, argv: list[str], fake) -> tuple[int, list[list[str]]]:
        calls: list[list[str]] = []

        def recording(passed_argv):
            calls.append(list(passed_argv))
            return fake(passed_argv)

        tmp = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"TMPDIR": tmp}), mock.patch.object(
            issues_mod, "make_adw_id", return_value="aaaaaaaa"
        ), mock.patch.object(
            issues_mod.issue_mod, "main", side_effect=recording
        ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = issues_mod.main(argv)
        return code, calls

    def test_runs_each_issue_in_order_with_forwarded_flags(self) -> None:
        code, calls = self._run(["15", "16", "--yes"], lambda a: 0)
        self.assertEqual(code, 0)
        self.assertEqual(
            calls,
            [
                ["15", "--adw-id", "aaaaaaaa", "--ci-max-polls", "80", "--yes"],
                ["16", "--adw-id", "aaaaaaaa", "--ci-max-polls", "80", "--yes"],
            ],
        )

    def test_stops_on_first_failure_by_default(self) -> None:
        code, calls = self._run(["15", "16", "--yes"], lambda a: 1)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [["15", "--adw-id", "aaaaaaaa", "--ci-max-polls", "80", "--yes"]])

    def test_keep_going_continues_past_failure(self) -> None:
        code, calls = self._run(["15", "16", "--yes", "--keep-going"], lambda a: 1)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)

    def test_tail_after_separator_is_forwarded_to_runner(self) -> None:
        # `-- <flags>` must reach issue.py after a `--` so they pass to the runner,
        # not get parsed as issue.py's own flags.
        code, calls = self._run(
            ["221", "--runner", "claude", "--yes", "--", "--dangerously-skip-permissions"], lambda a: 0
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            calls,
            [
                [
                    "221", "--adw-id", "aaaaaaaa", "--runner", "claude",
                    "--ci-max-polls", "80", "--yes", "--", "--dangerously-skip-permissions",
                ]
            ],
        )


if __name__ == "__main__":
    unittest.main()
