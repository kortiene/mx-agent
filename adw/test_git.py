"""Tests for adw/_git.py command construction, parsing, and dry-run.

`capture` is mocked; no real git/gh is invoked.
"""

from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest import mock

from adw import _git


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class CurrentBranchTests(unittest.TestCase):
    def test_strips_output(self) -> None:
        with mock.patch.object(_git, "capture", return_value=_cp(0, "feat/15-x\n")):
            self.assertEqual(_git.current_branch(), "feat/15-x")


class BranchTests(unittest.TestCase):
    def test_dry_run_prints_and_does_not_execute(self) -> None:
        with mock.patch.object(_git, "capture") as cap:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok, err = _git.create_or_checkout_branch("feat/15-x", "main", dry_run=True)
            cap.assert_not_called()
        self.assertTrue(ok)
        self.assertIn("[dry-run]", buf.getvalue())
        self.assertIn("git switch -c feat/15-x origin/main", buf.getvalue())

    def test_create_when_absent(self) -> None:
        # fetch ok, show-ref absent (rc 1), switch -c ok.
        seq = [_cp(0), _cp(1), _cp(0)]
        with mock.patch.object(_git, "capture", side_effect=seq) as cap:
            ok, err = _git.create_or_checkout_branch("feat/15-x", "main")
        self.assertTrue(ok)
        self.assertIsNone(err)
        switch_call = cap.call_args_list[-1].args[0]
        self.assertEqual(switch_call, ["git", "switch", "-c", "feat/15-x", "origin/main"])

    def test_switch_existing(self) -> None:
        seq = [_cp(0), _cp(0), _cp(0)]  # fetch, show-ref present, switch
        with mock.patch.object(_git, "capture", side_effect=seq) as cap:
            ok, _ = _git.create_or_checkout_branch("feat/15-x", "main")
        self.assertTrue(ok)
        self.assertEqual(cap.call_args_list[-1].args[0], ["git", "switch", "feat/15-x"])


class CommitTests(unittest.TestCase):
    def test_noop_when_clean(self) -> None:
        with mock.patch.object(_git, "capture", return_value=_cp(0, "")) as cap:
            ok, err = _git.commit_all("msg")
        self.assertTrue(ok)
        # Only the status probe ran; no add/commit.
        self.assertEqual(cap.call_count, 1)

    def test_commits_when_dirty(self) -> None:
        seq = [_cp(0, " M file"), _cp(0), _cp(0)]  # status dirty, add, commit
        with mock.patch.object(_git, "capture", side_effect=seq) as cap:
            ok, err = _git.commit_all("msg")
        self.assertTrue(ok)
        self.assertEqual(cap.call_args_list[-1].args[0], ["git", "commit", "-m", "msg"])


class PrTests(unittest.TestCase):
    def test_pr_for_branch_parses(self) -> None:
        with mock.patch.object(_git, "gh_json", return_value=[{"url": "https://x/pr/7"}]):
            self.assertEqual(_git.pr_for_branch("b", "/bin/gh", "o/r"), "https://x/pr/7")

    def test_pr_for_branch_none_when_empty(self) -> None:
        with mock.patch.object(_git, "gh_json", return_value=[]):
            self.assertIsNone(_git.pr_for_branch("b", "/bin/gh", "o/r"))

    def test_pr_for_branch_none_when_gh_fails(self) -> None:
        with mock.patch.object(_git, "gh_json", return_value=None):
            self.assertIsNone(_git.pr_for_branch("b", "/bin/gh", "o/r"))

    def test_create_pr_returns_number_and_url(self) -> None:
        with mock.patch.object(_git, "capture", return_value=_cp(0, "https://github.com/o/r/pull/42\n")):
            number, url, err = _git.create_pr("b", "t", "body", "main", "/bin/gh", "o/r")
        self.assertEqual(number, 42)
        self.assertEqual(url, "https://github.com/o/r/pull/42")
        self.assertIsNone(err)

    def test_create_pr_dry_run(self) -> None:
        with mock.patch.object(_git, "capture") as cap:
            buf = io.StringIO()
            with redirect_stdout(buf):
                number, url, err = _git.create_pr("b", "t", "body", "main", "/bin/gh", "o/r", dry_run=True)
            cap.assert_not_called()
        self.assertIn("[dry-run]", buf.getvalue())
        self.assertIsNone(err)


class PrNumberFromUrlTests(unittest.TestCase):
    def test_parses_trailing_number(self) -> None:
        self.assertEqual(_git.pr_number_from_url("https://github.com/o/r/pull/42"), 42)

    def test_tolerates_trailing_slash(self) -> None:
        self.assertEqual(_git.pr_number_from_url("https://github.com/o/r/pull/42/"), 42)

    def test_non_numeric_tail_is_none(self) -> None:
        self.assertIsNone(_git.pr_number_from_url("https://github.com/o/r/pull/abc"))

    def test_empty_is_none(self) -> None:
        self.assertIsNone(_git.pr_number_from_url(""))


class CiStatusTests(unittest.TestCase):
    def _status(self, rollup):
        # rollup is a Python list (or None to simulate a missing key).
        with mock.patch.object(_git, "gh_json", return_value={"statusCheckRollup": rollup}):
            return _git.ci_status(7, "/bin/gh", "o/r")

    def test_success(self) -> None:
        res = self._status([{"name": "ci", "status": "COMPLETED", "conclusion": "SUCCESS"}])
        self.assertEqual(res["state"], "success")

    def test_failure_lists_jobs(self) -> None:
        res = self._status([{"name": "ci", "status": "COMPLETED", "conclusion": "FAILURE"}])
        self.assertEqual(res["state"], "failure")
        self.assertEqual(res["failing_jobs"][0]["name"], "ci")

    def test_pending(self) -> None:
        res = self._status([{"name": "ci", "status": "IN_PROGRESS", "conclusion": ""}])
        self.assertEqual(res["state"], "pending")

    def test_none_when_empty_rollup(self) -> None:
        # Query succeeded, no checks registered -> 'none' (distinct from 'unknown').
        res = self._status([])
        self.assertEqual(res["state"], "none")

    def test_unknown_when_gh_fails(self) -> None:
        with mock.patch.object(_git, "gh_json", return_value=None):
            res = _git.ci_status(7, "/bin/gh", "o/r")
        self.assertEqual(res["state"], "unknown")


class MergeTests(unittest.TestCase):
    def test_squash_merge_dry_run(self) -> None:
        with mock.patch.object(_git, "capture") as cap:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok, err = _git.squash_merge(7, "/bin/gh", "o/r", dry_run=True)
            cap.assert_not_called()
        self.assertTrue(ok)
        self.assertIn("--squash", buf.getvalue())
        self.assertIn("--delete-branch", buf.getvalue())

    def test_squash_merge_executes(self) -> None:
        with mock.patch.object(_git, "capture", return_value=_cp(0)) as cap:
            ok, err = _git.squash_merge(7, "/bin/gh", "o/r")
        self.assertTrue(ok)
        self.assertIn("--squash", cap.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
