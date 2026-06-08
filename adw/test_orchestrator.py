"""Tests for adw/_orchestrator.py.

The runner, git, and gh layers are mocked; no real agent/git/gh/cargo runs.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from adw import _orchestrator, _phases, _state
from adw import issue as issue_mod
from adw._orchestrator import confirm_merge, finalize_gates, patch_loop, resolve_loop, truncate
from adw._phases import ReviewFinding
from adw._state import AdwState
from adw.common import AdwError


def _noop(_phase, _msg):  # progress callback
    pass


class TruncateTests(unittest.TestCase):
    def test_short_unchanged(self) -> None:
        self.assertEqual(truncate("abc", 10), "abc")

    def test_long_tail_kept(self) -> None:
        out = truncate("x" * 100, 10)
        self.assertTrue(out.endswith("x" * 10))
        self.assertIn("truncated", out)


class ConfirmMergeTests(unittest.TestCase):
    def test_yes_passes(self) -> None:
        confirm_merge(yes=True, isatty=False)  # no raise

    def test_non_tty_without_yes_aborts(self) -> None:
        with self.assertRaises(AdwError):
            confirm_merge(yes=False, isatty=False)

    def test_tty_confirm_yes(self) -> None:
        with mock.patch.object(_orchestrator, "confirm", return_value=True):
            confirm_merge(yes=False, isatty=True)

    def test_tty_confirm_no_aborts(self) -> None:
        with mock.patch.object(_orchestrator, "confirm", return_value=False):
            with self.assertRaises(AdwError):
                confirm_merge(yes=False, isatty=True)


class FinalizeGatesTests(unittest.TestCase):
    def test_custom_test_cmd_replaces_only_test_gate(self) -> None:
        # --test-cmd narrows the test gate but keeps fmt/clippy/build.
        args = mock.Mock(test_cmd="pytest -q")
        gates = finalize_gates(args)
        self.assertEqual(gates[0], "pytest -q")
        self.assertNotIn("cargo test --all", gates)
        self.assertIn("cargo fmt --check", gates)
        self.assertIn("cargo build --all", gates)

    def test_default_cargo_set(self) -> None:
        args = mock.Mock(test_cmd="")
        gates = finalize_gates(args)
        self.assertIn("cargo test --all", gates)
        self.assertIn("cargo fmt --check", gates)


class ResolveLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = AdwState(adw_id="a1b2c3d4")
        self.kw = dict(
            runner="pi", runner_bin="/bin/pi", cli_model="", thinking="", passthru=[], env=None, timeout=0, progress=_noop
        )

    def test_green_immediately(self) -> None:
        with mock.patch.object(_orchestrator, "run_cmd", return_value=(0, "")) as rc, mock.patch.object(
            _phases, "run_agent_phase"
        ) as agent:
            ok = resolve_loop(self.state, test_cmd="cargo test", max_attempts=3, **self.kw)
        self.assertTrue(ok)
        agent.assert_not_called()
        self.assertEqual(rc.call_count, 1)

    def test_fix_then_green(self) -> None:
        with mock.patch.object(_orchestrator, "run_cmd", side_effect=[(1, "fail"), (0, "")]), mock.patch.object(
            _phases, "run_agent_phase", return_value={"resolved": 1, "remaining": 0}
        ) as agent:
            ok = resolve_loop(self.state, test_cmd="cargo test", max_attempts=3, **self.kw)
        self.assertTrue(ok)
        self.assertEqual(agent.call_count, 1)

    def test_no_progress_stops(self) -> None:
        with mock.patch.object(_orchestrator, "run_cmd", return_value=(1, "fail")), mock.patch.object(
            _phases, "run_agent_phase", return_value={"resolved": 0, "remaining": 2}
        ) as agent:
            ok = resolve_loop(self.state, test_cmd="cargo test", max_attempts=3, **self.kw)
        self.assertFalse(ok)
        self.assertEqual(agent.call_count, 1)

    def test_max_attempts(self) -> None:
        with mock.patch.object(_orchestrator, "run_cmd", return_value=(1, "fail")) as rc, mock.patch.object(
            _phases, "run_agent_phase", return_value={"resolved": 1, "remaining": 1}
        ) as agent:
            ok = resolve_loop(self.state, test_cmd="cargo test", max_attempts=2, **self.kw)
        self.assertFalse(ok)
        self.assertEqual(agent.call_count, 2)
        self.assertEqual(rc.call_count, 3)  # initial + after each resolve


class PatchLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = AdwState(adw_id="a1b2c3d4")
        self.kw = dict(
            runner="pi", runner_bin="/bin/pi", cli_model="", thinking="", passthru=[], env=None, timeout=0, progress=_noop
        )

    def test_no_blockers_skips(self) -> None:
        findings = [ReviewFinding("skippable", "nit"), ReviewFinding("tech_debt", "later")]
        with mock.patch.object(_phases, "run_agent_phase") as agent:
            ok = patch_loop(self.state, findings, max_attempts=2, **self.kw)
        self.assertTrue(ok)
        agent.assert_not_called()

    def test_blockers_resolved(self) -> None:
        findings = [ReviewFinding("blocker", "bug")]
        with mock.patch.object(_phases, "run_agent_phase", return_value={"resolved": 1, "remaining": 0}) as agent:
            ok = patch_loop(self.state, findings, max_attempts=2, **self.kw)
        self.assertTrue(ok)
        self.assertEqual(agent.call_count, 1)

    def test_no_progress_breaks(self) -> None:
        findings = [ReviewFinding("blocker", "bug")]
        with mock.patch.object(_phases, "run_agent_phase", return_value={"resolved": 0, "remaining": 1}):
            ok = patch_loop(self.state, findings, max_attempts=3, **self.kw)
        self.assertFalse(ok)


class CiFixLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = AdwState(adw_id="a1b2c3d4", branch_name="feat/5-x")
        self.kw = dict(
            gh_bin="/bin/gh",
            repo="o/r",
            max_attempts=2,
            runner="pi",
            runner_bin="/bin/pi",
            cli_model="",
            thinking="",
            passthru=[],
            env=None,
            timeout=0,
            poll_interval=0,
            max_polls=3,
            progress=_noop,
        )

    def test_success_immediately(self) -> None:
        with mock.patch.object(_orchestrator._git, "ci_status", return_value={"state": "success", "failing_jobs": []}):
            self.assertTrue(_orchestrator.ci_fix_loop(self.state, 7, **self.kw))

    def test_unknown_returns_false(self) -> None:
        with mock.patch.object(_orchestrator._git, "ci_status", return_value={"state": "unknown", "failing_jobs": []}):
            self.assertFalse(_orchestrator.ci_fix_loop(self.state, 7, **self.kw))

    def test_none_settles_to_success(self) -> None:
        # An empty rollup (no checks registered) settles then is treated as green.
        with mock.patch.object(_orchestrator._git, "ci_status", return_value={"state": "none", "failing_jobs": []}):
            self.assertTrue(_orchestrator.ci_fix_loop(self.state, 7, **self.kw))

    def test_red_then_fixed(self) -> None:
        statuses = [
            {"state": "failure", "failing_jobs": [{"name": "ci", "log_excerpt": ""}]},
            {"state": "success", "failing_jobs": []},
        ]
        with mock.patch.object(_orchestrator._git, "ci_status", side_effect=statuses), mock.patch.object(
            _phases, "run_agent_phase", return_value={"resolved": 1, "remaining": 0}
        ), mock.patch.object(_orchestrator, "working_tree_dirty", return_value=True), mock.patch.object(
            _orchestrator._git, "commit_all", return_value=(True, None)
        ), mock.patch.object(_orchestrator._git, "push", return_value=(True, None)):
            self.assertTrue(_orchestrator.ci_fix_loop(self.state, 7, **self.kw))

    def test_fix_with_no_change_stops(self) -> None:
        # Agent claims a fix but the tree is clean -> can't move CI; stop.
        with mock.patch.object(
            _orchestrator._git, "ci_status", return_value={"state": "failure", "failing_jobs": [{"name": "ci"}]}
        ), mock.patch.object(_phases, "run_agent_phase", return_value={"resolved": 1, "remaining": 0}), mock.patch.object(
            _orchestrator, "working_tree_dirty", return_value=False
        ):
            self.assertFalse(_orchestrator.ci_fix_loop(self.state, 7, **self.kw))


class RunIntegrationTests(unittest.TestCase):
    """Drive run() end to end with every external effect mocked."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        p = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        p.start()
        self.addCleanup(p.stop)

    def _args(self, extra=None):
        argv = ["5", "--yes", "--no-progress"] + (extra or [])
        ours, _ = issue_mod.split_passthru(argv)
        return issue_mod.build_parser().parse_args(ours)

    def _patch_env(self, stack, *, run_agent, fetch_issue, env_vars, issue_states, pr_for_branch):
        """Enter all the external-effect patches the orchestrator touches."""

        stack.enter_context(mock.patch.dict("os.environ", env_vars, clear=True))
        stack.enter_context(mock.patch.object(_orchestrator, "resolve_gh_bin", return_value="/bin/gh"))
        stack.enter_context(mock.patch.object(_orchestrator, "detect_repo", return_value="o/r"))
        stack.enter_context(mock.patch.object(_orchestrator, "resolve_runner_bin", return_value="/bin/pi"))
        stack.enter_context(mock.patch.object(_orchestrator, "working_tree_dirty", return_value=False))
        stack.enter_context(mock.patch.object(_orchestrator, "issue_state", side_effect=issue_states))
        stack.enter_context(mock.patch.object(_orchestrator, "changed_files", return_value=["src/lib.rs"]))
        stack.enter_context(mock.patch.object(_orchestrator, "run_cmd", return_value=(0, "")))
        stack.enter_context(mock.patch.object(_orchestrator, "capture"))
        stack.enter_context(mock.patch.object(_orchestrator.work_issue, "fetch_issue", return_value=fetch_issue))
        stack.enter_context(mock.patch.object(_orchestrator.work_issue, "set_status"))
        g = _orchestrator._git
        stack.enter_context(mock.patch.object(g, "create_or_checkout_branch", return_value=(True, None)))
        stack.enter_context(mock.patch.object(g, "commit_all", return_value=(True, None)))
        stack.enter_context(mock.patch.object(g, "push", return_value=(True, None)))
        stack.enter_context(mock.patch.object(g, "pr_for_branch", return_value=pr_for_branch))
        stack.enter_context(mock.patch.object(g, "create_pr", return_value=(42, "https://x/pull/42", None)))
        stack.enter_context(mock.patch.object(g, "ci_status", return_value={"state": "success", "failing_jobs": []}))
        stack.enter_context(mock.patch.object(g, "squash_merge", return_value=(True, None)))
        stack.enter_context(mock.patch.object(g, "pull_rebase", return_value=(True, None)))
        stack.enter_context(mock.patch.object(_phases, "run_agent_phase", side_effect=run_agent))
        stack.enter_context(redirect_stdout(io.StringIO()))
        stack.enter_context(redirect_stderr(io.StringIO()))

    def test_phases_run_in_order_and_token_withheld(self) -> None:
        order: list[str] = []

        def fake_phase(phase, _targs, **kw):
            order.append(phase)
            # The phased agent env must never carry GH_TOKEN.
            self.assertNotIn("GH_TOKEN", kw.get("env") or {})
            st = kw["state"]
            if phase == "review":
                # Simulate the agent authoring commit/PR text to workspace files.
                cm = _phases.commit_message_path(st)
                cm.parent.mkdir(parents=True, exist_ok=True)
                cm.write_text("feat: phased pipeline\n\ncloses #5", encoding="utf-8")
                _phases.pr_body_path(st).write_text("Closes #5\n\nImplements the thing.", encoding="utf-8")
            return {
                "classify": {"issue_class": "feat", "reason": "r"},
                "plan": {"plan_file": "specs/x.md", "spec_created": True},
                "implement": {"summary": "did it", "files_changed": ["src/lib.rs"]},
                "tests": {"tests_added": True},
                "review": {"findings": [], "wrote_commit_message": True, "wrote_pr_body": True},
            }[phase]

        with ExitStack() as stack:
            self._patch_env(
                stack,
                run_agent=fake_phase,
                fetch_issue={"title": "T", "body": "B", "labels": ["type:feature"]},
                env_vars={"GH_TOKEN": "ghp_secret", "PATH": "/bin"},
                issue_states=["OPEN", "CLOSED"],
                pr_for_branch=None,
            )
            rc = _orchestrator.run(self._args(), [], 5)

        self.assertEqual(rc, 0)
        # e2e and document are gated off for an internal feature touching src/lib.rs.
        self.assertEqual(order, ["classify", "plan", "implement", "tests", "review"])
        state = AdwState.load(_loaded_id(self.tmp))
        self.assertIsNotNone(state)
        self.assertIn("merge", state.completed_phases)
        # The agent-authored commit message (artifact file) was absorbed into state.
        self.assertEqual(state.commit_message, "feat: phased pipeline\n\ncloses #5")
        self.assertIn("Implements the thing.", state.pr_body or "")

    def test_resume_skips_completed_phases(self) -> None:
        pre = AdwState(adw_id="a1b2c3d4", issue_number="5", branch_name="feat/5-x")
        for ph in ["setup", "classify", "plan", "implement", "tests", "resolve", "e2e", "review", "patch", "document"]:
            pre.mark_done(ph)
        pre.commit_message = "feat: x\n\ncloses #5"
        pre.pr_number = 42
        pre.save()

        def no_phase(*_a, **_k):
            raise AssertionError("no phase should run on resume")

        with ExitStack() as stack:
            self._patch_env(
                stack,
                run_agent=no_phase,
                fetch_issue={"title": "T", "body": "B", "labels": []},
                env_vars={"PATH": "/bin"},
                issue_states=["OPEN", "CLOSED"],
                pr_for_branch="https://x/pull/42",
            )
            rc = _orchestrator.run(self._args(["--adw-id", "a1b2c3d4", "--resume"]), [], 5)
        self.assertEqual(rc, 0)

    def test_resume_after_merge_does_not_remerge(self) -> None:
        pre = AdwState(adw_id="a1b2c3d4", issue_number="5", branch_name="feat/5-x")
        for ph in ["setup", "classify", "plan", "implement", "tests", "resolve",
                   "e2e", "review", "patch", "document", "merge"]:
            pre.mark_done(ph)
        pre.pr_number = 42
        pre.save()

        with ExitStack() as stack:
            self._patch_env(
                stack,
                run_agent=lambda *a, **k: {},
                fetch_issue={"title": "T", "body": "B", "labels": []},
                env_vars={"PATH": "/bin"},
                issue_states=["OPEN", "CLOSED"],
                pr_for_branch="https://x/pull/42",
            )
            merge = stack.enter_context(
                mock.patch.object(_orchestrator._git, "squash_merge", return_value=(True, None))
            )
            commit = stack.enter_context(
                mock.patch.object(_orchestrator._git, "commit_all", return_value=(True, None))
            )
            rc = _orchestrator.run(self._args(["--adw-id", "a1b2c3d4", "--resume"]), [], 5)
        self.assertEqual(rc, 0)
        merge.assert_not_called()  # already merged; finalize must short-circuit
        commit.assert_not_called()

    def _run_expecting_error(self, extra, issue=5):
        with ExitStack() as stack:
            self._patch_env(
                stack,
                run_agent=lambda *a, **k: {},
                fetch_issue={"title": "T", "body": "B", "labels": []},
                env_vars={"PATH": "/bin"},
                issue_states=["OPEN", "OPEN"],
                pr_for_branch=None,
            )
            with self.assertRaises(AdwError):
                _orchestrator.run(self._args(extra), [], issue)

    def test_resume_requires_adw_id(self) -> None:
        self._run_expecting_error(["--resume"])

    def test_adw_id_without_resume_refuses_to_clobber(self) -> None:
        AdwState(adw_id="a1b2c3d4", issue_number="5").save()
        self._run_expecting_error(["--adw-id", "a1b2c3d4"])

    def test_resume_rejects_issue_mismatch(self) -> None:
        pre = AdwState(adw_id="a1b2c3d4", issue_number="5")
        pre.mark_done("setup")
        pre.save()
        # Resuming run 'a1b2c3d4' (issue 5) while asking for issue 9 must abort.
        self._run_expecting_error(["--adw-id", "a1b2c3d4", "--resume"], issue=9)

    def test_resume_recovers_review_findings_for_patch(self) -> None:
        # review done with a persisted blocker, patch NOT done -> on resume the
        # patch phase must still see the blocker (regression: findings were lost).
        pre = AdwState(adw_id="a1b2c3d4", issue_number="5", branch_name="feat/5-x")
        for ph in ["setup", "classify", "plan", "implement", "tests", "resolve", "e2e", "review"]:
            pre.mark_done(ph)
        pre.review_findings = [{"severity": "blocker", "description": "bug", "location": "a.rs:1"}]
        pre.commit_message = "feat: x\n\ncloses #5"
        pre.pr_number = 42
        pre.save()

        seen: list = []

        def capture_patch(_state, findings, **_kw):
            seen.extend(findings)
            return True

        with ExitStack() as stack:
            self._patch_env(
                stack,
                run_agent=lambda *a, **k: {},
                fetch_issue={"title": "T", "body": "B", "labels": []},
                env_vars={"PATH": "/bin"},
                issue_states=["OPEN", "CLOSED"],
                pr_for_branch="https://x/pull/42",
            )
            stack.enter_context(mock.patch.object(_orchestrator, "patch_loop", side_effect=capture_patch))
            rc = _orchestrator.run(self._args(["--adw-id", "a1b2c3d4", "--resume"]), [], 5)
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].severity, "blocker")
        self.assertEqual(seen[0].location, "a.rs:1")


def _loaded_id(tmp: str) -> str:
    """Return the single adw_id directory created under the temp AGENTS_DIR."""

    ids = [p.name for p in Path(tmp).iterdir() if p.is_dir()]
    return ids[0]


if __name__ == "__main__":
    unittest.main()
