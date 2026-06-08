"""Tests for adw/_phases.py: routing, gates, output mapping, run_agent_phase.

No real runner is invoked; run_agent_capture is mocked.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adw import _phases, _state
from adw._phases import (
    gate_conditional,
    gate_document,
    gate_e2e,
    model_for_phase,
    parse_phases,
    template_path,
    to_result,
)
from adw._state import AdwState
from adw.common import AdwError, render_prompt_file


class ParsePhasesTests(unittest.TestCase):
    def test_default_is_full_chain(self) -> None:
        self.assertEqual(parse_phases(None)[0], "classify")
        self.assertIn("document", parse_phases(None))

    def test_subset(self) -> None:
        self.assertEqual(parse_phases("plan,implement,tests"), ["plan", "implement", "tests"])

    def test_unknown_raises(self) -> None:
        with self.assertRaises(AdwError):
            parse_phases("plan,bogus")


class ModelRoutingTests(unittest.TestCase):
    def test_tier_defaults_claude(self) -> None:
        self.assertEqual(model_for_phase("classify", "claude"), "haiku")
        self.assertEqual(model_for_phase("implement", "claude"), "opus")
        self.assertEqual(model_for_phase("tests", "claude"), "sonnet")

    def test_cli_model_overrides_all(self) -> None:
        self.assertEqual(model_for_phase("classify", "claude", cli_model="opus"), "opus")

    def test_env_override_one_phase(self) -> None:
        with mock.patch.dict(os.environ, {"MX_AGENT_MODEL_CLASSIFY": "sonnet"}, clear=False):
            self.assertEqual(model_for_phase("classify", "claude"), "sonnet")
            # other phases unaffected
            self.assertEqual(model_for_phase("implement", "claude"), "opus")

    def test_cli_beats_env(self) -> None:
        with mock.patch.dict(os.environ, {"MX_AGENT_MODEL_CLASSIFY": "sonnet"}, clear=False):
            self.assertEqual(model_for_phase("classify", "claude", cli_model="opus"), "opus")


class GateTests(unittest.TestCase):
    def test_e2e_true_on_cross_boundary(self) -> None:
        run_it, _ = gate_e2e("this changes the daemon IPC protocol")
        self.assertTrue(run_it)

    def test_e2e_false_otherwise(self) -> None:
        run_it, _ = gate_e2e("rename an internal helper")
        self.assertFalse(run_it)

    def test_e2e_false_on_incidental_substrings(self) -> None:
        # Word-boundary matching: the helper path and "design"/"assignee" must
        # not trip "exec"/signing hints.
        run_it, _ = gate_e2e("refactor adw/_exec.py and redesign the assignee list")
        self.assertFalse(run_it)

    def test_e2e_true_on_whole_word(self) -> None:
        run_it, _ = gate_e2e("add the exec subsystem and signing keys")
        self.assertTrue(run_it)

    def test_document_true_on_doc_files(self) -> None:
        run_it, _ = gate_document("internal", ["docs/architecture.md"])
        self.assertTrue(run_it)

    def test_document_true_on_api_hint(self) -> None:
        run_it, _ = gate_document("adds a new CLI flag", [])
        self.assertTrue(run_it)

    def test_document_false_internal(self) -> None:
        run_it, _ = gate_document("internal refactor", ["src/lib.rs"])
        self.assertFalse(run_it)

    def test_conditional_dispatches_e2e(self) -> None:
        # e2e routes through gate_e2e (signal only).
        self.assertEqual(gate_conditional("e2e", "touches the daemon IPC"), gate_e2e("touches the daemon IPC"))

    def test_conditional_dispatches_document(self) -> None:
        # document routes through gate_document (signal + files).
        self.assertEqual(
            gate_conditional("document", "internal", ["docs/x.md"]),
            gate_document("internal", ["docs/x.md"]),
        )

    def test_conditional_rejects_non_conditional_phase(self) -> None:
        with self.assertRaises(AdwError):
            gate_conditional("implement", "anything")


class ToResultTests(unittest.TestCase):
    def test_classify_requires_class(self) -> None:
        self.assertEqual(to_result("classify", {"issue_class": "feat", "reason": "x"}).issue_class, "feat")
        with self.assertRaises(AdwError):
            to_result("classify", {"reason": "missing"})

    def test_review_maps_findings_and_wrote_flags(self) -> None:
        data = {
            "findings": [
                {"severity": "blocker", "description": "bug", "location": "a.rs:1"},
                {"severity": "skippable", "description": "nit"},
            ],
            "wrote_commit_message": True,
            "wrote_pr_body": True,
        }
        res = to_result("review", data)
        self.assertEqual(len(res.findings), 2)
        self.assertEqual(res.findings[0].severity, "blocker")
        self.assertTrue(res.wrote_commit_message)
        self.assertTrue(res.wrote_pr_body)

    def test_document_wrote_flags(self) -> None:
        res = to_result(
            "document",
            {"docs_updated": True, "files": ["docs/x.md"], "wrote_commit_message": True, "wrote_pr_body": False},
        )
        self.assertTrue(res.docs_updated)
        self.assertTrue(res.wrote_commit_message)
        self.assertFalse(res.wrote_pr_body)

    def test_resolve_counts(self) -> None:
        res = to_result("resolve", {"resolved": 2, "remaining": 1, "summary": "s"})
        self.assertEqual((res.resolved, res.remaining), (2, 1))

    def test_resolve_bad_int_raises_adw_error(self) -> None:
        # Malformed agent JSON must surface as AdwError, not a bare ValueError
        # traceback (AdwError subclasses ValueError, so callers' except misses it).
        with self.assertRaises(AdwError):
            to_result("resolve", {"resolved": "two", "remaining": 0})


class TemplateRenderTests(unittest.TestCase):
    def test_classify_template_substitutes_issue_number(self) -> None:
        path = template_path("pi", "classify")
        rendered = render_prompt_file(path, ["5", "Title and body"])
        self.assertIn("#5", rendered)
        self.assertIn("issue_class", rendered)  # contract documented inline


class RunAgentPhaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.state = AdwState(adw_id="a1b2c3d4")

    def _call(self, capture_side):
        with mock.patch.object(_phases, "run_agent_capture", side_effect=capture_side) as cap:
            data = _phases.run_agent_phase(
                "classify", ["5", "ctx"], state=self.state, runner="pi", runner_bin="/bin/pi"
            )
        return data, cap

    def test_parses_fenced_json(self) -> None:
        data, cap = self._call([(0, '```json\n{"issue_class": "feat"}\n```')])
        self.assertEqual(data, {"issue_class": "feat"})
        self.assertEqual(cap.call_count, 1)
        # prompt was persisted for debugging
        self.assertTrue((Path(self.tmp) / "a1b2c3d4" / "classify" / "prompt.txt").is_file())

    def test_reparse_nudge_then_success(self) -> None:
        data, cap = self._call([(0, "no json"), (0, '{"issue_class": "fix"}')])
        self.assertEqual(data, {"issue_class": "fix"})
        self.assertEqual(cap.call_count, 2)

    def test_double_failure_raises(self) -> None:
        with self.assertRaises(AdwError):
            self._call([(0, "nope"), (0, "still nope")])

    def test_timeout_skips_retry(self) -> None:
        # A timeout exit code (124) must not trigger a second full-timeout retry.
        with self.assertRaises(AdwError):
            _, cap = self._call([(124, "")])
        # Only one invocation happened (no nudge retry).
        # (Re-run to inspect call count without the raise masking it.)
        with mock.patch.object(_phases, "run_agent_capture", side_effect=[(124, "")]) as cap:
            with self.assertRaises(AdwError):
                _phases.run_agent_phase("classify", ["5", "ctx"], state=self.state, runner="pi", runner_bin="/bin/pi")
        self.assertEqual(cap.call_count, 1)


if __name__ == "__main__":
    unittest.main()
