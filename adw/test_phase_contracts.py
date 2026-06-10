"""Offline self-test: every phased prompt carries its machine contract.

Renders each phase's composed prompt (preamble + reused/new template body +
JSON-contract footer) without invoking any agent, and asserts the phased rules
and output contract are present. This catches the failure mode where a reused
interactive template silently lacks a JSON contract or git-prohibition — at CI
time instead of mid-run. Mock-free, stdlib only.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adw import _phases, _state
from adw._phases import AGENT_PHASES, OUTPUT_CONTRACT, compose_phase_prompt, to_result
from adw._state import AdwState

# One representative key from each phase's JSON contract, to confirm the footer
# carries the right schema for that phase.
_PHASE_KEY = {
    "classify": "issue_class",
    "plan": "plan_file",
    "implement": "files_changed",
    "tests": "tests_added",
    "resolve": "resolved",
    "e2e": "e2e_added",
    "review": "findings",
    "patch": "resolved",
    "document": "docs_updated",
}


class PhaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.state = AdwState(adw_id="a1b2c3d4")

    def test_every_phase_has_no_git_rule_and_json_contract(self) -> None:
        for phase in AGENT_PHASES:
            with self.subTest(phase=phase):
                prompt = compose_phase_prompt(phase, ["5", "issue context"], self.state)
                self.assertIn("do NOT run git", prompt)
                self.assertIn("no GitHub access", prompt)
                self.assertIn("```json", prompt)
                self.assertIn(_PHASE_KEY[phase], prompt)

    def test_artifact_phases_reference_workspace_files(self) -> None:
        for phase in ("review", "document"):
            with self.subTest(phase=phase):
                prompt = compose_phase_prompt(phase, ["5", "ctx"], self.state)
                self.assertIn("commit_message.txt", prompt)
                self.assertIn("pr_body.md", prompt)
                self.assertIn("a1b2c3d4", prompt)  # the concrete workspace path

    def test_non_artifact_phase_has_no_file_instruction(self) -> None:
        prompt = compose_phase_prompt("implement", ["5", "ctx"], self.state)
        self.assertNotIn("commit_message.txt", prompt)
        self.assertNotIn("pr_body.md", prompt)

    def test_review_uses_dedicated_working_tree_template(self) -> None:
        prompt = compose_phase_prompt("review", ["specs/x.md", "ctx"], self.state)
        # Dedicated phased body reviews the working tree, not a PR, and is not the
        # PR-oriented interactive review.md ("Review this pull request").
        normalized = " ".join(prompt.split()).lower()  # collapse wrapped whitespace
        self.assertIn("working tree", normalized)
        self.assertIn("no pull request yet", normalized)
        self.assertNotIn("review this pull request", normalized)

    def test_code_mutating_phases_instruct_cargo_fmt(self) -> None:
        # Every phase that edits Rust must tell the agent to run `cargo fmt`.
        # The Python finalize step runs `cargo fmt --check` as a pre-merge gate
        # and aborts the run (no commit/push/PR) on any unformatted line, so a
        # code phase that never formats can silently kill an otherwise-complete
        # run. Regression: the `patch`/`resolve` phases once lacked this and a
        # patch-phase formatting violation aborted a finished run before its PR.
        for phase in ("implement", "tests", "e2e", "resolve", "patch"):
            with self.subTest(phase=phase):
                prompt = compose_phase_prompt(phase, ["specs/x.md", "ctx"], self.state)
                self.assertIn("cargo fmt", prompt)

    def test_every_phase_contract_has_a_result_mapping(self) -> None:
        # Each phase named in the contract table must map to a dataclass.
        for phase in AGENT_PHASES:
            self.assertIn(phase, OUTPUT_CONTRACT)
            with self.subTest(phase=phase):
                # to_result must accept a minimal payload built from the contract keys.
                minimal = {"issue_class": "feat"} if phase == "classify" else {}
                # Should not raise for classify (has a required field); others tolerate {}.
                to_result(phase, minimal)


if __name__ == "__main__":
    unittest.main()
