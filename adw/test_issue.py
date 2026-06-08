"""Tests for the `/issue` executor (adw/issue.py).

These cover argument parsing, command building, template selection, and the
offline `--print-prompt` / `--dry-run` paths. They never invoke pi, claude, or
gh: execution paths are exercised only through dry-run and print-prompt.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from adw import issue as issue_mod


class SplitPassthruTests(unittest.TestCase):
    """Tests for splitting argv at `--`."""

    def test_no_separator(self) -> None:
        self.assertEqual(issue_mod.split_passthru(["15", "note"]), (["15", "note"], []))

    def test_splits_at_separator(self) -> None:
        ours, passthru = issue_mod.split_passthru(["15", "--json", "--", "--model", "x"])
        self.assertEqual(ours, ["15", "--json"])
        self.assertEqual(passthru, ["--model", "x"])


class BuildRunnerCommandTests(unittest.TestCase):
    """Tests for mapping neutral options onto a runner invocation."""

    def test_pi_command(self) -> None:
        cmd = issue_mod.build_runner_command(
            "pi",
            "/bin/pi",
            json_mode=True,
            model="sonnet:high",
            thinking="high",
            passthru=["-nc"],
            prompt="PROMPT",
        )
        self.assertEqual(
            cmd,
            ["/bin/pi", "-p", "--mode", "json", "--model", "sonnet:high", "--thinking", "high", "-nc", "PROMPT"],
        )
        # pi has no --name flag (it errors on it); ensure we never emit one.
        self.assertNotIn("--name", cmd)

    def test_claude_command_ignores_thinking(self) -> None:
        cmd = issue_mod.build_runner_command(
            "claude",
            "/bin/claude",
            json_mode=False,
            model="opus",
            thinking="high",
            passthru=[],
            prompt="PROMPT",
        )
        self.assertEqual(cmd, ["/bin/claude", "-p", "--model", "opus", "PROMPT"])
        self.assertNotIn("--thinking", cmd)


class DefaultTemplateTests(unittest.TestCase):
    """Tests for per-runner template selection."""

    def test_pi_uses_pi_prompts(self) -> None:
        path = issue_mod.default_template("pi")
        self.assertTrue(str(path).endswith(".pi/prompts/issue.md"))

    def test_claude_prefers_claude_commands_when_present(self) -> None:
        path = issue_mod.default_template("claude")
        # The repo ships .claude/commands/issue.md, so claude resolves to it.
        self.assertTrue(str(path).endswith(".claude/commands/issue.md"))


class MainPrintPromptTests(unittest.TestCase):
    """Tests for the render-only and validation paths of main()."""

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = issue_mod.main(argv)
        return code, buf.getvalue()

    def test_print_prompt_substitutes_issue_number(self) -> None:
        code, out = self._run(["15", "--print-prompt"])
        self.assertEqual(code, 0)
        self.assertIn("issue #15", out)
        self.assertNotIn("$1", out)

    def test_print_prompt_substitutes_notes(self) -> None:
        code, out = self._run(["15", "keep", "it", "minimal", "--print-prompt"])
        self.assertEqual(code, 0)
        self.assertIn("keep it minimal", out)

    def test_missing_issue_number_fails(self) -> None:
        code, _ = self._run(["--print-prompt"])
        self.assertEqual(code, 1)

    def test_non_numeric_issue_fails(self) -> None:
        code, _ = self._run(["abc", "--print-prompt"])
        self.assertEqual(code, 1)

    def test_unknown_runner_fails(self) -> None:
        code, _ = self._run(["15", "--runner", "bogus", "--print-prompt"])
        self.assertEqual(code, 1)

    def test_one_shot_dry_run_prints_command_without_executing(self) -> None:
        with mock.patch.dict("os.environ", {"PI_BIN": "/usr/bin/true"}, clear=False):
            code, out = self._run(["15", "--one-shot", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("[dry-run]", out)
        self.assertIn("/usr/bin/true", out)
        self.assertIn("-p", out)

    def test_phased_dry_run_prints_plan(self) -> None:
        code, out = self._run(["15", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("[dry-run]", out)
        self.assertIn("phased run for issue #15", out)
        # Phase chain and the token-withholding posture are shown.
        self.assertIn("classify", out)
        self.assertIn("GH_TOKEN withheld", out)

    def test_phased_dry_run_custom_phases(self) -> None:
        code, out = self._run(["15", "--dry-run", "--phases", "plan,implement,tests"])
        self.assertEqual(code, 0)
        self.assertIn("plan -> implement -> tests", out)


if __name__ == "__main__":
    unittest.main()
