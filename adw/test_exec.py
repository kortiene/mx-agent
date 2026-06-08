"""Tests for adw/_exec.py: env allowlist, bin resolution, gh/git queries.

These never spawn real processes (capture/shutil.which are mocked) except the
OSError-guard test, which intentionally invokes a missing binary.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adw import _exec
from adw._exec import (
    _resolve_bin,
    detect_repo,
    format_progress,
    issue_state,
    post_progress,
    resolve_gh_bin,
    resolve_runner_bin,
    safe_subprocess_env,
)
from adw.common import AdwError


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class SafeEnvTests(unittest.TestCase):
    def test_allowlist_and_token_gating(self) -> None:
        fake = {
            "PATH": "/bin",
            "HOME": "/home/u",
            "ANTHROPIC_API_KEY": "sk-test",
            "GH_TOKEN": "ghp_secret",
            "MATRIX_ACCESS_TOKEN": "matrix-secret",
            "MX_AGENT_RUNNER": "pi",
            "SOMETHING_ELSE": "x",
        }
        with mock.patch.dict(os.environ, fake, clear=True):
            without = safe_subprocess_env(allow_gh_token=False)
            withtok = safe_subprocess_env(allow_gh_token=True)

        # Allowlisted vars present; PYTHONUNBUFFERED forced.
        self.assertEqual(without["PATH"], "/bin")
        self.assertEqual(without["ANTHROPIC_API_KEY"], "sk-test")
        self.assertEqual(without["PYTHONUNBUFFERED"], "1")
        # Secrets / non-allowlisted withheld.
        self.assertNotIn("GH_TOKEN", without)
        self.assertNotIn("MATRIX_ACCESS_TOKEN", without)
        self.assertNotIn("MX_AGENT_RUNNER", without)
        self.assertNotIn("SOMETHING_ELSE", without)
        # GH_TOKEN only when explicitly allowed.
        self.assertEqual(withtok["GH_TOKEN"], "ghp_secret")

    def test_absent_vars_dropped(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/bin"}, clear=True):
            env = safe_subprocess_env(allow_gh_token=False)
        self.assertNotIn("HOME", env)  # absent → dropped, not None

    def test_extra_allow_cannot_smuggle_denied_prefix(self) -> None:
        with mock.patch.dict(os.environ, {"MATRIX_X": "no", "MY_OK": "yes"}, clear=True):
            env = safe_subprocess_env(allow_gh_token=False, extra_allow=["MATRIX_X", "MY_OK"])
        self.assertNotIn("MATRIX_X", env)
        self.assertEqual(env["MY_OK"], "yes")


class ResolveBinTests(unittest.TestCase):
    def test_env_override_wins(self) -> None:
        with mock.patch.dict(os.environ, {"FOO_BIN": "/custom/foo"}, clear=True):
            self.assertEqual(_resolve_bin("FOO_BIN", "foo", []), "/custom/foo")

    def test_path_used_when_no_env(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value="/usr/bin/foo"):
            self.assertEqual(_resolve_bin("FOO_BIN", "foo", []), "/usr/bin/foo")

    def test_fallback_when_no_env_or_path(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            candidate = Path(d) / "foo"
            candidate.write_text("#!/bin/sh\n")
            candidate.chmod(0o755)
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
                self.assertEqual(_resolve_bin("FOO_BIN", "foo", [candidate]), str(candidate))

    def test_none_when_nothing_found(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(_resolve_bin("FOO_BIN", "foo", []))


class ResolveRunnerGhTests(unittest.TestCase):
    def test_runner_uses_env(self) -> None:
        with mock.patch.dict(os.environ, {"PI_BIN": "/x/pi"}, clear=True):
            self.assertEqual(resolve_runner_bin("pi"), "/x/pi")

    def test_runner_missing_raises(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            with self.assertRaises(AdwError):
                resolve_runner_bin("pi")

    def test_gh_missing_returns_none(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(resolve_gh_bin())


class GhQueryTests(unittest.TestCase):
    def test_issue_state_parses(self) -> None:
        with mock.patch.object(_exec, "capture", return_value=_cp(0, "CLOSED\n")):
            self.assertEqual(issue_state("/bin/gh", 5, "o/r"), "CLOSED")

    def test_issue_state_unknown_on_failure(self) -> None:
        with mock.patch.object(_exec, "capture", return_value=_cp(1, "", "boom")):
            self.assertEqual(issue_state("/bin/gh", 5, "o/r"), "UNKNOWN")

    def test_issue_state_no_gh(self) -> None:
        self.assertEqual(issue_state(None, 5, "o/r"), "UNKNOWN")

    def test_detect_repo_parses(self) -> None:
        with mock.patch.object(_exec, "capture", return_value=_cp(0, "owner/repo\n")):
            self.assertEqual(detect_repo("/bin/gh"), "owner/repo")

    def test_detect_repo_empty_on_failure(self) -> None:
        with mock.patch.object(_exec, "capture", return_value=_cp(1)):
            self.assertEqual(detect_repo("/bin/gh"), "")


class CaptureGuardTests(unittest.TestCase):
    def test_missing_binary_does_not_raise(self) -> None:
        result = _exec.capture(["this-binary-does-not-exist-xyz-123"])
        self.assertEqual(result.returncode, 127)


class ProgressTests(unittest.TestCase):
    def test_format_includes_tag(self) -> None:
        line = format_progress("a1b2c3d4", "plan", "done")
        self.assertTrue(line.startswith("[MX-ADW] a1b2c3d4_plan:"))
        self.assertIn("done", line)

    def test_post_progress_noop_without_gh(self) -> None:
        with mock.patch.object(_exec, "capture") as cap:
            post_progress(None, 5, "o/r", "a1b2c3d4", "plan", "hi")
            cap.assert_not_called()

    def test_post_progress_never_raises(self) -> None:
        with mock.patch.object(_exec, "capture", return_value=_cp(1, "", "fail")):
            # Should swallow the failure and not raise.
            post_progress("/bin/gh", 5, "o/r", "a1b2c3d4", "plan", "hi")


if __name__ == "__main__":
    unittest.main()
