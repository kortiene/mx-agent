"""Shared execution helpers for the executable ADW drivers.

These wrap `subprocess`, runner/`gh` resolution, GitHub queries, and small
console helpers shared by `issue.py`, `issues.py`, and `work_issue.py`. They
intentionally live apart from `common.py`, which stays render-only. Unix-only,
standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from adw.common import AdwError

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- console -----------------------------------------------------------------


def note(message: str) -> None:
    """Print a progress note to stderr (stdout carries runner/command output)."""

    print(f">> {message}", file=sys.stderr)


def die(message: str) -> "None":
    """Raise a user-facing `AdwError`; callers print it as `error: ...`."""

    raise AdwError(message)


def assume_yes(flag: bool) -> bool:
    """Whether confirmation prompts should be skipped (flag or MX_AGENT_YES=1)."""

    return flag or os.environ.get("MX_AGENT_YES") == "1"


def confirm(prompt: str) -> bool:
    """Write a prompt to stderr and read a yes/no answer from stdin."""

    sys.stderr.write(prompt)
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


# --- subprocess --------------------------------------------------------------


def capture(cmd: Sequence[str]) -> subprocess.CompletedProcess:
    """Run a command capturing text stdout/stderr; never raises on non-zero."""

    return subprocess.run(list(cmd), capture_output=True, text=True, check=False)


def run(cmd: Sequence[str]) -> int:
    """Run a command with inherited stdio; return its exit code."""

    return subprocess.run(list(cmd), check=False).returncode


def gh_json(cmd: Sequence[str]):
    """Run a `gh` command expected to emit JSON; return parsed data or `None`."""

    try:
        result = capture(cmd)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return None


# --- executable resolution ---------------------------------------------------


def _resolve_bin(env_var: str, name: str, fallbacks: Sequence[Path]) -> "str | None":
    """Resolve an executable via an env override, `$PATH`, then fallbacks."""

    override = os.environ.get(env_var)
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    for candidate in fallbacks:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def resolve_runner_bin(runner: str) -> str:
    """Resolve the runner executable, raising `AdwError` if it is missing."""

    home = Path.home()
    if runner == "pi":
        found = _resolve_bin("PI_BIN", "pi", [home / ".local/share/pi-node/current/bin/pi"])
        if found:
            return found
        raise AdwError("pi CLI not found; install pi or set PI_BIN")
    found = _resolve_bin("CLAUDE_BIN", "claude", [home / ".claude/local/claude", home / ".local/bin/claude"])
    if found:
        return found
    raise AdwError("claude CLI not found; install Claude Code or set CLAUDE_BIN")


def resolve_gh_bin() -> "str | None":
    """Resolve the `gh` executable, or `None` if unavailable."""

    return _resolve_bin("GH_BIN", "gh", [Path.home() / ".local/bin/gh"])


# --- GitHub / git queries ----------------------------------------------------


def issue_state(gh_bin: "str | None", issue: int, repo: str) -> str:
    """Return an issue's state via `gh`, or `UNKNOWN` if undeterminable."""

    if not gh_bin:
        return "UNKNOWN"
    args = [gh_bin, "issue", "view", str(issue)]
    if repo:
        args += ["--repo", repo]
    args += ["--json", "state", "-q", ".state"]
    try:
        result = capture(args)
    except OSError:
        return "UNKNOWN"
    if result.returncode != 0:
        return "UNKNOWN"
    return result.stdout.strip() or "UNKNOWN"


def detect_repo(gh_bin: "str | None") -> str:
    """Best-effort `owner/repo` detection via `gh`, or empty string."""

    if not gh_bin:
        return ""
    try:
        result = capture([gh_bin, "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"])
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def working_tree_dirty() -> bool:
    """Return True when inside a git work tree with uncommitted changes."""

    inside = capture(["git", "rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0:
        return False
    return bool(capture(["git", "status", "--porcelain"]).stdout.strip())
