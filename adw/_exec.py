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


# --- issue progress comments -------------------------------------------------

# Tag stamped on every ADW-authored issue comment. It marks a comment as
# machine-authored so any future trigger (a Matrix listener, a poller) can skip
# the tool's own comments and avoid feedback loops.
MX_ADW_BOT_TAG = "[MX-ADW]"


def format_progress(adw_id: str, phase: str, message: str) -> str:
    """Format a run-tagged progress line for a GitHub issue comment.

    The body is built only from the run id, phase, and a caller-supplied fixed
    message — never runner output, environment, or secrets.
    """

    return f"{MX_ADW_BOT_TAG} {adw_id}_{phase}: {message}"


def post_progress(
    gh_bin: "str | None",
    issue: "int | str",
    repo: str,
    adw_id: str,
    phase: str,
    message: str,
) -> None:
    """Best-effort `gh issue comment` with a run-tagged body; never raises."""

    if not gh_bin:
        return
    args = [gh_bin, "issue", "comment", str(issue), "--body", format_progress(adw_id, phase, message)]
    if repo:
        args += ["--repo", repo]
    result = capture(args)
    if result.returncode != 0:
        note(f"could not post progress comment for #{issue} ({phase})")


# --- runner environment ------------------------------------------------------

# Base environment variables the coding-agent runner legitimately needs. The
# parent environment is NEVER copied wholesale: only these (plus an explicit
# `extra_allow`, and `GH_TOKEN`/`GH_BIN` when `allow_gh_token=True`) are passed
# through, so Matrix tokens, device keys, and unrelated secrets are withheld.
_BASE_ENV_ALLOW = (
    "HOME",
    "USER",
    "PATH",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "ANTHROPIC_API_KEY",
    "PI_BIN",
    "CLAUDE_BIN",
    "CLAUDE_CODE_PATH",
    "PI_MODEL",
    "PI_THINKING",
)

# Never forwarded to the agent, even via extra_allow.
_ENV_DENY_PREFIXES = ("MATRIX_", "MX_AGENT_")


def safe_subprocess_env(*, allow_gh_token: bool, extra_allow: Sequence[str] = ()) -> "dict[str, str]":
    """Build an allowlist environment for the coding-agent runner.

    Only allowlisted variables present in the parent environment are forwarded.
    `GH_TOKEN`/`GH_BIN` are included only when `allow_gh_token=True` (phased mode
    keeps the GitHub token out of the agent because Python performs all `gh`
    work; one-shot mode needs it because the agent pushes/merges). Variables
    matching `MATRIX_`/`MX_AGENT_` prefixes are never forwarded.
    """

    allow = list(_BASE_ENV_ALLOW)
    if allow_gh_token:
        allow += ["GH_TOKEN", "GH_BIN"]
    for key in extra_allow:
        if not any(key.startswith(p) for p in _ENV_DENY_PREFIXES):
            allow.append(key)

    env: dict[str, str] = {}
    for key in allow:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env["PYTHONUNBUFFERED"] = "1"
    return env


# --- subprocess --------------------------------------------------------------


def capture(cmd: Sequence[str]) -> subprocess.CompletedProcess:
    """Run a command capturing text stdout/stderr; never raises.

    A non-zero exit yields a `CompletedProcess` as usual. A missing binary (or
    other `OSError`) is mapped to a synthetic exit code 127 with the error text
    on stderr, so callers can treat "command failed" and "command absent"
    uniformly instead of crashing on an unhandled `FileNotFoundError`.
    """

    try:
        return subprocess.run(list(cmd), capture_output=True, text=True, check=False)
    except OSError as exc:
        return subprocess.CompletedProcess(list(cmd), 127, "", str(exc))


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
