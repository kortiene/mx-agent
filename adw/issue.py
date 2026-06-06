#!/usr/bin/env python3
"""Run the `/issue` Agent Development Workflow end to end.

This is the executable counterpart to the `/issue` slash command. It expands the
same prompt template (substituting the issue number and notes) and drives a
coding-agent runner (`pi` or `claude`) in print mode so the agent implements the
issue end to end: branch, code, test, open a PR, watch CI, merge.

Because a runner's print-mode exit code only reflects whether the model
responded — not whether the issue actually shipped — the run is verified against
GitHub afterward: it counts as success only when the issue ends up CLOSED.
Already-closed issues are skipped, and unknown issue numbers fail fast before
spending tokens.

Use `--print-prompt` for the old render-only behavior, or `--dry-run` to print
the exact runner command without executing it. `adw/issues.py` drives this module
to process several issues in order.
"""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import AdwError, render_prompt_file
from adw._exec import (
    assume_yes,
    confirm,
    detect_repo,
    issue_state,
    note,
    resolve_gh_bin,
    resolve_runner_bin,
    working_tree_dirty,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNERS = ("pi", "claude")


def default_template(runner: str) -> Path:
    """Resolve the default prompt template for a runner.

    The `claude` runner prefers `.claude/commands/issue.md` when present (its
    `$ARGUMENTS` dialect); everything else falls back to `.pi/prompts/issue.md`.
    Paths are anchored at the repo root so the result is independent of CWD.
    """

    if runner == "claude":
        claude_template = REPO_ROOT / ".claude" / "commands" / "issue.md"
        if claude_template.is_file():
            return claude_template
    return REPO_ROOT / ".pi" / "prompts" / "issue.md"


def build_runner_command(
    runner: str,
    runner_bin: str,
    *,
    json_mode: bool,
    model: str,
    thinking: str,
    session_name: str,
    passthru: Sequence[str],
    prompt: str,
) -> list[str]:
    """Map the neutral options onto the runner's print-mode invocation."""

    cmd = [runner_bin, "-p"]
    if runner == "pi":
        if json_mode:
            cmd += ["--mode", "json"]
        cmd += ["--name", session_name]
        if model:
            cmd += ["--model", model]
        if thinking:
            cmd += ["--thinking", thinking]
    else:  # claude
        if json_mode:
            cmd += ["--output-format", "stream-json", "--verbose"]
        if model:
            cmd += ["--model", model]
    cmd += list(passthru)
    cmd.append(prompt)
    return cmd


def wrap_timeout(cmd: Sequence[str], timeout: int) -> list[str]:
    """Prefix a command with `timeout --signal=INT N` when requested/available."""

    if timeout > 0:
        if shutil.which("timeout"):
            return ["timeout", "--signal=INT", str(timeout), *cmd]
        note("--timeout requested but 'timeout' not found; running without it")
    return list(cmd)


def run_runner(cmd: Sequence[str], log_dir: str, issue: int) -> int:
    """Run the runner, optionally teeing combined output to a per-issue log."""

    if not log_dir:
        return subprocess.run(list(cmd), check=False).returncode

    os.makedirs(log_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    log_file = Path(log_dir) / f"issue-{issue}-{stamp}.log"
    note(f"logging transcript to {log_file}")
    with open(log_file, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen(
            list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            handle.write(line)
        return proc.wait()


def build_parser() -> argparse.ArgumentParser:
    """Build the `/issue` executor argument parser."""

    parser = argparse.ArgumentParser(
        prog="python adw/issue.py",
        description="Run the /issue delivery workflow end to end via a coding-agent runner.",
        epilog=(
            "Everything after `--` is passed verbatim to the runner (e.g. "
            "-- --permission-mode acceptEdits)."
        ),
    )
    parser.add_argument("tokens", nargs="*", help="<issue-number> [notes...]")
    parser.add_argument(
        "--runner",
        default=os.environ.get("MX_AGENT_RUNNER", "pi"),
        help="agent runner: pi (default) or claude. Env: MX_AGENT_RUNNER",
    )
    parser.add_argument("--template", help="prompt template to expand (default: per-runner issue.md)")
    parser.add_argument("--json", action="store_true", help="stream runner events as JSON")
    parser.add_argument("--model", default=os.environ.get("PI_MODEL", ""), help="runner --model pattern")
    parser.add_argument(
        "--thinking", default=os.environ.get("PI_THINKING", ""), help="pi --thinking level (ignored by claude)"
    )
    parser.add_argument("--name", default="", help="session display name (pi only)")
    parser.add_argument("--repo", default=os.environ.get("REPO", ""), help="owner/repo for issue lookups")
    parser.add_argument(
        "--log-dir", default=os.environ.get("MX_AGENT_LOG_DIR", ""), help="tee transcript to <dir>/issue-<n>-<ts>.log"
    )
    parser.add_argument("--timeout", type=int, default=0, help="abort the run after N seconds (0 = none)")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="skip the post-run CLOSED check")
    parser.add_argument("--force", action="store_true", help="run even if the issue is already CLOSED")
    parser.add_argument("--allow-dirty", action="store_true", help="skip the clean-working-tree precondition")
    parser.add_argument("-y", "--yes", action="store_true", help="do not prompt for confirmation")
    parser.add_argument("--print-prompt", action="store_true", help="expand the template and print it; do not run")
    parser.add_argument("--dry-run", action="store_true", help="print the exact runner command; do not run it")
    return parser


def split_passthru(argv: Sequence[str]) -> "tuple[list[str], list[str]]":
    """Split argv at the first `--` into our args and verbatim runner flags."""

    argv = list(argv)
    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1 :]
    return argv, []


def main(argv: "Sequence[str] | None" = None) -> int:
    """Render and (by default) run the `/issue` workflow for one issue."""

    raw = list(sys.argv[1:] if argv is None else argv)
    ours, passthru = split_passthru(raw)
    args = build_parser().parse_args(ours)

    try:
        return _run(args, passthru)
    except AdwError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace, passthru: Sequence[str]) -> int:
    """Execute the parsed workflow; raises `AdwError` on user-facing failures."""

    if args.runner not in RUNNERS:
        raise AdwError(f"unknown --runner: {args.runner} (want: pi or claude)")
    if not args.tokens:
        raise AdwError("missing issue number; usage: issue <number> [notes]")

    issue_str = args.tokens[0]
    if not issue_str.isdigit():
        raise AdwError(f"issue must be a number, got: {issue_str}")
    issue = int(issue_str)

    template = Path(args.template) if args.template else default_template(args.runner)
    if not template.is_file():
        raise AdwError(f"prompt template not found: {template}")

    # ARGS[0] is $1 (issue number); the remainder are notes for ${@:2}/$ARGUMENTS.
    prompt = render_prompt_file(template, args.tokens)

    if args.print_prompt:
        print(prompt)
        return 0

    if args.runner == "claude" and args.thinking:
        note(f"thinking level '{args.thinking}' is ignored by the claude runner")

    runner_bin = resolve_runner_bin(args.runner)
    session_name = args.name or f"issue #{issue}"
    cmd = build_runner_command(
        args.runner,
        runner_bin,
        json_mode=args.json,
        model=args.model,
        thinking=args.thinking,
        session_name=session_name,
        passthru=passthru,
        prompt=prompt,
    )
    run_cmd = wrap_timeout(cmd, args.timeout)

    if args.dry_run:
        print("[dry-run] " + " ".join(_quote(part) for part in run_cmd))
        return 0

    gh_bin = resolve_gh_bin()
    repo = args.repo or detect_repo(gh_bin)

    # Preflight: skip already-closed issues and fail fast on unknown numbers.
    if args.verify or not args.force:
        if not gh_bin:
            if args.verify:
                raise AdwError("gh not found but verification is on; install gh, set GH_BIN, or pass --no-verify")
        else:
            state = issue_state(gh_bin, issue, repo)
            if state == "CLOSED" and not args.force:
                note(f"issue #{issue} is already CLOSED; skipping (use --force to run anyway)")
                return 0
            if state == "UNKNOWN":
                raise AdwError(f"issue #{issue} not found in {repo or 'the current repo'} (is gh authenticated?)")

    if not args.allow_dirty and working_tree_dirty():
        raise AdwError("working tree is dirty; commit/stash first or pass --allow-dirty")

    if not assume_yes(args.yes) and sys.stdin.isatty():
        if not confirm(f">> About to autonomously implement and MERGE issue #{issue}. Continue? [y/N] "):
            raise AdwError("aborted")

    note(f"running /issue {issue} headlessly via {args.runner} ({runner_bin})")
    run_rc = run_runner(run_cmd, args.log_dir, issue)

    if args.verify:
        state = issue_state(gh_bin, issue, repo)
        if state == "CLOSED":
            note(f"verified: issue #{issue} is CLOSED")
            return 0
        raise AdwError(f"issue #{issue} is still {state} after the run ({args.runner} exit {run_rc}); treating as failure")

    return run_rc


def _quote(part: str) -> str:
    """Shell-quote a command part for readable --dry-run output."""

    import shlex

    return shlex.quote(part)


if __name__ == "__main__":
    raise SystemExit(main())
