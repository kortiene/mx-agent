#!/usr/bin/env python3
"""Run the `/issue` Agent Development Workflow for one issue.

By default this drives the **phased** Python-orchestrated pipeline (see
`adw/_orchestrator.py`): Python runs discrete agent phases (classify → plan →
implement → tests → resolve → e2e? → review → patch → document?) and owns all
git/GitHub work itself, withholding `GH_TOKEN` from the coding agent.

`--one-shot` restores the legacy behavior: render the monolithic
`.pi/prompts/issue.md` template and hand the whole pipeline to a single agent
call (which then needs `GH_TOKEN` to push/merge — a less isolated mode).

`--print-prompt` renders the one-shot template only; `--dry-run` previews the
phase plan (or, with `--one-shot`, the exact runner command).
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import REPO_ROOT, AdwError, partition_on_double_dash, render_prompt_file
from adw import _orchestrator
from adw._exec import (
    assume_yes,
    confirm,
    detect_repo,
    issue_state,
    note,
    resolve_gh_bin,
    resolve_runner_bin,
    safe_subprocess_env,
    working_tree_dirty,
)
from adw._runner import RUNNERS, build_runner_command, run_runner, wrap_timeout  # re-exported

__all__ = ["main", "build_runner_command", "wrap_timeout", "run_runner", "default_template", "split_passthru"]


def default_template(runner: str) -> Path:
    """Resolve the default one-shot prompt template for a runner.

    The `claude` runner prefers `.claude/commands/issue.md` (its `$ARGUMENTS`
    dialect); everything else falls back to `.pi/prompts/issue.md`.
    """

    if runner == "claude":
        claude_template = REPO_ROOT / ".claude" / "commands" / "issue.md"
        if claude_template.is_file():
            return claude_template
    return REPO_ROOT / ".pi" / "prompts" / "issue.md"


def build_parser() -> argparse.ArgumentParser:
    """Build the `/issue` executor argument parser."""

    parser = argparse.ArgumentParser(
        prog="python adw/issue.py",
        description="Run the /issue delivery workflow (phased by default; --one-shot for the legacy single call).",
        epilog="Everything after `--` is passed verbatim to the runner (e.g. -- --permission-mode acceptEdits).",
    )
    parser.add_argument("tokens", nargs="*", help="<issue-number> [notes...]")
    parser.add_argument(
        "--runner",
        default=os.environ.get("MX_AGENT_RUNNER", "pi"),
        help="agent runner: pi (default) or claude. Env: MX_AGENT_RUNNER",
    )
    # Execution mode.
    parser.add_argument("--one-shot", action="store_true", help="legacy: one monolithic issue.md agent call")
    parser.add_argument("--phases", help="phased mode: comma-separated phase subset/order (default: full chain)")
    parser.add_argument("--adw-id", dest="adw_id", default="", help="reuse/resume a run by its 8-char id")
    parser.add_argument("--resume", action="store_true", help="resume from saved state (requires --adw-id)")
    parser.add_argument("--no-progress", dest="no_progress", action="store_true", help="do not post [MX-ADW] issue comments")
    parser.add_argument("--inherit-env", dest="inherit_env", action="store_true", help="give the agent the full env (less isolated)")
    # Loop bounds / gates (phased).
    parser.add_argument("--max-resolve", dest="max_resolve", type=int, default=3, help="max self-heal test attempts")
    parser.add_argument("--max-patch", dest="max_patch", type=int, default=2, help="max review-blocker patch attempts")
    parser.add_argument("--max-ci-fix", dest="max_ci_fix", type=int, default=3, help="max CI-fix attempts")
    parser.add_argument("--ci-poll-interval", dest="ci_poll_interval", type=int, default=30, help="seconds between CI polls")
    parser.add_argument("--ci-max-polls", dest="ci_max_polls", type=int, default=40, help="max CI status polls")
    parser.add_argument(
        "--test-cmd", dest="test_cmd", default=os.environ.get("MX_AGENT_TEST_CMD", ""), help="test gate command; fmt/clippy/build still run (default: cargo test --all)"
    )
    # One-shot / shared.
    parser.add_argument("--template", help="one-shot: prompt template to expand (default: per-runner issue.md)")
    parser.add_argument("--json", action="store_true", help="one-shot: stream runner events as JSON")
    # Deliberately NOT defaulted from PI_MODEL: an exported PI_MODEL must not
    # silently override phased per-phase model routing. `pi` still honours
    # PI_MODEL via the forwarded env; pass --model to override routing explicitly.
    parser.add_argument("--model", default="", help="runner --model (overrides per-phase routing)")
    parser.add_argument("--thinking", default=os.environ.get("PI_THINKING", ""), help="pi --thinking level (ignored by claude)")
    parser.add_argument("--repo", default=os.environ.get("REPO", ""), help="owner/repo for issue lookups")
    parser.add_argument("--base", default="main", help="base branch to fork from / merge into (default: main)")
    parser.add_argument(
        "--log-dir", default=os.environ.get("MX_AGENT_LOG_DIR", ""), help="one-shot: tee transcript to <dir>/issue-<n>-<ts>.log"
    )
    parser.add_argument("--timeout", type=int, default=0, help="abort a runner call after N seconds (0 = none)")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="skip the post-run CLOSED check")
    parser.add_argument("--force", action="store_true", help="run even if the issue is already CLOSED")
    parser.add_argument("--allow-dirty", action="store_true", help="skip the clean-working-tree precondition")
    parser.add_argument("-y", "--yes", action="store_true", help="do not prompt for confirmation")
    parser.add_argument("--print-prompt", action="store_true", help="render the one-shot template and print it; do not run")
    parser.add_argument("--dry-run", action="store_true", help="preview the plan/command; do not run")
    return parser


def split_passthru(argv: Sequence[str]) -> "tuple[list[str], list[str]]":
    """Split argv at the first `--` into our args and verbatim runner flags."""

    return partition_on_double_dash(argv)


def main(argv: "Sequence[str] | None" = None) -> int:
    """Render and (by default) run the `/issue` workflow for one issue."""

    raw = list(sys.argv[1:] if argv is None else argv)
    ours, passthru = split_passthru(raw)
    args = build_parser().parse_args(ours)

    try:
        return _dispatch(args, passthru)
    except AdwError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace, passthru: Sequence[str]) -> int:
    """Validate input, then render / run one-shot / run phased."""

    if args.runner not in RUNNERS:
        raise AdwError(f"unknown --runner: {args.runner} (want: pi or claude)")
    if not args.tokens:
        raise AdwError("missing issue number; usage: issue <number> [notes]")
    issue_str = args.tokens[0]
    if not issue_str.isdigit():
        raise AdwError(f"issue must be a number, got: {issue_str}")
    issue = int(issue_str)

    if args.print_prompt:
        template = Path(args.template) if args.template else default_template(args.runner)
        if not template.is_file():
            raise AdwError(f"prompt template not found: {template}")
        print(render_prompt_file(template, args.tokens))
        return 0

    if args.one_shot:
        return run_one_shot(args, passthru, issue)

    return _orchestrator.run(args, passthru, issue)


def run_one_shot(args: argparse.Namespace, passthru: Sequence[str], issue: int) -> int:
    """Legacy path: one monolithic issue.md agent call, verified against GitHub."""

    template = Path(args.template) if args.template else default_template(args.runner)
    if not template.is_file():
        raise AdwError(f"prompt template not found: {template}")

    # ARGS[0] is $1 (issue number); the remainder are notes for ${@:2}/$ARGUMENTS.
    prompt = render_prompt_file(template, args.tokens)

    if args.runner == "claude" and args.thinking:
        note(f"thinking level '{args.thinking}' is ignored by the claude runner")

    runner_bin = resolve_runner_bin(args.runner)
    cmd = build_runner_command(
        args.runner,
        runner_bin,
        json_mode=args.json,
        model=args.model,
        thinking=args.thinking,
        passthru=passthru,
        prompt=prompt,
    )
    run_cmd = wrap_timeout(cmd, args.timeout)

    if args.dry_run:
        print("[dry-run] " + " ".join(shlex.quote(part) for part in run_cmd))
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

    # Confirmation gate. Unattended (non-tty) runs MUST pass --yes / MX_AGENT_YES=1.
    if not assume_yes(args.yes):
        if sys.stdin.isatty():
            if not confirm(f">> About to autonomously implement and MERGE issue #{issue}. Continue? [y/N] "):
                raise AdwError("aborted")
        else:
            raise AdwError("refusing to implement and merge unattended without --yes / MX_AGENT_YES=1")

    # One-shot: the agent runs gh/git itself, so it needs GH_TOKEN (less isolated).
    env = None if args.inherit_env else safe_subprocess_env(allow_gh_token=True)

    note(f"running /issue {issue} (one-shot) via {args.runner} ({runner_bin})")
    run_rc = run_runner(run_cmd, args.log_dir, issue, env=env)

    if args.verify:
        state = issue_state(gh_bin, issue, repo)
        if state == "CLOSED":
            note(f"verified: issue #{issue} is CLOSED")
            return 0
        raise AdwError(f"issue #{issue} is still {state} after the run ({args.runner} exit {run_rc}); treating as failure")

    return run_rc


if __name__ == "__main__":
    raise SystemExit(main())
