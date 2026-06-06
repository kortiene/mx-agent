#!/usr/bin/env python3
"""Run the `/issues` Agent Development Workflow across several issues in order.

By default this executes the batch: each issue is delivered end to end via
`issue.py` (branch, code, test, PR, watch CI, merge), one fully completing before
the next begins — important because later backlog issues usually depend on
earlier ones being merged to `main`. Selectors support single IDs (`12`) and
inclusive ranges (`12-15`, `12..15`); they are expanded ascending and
de-duplicated.

Use `--print-prompt` to render the `/issues` agent prompt instead of executing
(notes after `--` become shared context); use `--dry-run` to preview the per-
issue plan without running anything. Only one batch runs at a time, guarded by a
lock file.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import signal
import sys
import time
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import AdwError, expand_issue_selectors, print_rendered, split_notes
from adw._exec import assume_yes, confirm, note
from adw import issue as issue_mod


def build_parser() -> argparse.ArgumentParser:
    """Build the `/issues` argument parser."""

    parser = argparse.ArgumentParser(
        prog="python adw/issues.py",
        description="Deliver several issues in order, or (--print-prompt) render the /issues workflow.",
        epilog="Everything after `--` is forwarded to the runner (or, with --print-prompt, used as shared notes).",
    )
    parser.add_argument("specs", nargs="*", help="issue selectors: single IDs (12) and ranges (12-15, 12..15)")
    parser.add_argument("--runner", help="forward --runner to issue.py (pi|claude)")
    parser.add_argument("--model", help="forward --model to issue.py")
    parser.add_argument("--thinking", help="forward --thinking to issue.py")
    parser.add_argument("--log-dir", help="forward --log-dir to issue.py so each run is captured")
    parser.add_argument("--start", type=int, default=0, help="resume at the first occurrence of this issue")
    parser.add_argument("--delay", type=int, default=0, help="sleep this many seconds between issues")
    parser.add_argument("--keep-going", action="store_true", help="continue to the next issue even if one fails")
    parser.add_argument("-y", "--yes", action="store_true", help="confirm once for the whole batch")
    parser.add_argument("--dry-run", action="store_true", help="print the per-issue plan; do not run")
    parser.add_argument("--print-prompt", action="store_true", help="render the /issues prompt instead of executing")
    return parser


def render_args(argv: list[str]) -> list[str]:
    """Normalize issue selectors and notes into prompt arguments."""

    selectors, notes = split_notes(argv)
    if not selectors:
        raise AdwError("missing issue selector; provide one or more issue IDs/ranges")
    issue_ids = expand_issue_selectors(selectors)
    if not issue_ids:
        raise AdwError("no issue IDs selected")
    rendered = [str(issue_id) for issue_id in issue_ids]
    if notes:
        rendered.extend(["--", *notes])
    return rendered


def apply_start(issues: list[int], start: int) -> list[int]:
    """Drop everything before the first occurrence of `start`."""

    if start <= 0:
        return issues
    if start not in issues:
        raise AdwError(f"--start {start} is not in the issue list: {' '.join(map(str, issues))}")
    return issues[issues.index(start) :]


def issue_flags(args: argparse.Namespace, yes: bool) -> list[str]:
    """Assemble the flags forwarded to each issue.py run."""

    flags: list[str] = []
    if args.runner:
        flags += ["--runner", args.runner]
    if args.model:
        flags += ["--model", args.model]
    if args.thinking:
        flags += ["--thinking", args.thinking]
    if args.log_dir:
        flags += ["--log-dir", args.log_dir]
    if yes:
        flags += ["--yes"]
    return flags


def _summary(done: list[int], failed: list[int]) -> None:
    note(f"summary: {len(done)} completed, {len(failed)} failed")
    if done:
        note(f"  completed: {' '.join(map(str, done))}")
    if failed:
        note(f"  failed:    {' '.join(map(str, failed))}")


def _acquire_lock() -> "object | None":
    """Take an exclusive, non-blocking batch lock; raise if one is held."""

    lock_path = Path(os.environ.get("TMPDIR", "/tmp")) / "mx-agent-issues.lock"
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise AdwError(f"another issues batch holds {lock_path}; wait for it or remove the lock")
    return handle


def run_batch(args: argparse.Namespace, issues: list[int], tail: Sequence[str]) -> int:
    """Deliver each issue in order via issue.py; return 1 if any failed."""

    yes = assume_yes(args.yes)
    if not args.dry_run and not yes and sys.stdin.isatty():
        prompt = (
            f">> About to autonomously implement and MERGE {len(issues)} issue(s): "
            f"{' '.join(map(str, issues))}. Continue? [y/N] "
        )
        if not confirm(prompt):
            raise AdwError("aborted")
        yes = True

    lock = None if args.dry_run else _acquire_lock()
    flags = issue_flags(args, yes)
    note(f"processing {len(issues)} issue(s) in order: {' '.join(map(str, issues))}")

    done: list[int] = []
    failed: list[int] = []
    total = len(issues)
    try:
        for index, number in enumerate(issues, start=1):
            print(file=sys.stderr)
            note(f"[{index}/{total}] === issue #{number} ===")
            # Re-insert `--` so issue.py forwards the tail to the runner rather
            # than parsing it as its own flags.
            argv = [str(number), *flags] + (["--", *tail] if tail else [])

            if args.dry_run:
                print("[dry-run] python adw/issue.py " + " ".join(argv))
                done.append(number)
                continue

            if issue_mod.main(argv) == 0:
                note(f"[{index}/{total}] issue #{number} finished")
                done.append(number)
            else:
                note(f"[{index}/{total}] issue #{number} FAILED")
                failed.append(number)
                if not args.keep_going:
                    note("stopping (use --keep-going to continue past failures)")
                    break

            if args.delay > 0 and index < total:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        note("interrupted")
        _summary(done, failed)
        return 130
    finally:
        if lock is not None:
            lock.close()

    print(file=sys.stderr)
    _summary(done, failed)
    return 1 if failed else 0


def _split_tail(argv: Sequence[str]) -> "tuple[list[str], list[str]]":
    """Split argv at the first `--` into our args and the forwarded tail."""

    argv = list(argv)
    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1 :]
    return argv, []


def main(argv: "Sequence[str] | None" = None) -> int:
    """Execute the batch, or render the `/issues` prompt with `--print-prompt`."""

    raw = list(sys.argv[1:] if argv is None else argv)
    if "-h" in raw or "--help" in raw:
        build_parser().parse_args(["--help"])
        return 0

    head, tail = _split_tail(raw)
    args = build_parser().parse_args(head)

    # Reuse the batch summary on SIGTERM by funneling it through KeyboardInterrupt.
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    try:
        if args.print_prompt:
            render_input = [*args.specs] + (["--", *tail] if tail else [])
            return print_rendered("issues", render_args(render_input))

        if not args.specs:
            raise AdwError("missing issue selector; provide one or more issue IDs/ranges")
        issues = apply_start(expand_issue_selectors(args.specs), args.start)
        if not issues:
            raise AdwError("no issues to process after expansion/filtering")
        return run_batch(args, issues, tail)
    except AdwError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _raise_keyboard_interrupt(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    raise SystemExit(main())
