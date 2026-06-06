#!/usr/bin/env python3
"""Start (or inspect) work on a GitHub issue by number.

Given an issue number, this:
  1. Fetches the issue (title, body, labels, milestone, state).
  2. Derives a branch name from the issue type label and title.
  3. Creates/checks out that branch from an up-to-date base branch.
  4. Assigns the issue to the current user.
  5. Moves the issue's project board card to "In Progress" (best effort).
  6. Prints the scope and acceptance criteria for implementation.

The `/issue` workflow runs `python adw/work_issue.py <n> --print` for context and
then `python adw/work_issue.py <n>` to set up the branch. Requires `gh`
(authenticated, with `project` scope for board updates) and `git`.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import AdwError
from adw._exec import capture, detect_repo, die, gh_json, note, resolve_gh_bin, run, working_tree_dirty

PROJECT_NUMBER = os.environ.get("PROJECT_NUMBER", "1")

# Issue type label -> branch prefix. Unlisted labels keep the "feat" default.
TYPE_PREFIX = {"type:bug": "fix", "type:docs": "docs", "type:ci": "ci", "type:testing": "test"}


def branch_prefix(labels: Sequence[str]) -> str:
    """Pick a branch prefix from issue type labels (last match wins)."""

    prefix = "feat"
    for label in labels:
        prefix = TYPE_PREFIX.get(label, prefix)
    return prefix


def slugify_title(title: str) -> str:
    """Slugify an issue title for use in a branch name.

    Strips a leading `Phase issue N:` prefix, lowercases, collapses runs of
    non-alphanumerics to single hyphens, trims hyphens, and caps at 40 chars.
    """

    src = re.sub(r"^Phase issue [0-9]+: *", "", title)
    slug = re.sub(r"[^a-z0-9]+", "-", src.lower()).strip("-")
    return slug[:40].rstrip("-")


def extract_scope(body: str) -> str:
    """Extract the `## Backlog Entry` section's body, collapsing blank runs."""

    lines = body.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("## Backlog Entry")), None)
    if start is None:
        return ""
    out: list[str] = []
    prev_blank = False
    for line in lines[start + 1 :]:  # drop the heading line itself
        blank = not line.strip()
        if blank and prev_blank:
            continue
        out.append(line)
        prev_blank = blank
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def set_status(gh_bin: str, owner: str, issue: int, target_status: str) -> None:
    """Best-effort move of the issue's project board card to `target_status`."""

    proj = gh_json([gh_bin, "project", "view", PROJECT_NUMBER, "--owner", owner, "--format", "json"])
    proj_id = (proj or {}).get("id")
    if not proj_id:
        note("project board not found; skipping status")
        return

    items = gh_json(
        [gh_bin, "project", "item-list", PROJECT_NUMBER, "--owner", owner, "--format", "json", "--limit", "300"]
    )
    item_id = next(
        (
            it["id"]
            for it in (items or {}).get("items", [])
            if (it.get("content") or {}).get("number") == issue
        ),
        None,
    )
    if not item_id:
        note("issue not on board; skipping status")
        return

    fields = gh_json([gh_bin, "project", "field-list", PROJECT_NUMBER, "--owner", owner, "--format", "json"])
    status_field = next((f for f in (fields or {}).get("fields", []) if f.get("name") == "Status"), None)
    option_id = next(
        (o["id"] for o in (status_field or {}).get("options", []) if o.get("name") == target_status),
        None,
    )
    if not status_field or not option_id:
        note(f"status option '{target_status}' not found; skipping")
        return

    rc = run(
        [gh_bin, "project", "item-edit", "--id", item_id, "--project-id", proj_id,
         "--field-id", status_field["id"], "--single-select-option-id", option_id]
    )
    if rc == 0:
        note(f"set board status of #{issue} -> {target_status}")
    else:
        note("could not update board status")


def _action(cmd: Sequence[str], dry_run: bool, *, check: bool = True) -> None:
    """Run a mutating command, or print it under `--dry-run`."""

    if dry_run:
        print("[dry-run] " + " ".join(cmd))
        return
    note(" ".join(cmd))
    rc = run(cmd)
    if check and rc != 0:
        die(f"command failed ({rc}): {' '.join(cmd)}")


def build_parser() -> argparse.ArgumentParser:
    """Build the `work_issue` argument parser."""

    parser = argparse.ArgumentParser(
        prog="python adw/work_issue.py",
        description="Start (or inspect) work on a GitHub issue: branch, assign, board status.",
    )
    parser.add_argument("issue", nargs="?", help="issue number")
    parser.add_argument("--dry-run", action="store_true", help="show what would happen; make no changes")
    parser.add_argument("--print", dest="print_only", action="store_true", help="only print issue context")
    parser.add_argument("--base", default="main", help="base branch to fork from (default: main)")
    parser.add_argument("--no-branch", dest="do_branch", action="store_false", help="do not create/switch a branch")
    parser.add_argument("--no-assign", dest="do_assign", action="store_false", help="do not assign the issue")
    parser.add_argument("--no-status", dest="do_status", action="store_false", help="do not update board status")
    parser.add_argument("--status", default="In Progress", help='Status option to set (default: "In Progress")')
    return parser


def main(argv: "Sequence[str] | None" = None) -> int:
    """Inspect and (unless --print/--dry-run) start work on one issue."""

    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        return _run(args)
    except AdwError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    """Execute the parsed workflow; raises `AdwError` on user-facing failures."""

    if not args.issue:
        raise AdwError("missing issue number; usage: work_issue <number> [options]")
    if not args.issue.isdigit():
        raise AdwError(f"issue must be a number, got: {args.issue}")
    issue = int(args.issue)
    dry_run = args.dry_run or args.print_only

    gh_bin = resolve_gh_bin()
    if not gh_bin:
        raise AdwError("gh CLI not found")
    if not shutil.which("git"):
        raise AdwError("git not found")

    repo = os.environ.get("REPO") or detect_repo(gh_bin)
    if not repo:
        raise AdwError("could not determine repository (is gh authenticated?)")
    owner = os.environ.get("OWNER") or repo.split("/", 1)[0]

    data = gh_json(
        [gh_bin, "issue", "view", str(issue), "--repo", repo,
         "--json", "number,title,body,labels,milestone,state,url,assignees"]
    )
    if not data:
        raise AdwError(f"issue #{issue} not found in {repo} (is gh authenticated?)")

    title = data.get("title", "")
    state = data.get("state", "")
    url = data.get("url", "")
    milestone = (data.get("milestone") or {}).get("title") or "none"
    labels = [label["name"] for label in data.get("labels", [])]
    branch = f"{branch_prefix(labels)}/{issue}-{slugify_title(title)}"

    print()
    print(f"================ issue #{issue} ================")
    print(f"Title:     {title}")
    print(f"State:     {state}")
    print(f"Milestone: {milestone}")
    print(f"Labels:    {' '.join(labels)}")
    print(f"URL:       {url}")
    print(f"Branch:    {branch}")
    print(f"Base:      {args.base}")
    print("===============================================")
    print()
    print("----- scope & acceptance criteria -----")
    print(extract_scope(data.get("body", "")))
    print("---------------------------------------")
    print()

    if state == "CLOSED":
        print(f"warning: issue #{issue} is CLOSED.", file=sys.stderr)

    if args.print_only:
        return 0

    if args.do_branch:
        if not dry_run and working_tree_dirty():
            raise AdwError("working tree is dirty; commit or stash before starting an issue")
        _action(["git", "fetch", "origin", "--quiet"], dry_run)
        if capture(["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"]).returncode == 0:
            _action(["git", "switch", branch], dry_run)
        else:
            _action(["git", "switch", "-c", branch, f"origin/{args.base}"], dry_run)

    if args.do_assign:
        _action([gh_bin, "issue", "edit", str(issue), "--repo", repo, "--add-assignee", "@me"], dry_run)

    if args.do_status:
        if dry_run:
            print(f"[dry-run] set board status of #{issue} -> {args.status}")
        else:
            set_status(gh_bin, owner, issue, args.status)

    print()
    note(f"ready to implement #{issue} on branch '{branch}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
