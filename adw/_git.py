"""Python-owned git/GitHub operations for the phased ADW pipeline.

Under the phased model the coding agent never touches `git`/`gh`; Python performs
all branch/commit/push/PR/CI-watch/merge work here, with its own environment
(which may legitimately hold `GH_TOKEN`). The agent only *authors* the commit
message and PR body, which Python then executes.

Every mutating operation honours `dry_run` by printing the command instead of
running it. Stdlib only, Unix-only.
"""

from __future__ import annotations

from typing import Optional

from adw._exec import capture, gh_json, note

# Treat these PR-check conclusions/states as red.
_FAIL_CONCLUSIONS = {"FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"}
_FAIL_STATES = {"FAILURE", "ERROR"}
_PENDING_STATES = {"PENDING", "EXPECTED"}


def _emit(cmd: list[str], dry_run: bool) -> "Optional[tuple[bool, Optional[str]]]":
    """Print a command under dry-run and return a success result; else `None`."""

    if dry_run:
        print("[dry-run] " + " ".join(cmd))
        return True, None
    note(" ".join(cmd))
    return None


def current_branch() -> str:
    """Return the current git branch name (empty string if undeterminable)."""

    return capture(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()


def create_or_checkout_branch(branch: str, base: str, *, dry_run: bool = False) -> "tuple[bool, Optional[str]]":
    """Fetch origin and switch to `branch`, creating it from `origin/<base>`."""

    if dry_run:
        print("[dry-run] git fetch origin --quiet")
        print(f"[dry-run] git switch -c {branch} origin/{base}")
        return True, None

    capture(["git", "fetch", "origin", "--quiet"])  # best effort; offline is tolerable
    exists_locally = capture(["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"]).returncode == 0
    cmd = ["git", "switch", branch] if exists_locally else ["git", "switch", "-c", branch, f"origin/{base}"]

    note(" ".join(cmd))
    result = capture(cmd)
    if result.returncode != 0:
        return False, result.stderr.strip() or "git switch failed"
    return True, None


def commit_all(message: str, *, dry_run: bool = False) -> "tuple[bool, Optional[str]]":
    """Stage all changes and commit `message`; a clean tree is a no-op success."""

    if not dry_run and not capture(["git", "status", "--porcelain"]).stdout.strip():
        return True, None  # nothing to commit

    add = ["git", "add", "-A"]
    commit = ["git", "commit", "-m", message]
    for cmd in (add, commit):
        emitted = _emit(cmd, dry_run)
        if emitted is not None:
            continue
        result = capture(cmd)
        if result.returncode != 0:
            return False, result.stderr.strip() or "git commit failed"
    return True, None


def push(branch: str, *, dry_run: bool = False) -> "tuple[bool, Optional[str]]":
    """Push `branch` to origin, setting upstream."""

    cmd = ["git", "push", "-u", "origin", branch]
    emitted = _emit(cmd, dry_run)
    if emitted is not None:
        return emitted
    result = capture(cmd)
    if result.returncode != 0:
        return False, result.stderr.strip() or "git push failed"
    return True, None


def pull_rebase(base: str, *, dry_run: bool = False) -> "tuple[bool, Optional[str]]":
    """Switch back to `base` and rebase-pull it."""

    for cmd in (["git", "switch", base], ["git", "pull", "--rebase", "origin", base]):
        emitted = _emit(cmd, dry_run)
        if emitted is not None:
            continue
        result = capture(cmd)
        if result.returncode != 0:
            return False, result.stderr.strip() or "git pull --rebase failed"
    return True, None


def pr_for_branch(branch: str, gh_bin: str, repo: str) -> Optional[str]:
    """Return the URL of an existing PR for `branch`, or `None`."""

    args = [gh_bin, "pr", "list", "--head", branch, "--json", "url", "--state", "open"]
    if repo:
        args += ["--repo", repo]
    prs = gh_json(args)
    if isinstance(prs, list) and prs:
        return prs[0].get("url")
    return None


def create_pr(
    branch: str,
    title: str,
    body: str,
    base: str,
    gh_bin: str,
    repo: str,
    *,
    dry_run: bool = False,
) -> "tuple[Optional[int], Optional[str], Optional[str]]":
    """Open a PR for `branch`; return (number, url, error)."""

    args = [gh_bin, "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body]
    if repo:
        args += ["--repo", repo]
    if dry_run:
        print("[dry-run] " + " ".join(args))
        return None, None, None
    note(" ".join(args[:6]) + " …")
    result = capture(args)
    if result.returncode != 0:
        return None, None, result.stderr.strip() or "gh pr create failed"
    url = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    number = pr_number_from_url(url)
    return number, url or None, None


def ci_status(pr: "int | str", gh_bin: str, repo: str) -> dict:
    """Return `{state, failing_jobs}` for a PR's checks.

    `state` is one of ``success``/``failure``/``pending``/``none``/``unknown``:
    ``none`` means the query succeeded but the PR has no checks (yet),
    distinct from ``unknown`` (the `gh` query itself failed / was unparseable).
    Callers settle on ``none`` before concluding there is nothing to gate on.
    ``failing_jobs`` is a list of ``{name, log_excerpt}`` (excerpt left empty —
    fetching per-job logs is out of scope and would risk leaking secrets).
    """

    args = [gh_bin, "pr", "view", str(pr), "--json", "statusCheckRollup"]
    if repo:
        args += ["--repo", repo]
    data = gh_json(args)
    if not isinstance(data, dict):
        return {"state": "unknown", "failing_jobs": []}

    rollup = data.get("statusCheckRollup") or []
    if not rollup:
        return {"state": "none", "failing_jobs": []}

    failing: list[dict] = []
    pending = False
    for check in rollup:
        name = check.get("name") or check.get("context") or "check"
        status = (check.get("status") or "").upper()  # CheckRun: QUEUED/IN_PROGRESS/COMPLETED
        conclusion = (check.get("conclusion") or "").upper()  # CheckRun
        state = (check.get("state") or "").upper()  # StatusContext
        if conclusion in _FAIL_CONCLUSIONS or state in _FAIL_STATES:
            failing.append({"name": name, "log_excerpt": ""})
        elif (status and status != "COMPLETED") or state in _PENDING_STATES:
            pending = True

    if failing:
        return {"state": "failure", "failing_jobs": failing}
    if pending:
        return {"state": "pending", "failing_jobs": []}
    return {"state": "success", "failing_jobs": []}


def squash_merge(pr: "int | str", gh_bin: str, repo: str, *, dry_run: bool = False) -> "tuple[bool, Optional[str]]":
    """Squash-merge `pr` and delete its branch."""

    args = [gh_bin, "pr", "merge", str(pr), "--squash", "--delete-branch"]
    if repo:
        args += ["--repo", repo]
    emitted = _emit(args, dry_run)
    if emitted is not None:
        return emitted
    result = capture(args)
    if result.returncode != 0:
        return False, result.stderr.strip() or "gh pr merge failed"
    return True, None


def pr_number_from_url(url: str) -> Optional[int]:
    """Extract the trailing PR number from a GitHub PR URL."""

    if not url:
        return None
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None
