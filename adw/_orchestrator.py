"""Phased ADW delivery driver.

Python owns the control flow: it runs a sequence of discrete, single-purpose
agent phases (each one runner invocation), threads `AdwState` between them, and
performs all git/GitHub mechanics itself — the coding agent never sees `GH_TOKEN`
in this mode. Setup, finalize, CI-watch, and the squash-merge gate live in Python;
the agent authors only the commit message and PR body.

Stdlib only, Unix-only.
"""

from __future__ import annotations

import argparse
import shlex
import sys
import time
from typing import Optional, Sequence

from adw import _git, _phases, work_issue
from adw.common import AdwError
from adw._exec import (
    assume_yes,
    capture,
    confirm,
    detect_repo,
    issue_state,
    note,
    post_progress,
    resolve_gh_bin,
    resolve_runner_bin,
    safe_subprocess_env,
    working_tree_dirty,
)
from adw._runner import RUNNERS
from adw._state import AdwState, make_adw_id

MAX_OUTPUT_CHARS = 8000  # cap failure text fed into prompts/comments

# How many times to re-poll an empty check rollup before concluding the PR
# genuinely has no checks (vs. checks merely not registered yet right after
# `gh pr create`). With the default 30s poll interval this is a ~90s settle.
_NO_CHECKS_SETTLE_POLLS = 3

# Default test gate. `--test-cmd` overrides only this (the test step); the other
# pre-merge gates below always run. Centralised so the resolve loop, the
# pre-merge gates, and the dry-run preview never drift apart.
DEFAULT_TEST_CMD = "cargo test --all"

# Pre-merge verification gates run by Python (the first is overridden by --test-cmd).
DEFAULT_FINALIZE_GATES = (
    DEFAULT_TEST_CMD,
    "cargo fmt --check",
    "cargo clippy --all-targets --all-features -- -D warnings",
    "cargo build --all",
)


# --- small seams (patched in tests) ------------------------------------------


def run_cmd(cmd: Sequence[str]) -> "tuple[int, str]":
    """Run a local gate command with the inherited env; return (rc, combined text).

    Gate commands are build tools (e.g. `cargo test`), not the coding agent, so
    they legitimately use the normal environment.
    """

    result = capture(list(cmd))
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# --- helpers (unit-testable) -------------------------------------------------


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Tail-truncate noisy output for inclusion in a prompt or comment."""

    text = text or ""
    if len(text) <= limit:
        return text
    return "…(truncated)…\n" + text[-limit:]


def confirm_merge(*, yes: bool, isatty: bool) -> None:
    """Gate the irreversible squash-merge; raise `AdwError` to abort.

    Fixes the prior non-tty bypass: when stdin is not a terminal and the run was
    not pre-authorized (`--yes`/`MX_AGENT_YES=1`), refuse rather than silently
    merge.
    """

    if yes:
        return
    if not isatty:
        raise AdwError("refusing to merge unattended without --yes / MX_AGENT_YES=1")
    if not confirm(">> About to squash-merge this PR to main. Continue? [y/N] "):
        raise AdwError("aborted")


def changed_files(base: str) -> list[str]:
    """Best-effort list of files changed vs `origin/<base>`."""

    result = capture(["git", "diff", f"origin/{base}", "--name-only"])
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def render_findings(findings: Sequence) -> str:
    """Render review findings into a prompt-friendly block."""

    lines = []
    for idx, f in enumerate(findings, start=1):
        loc = f" ({f.location})" if getattr(f, "location", "") else ""
        lines.append(f"{idx}. [{f.severity}]{loc} {f.description}")
    return "\n".join(lines)


# --- bounded loops -----------------------------------------------------------


def resolve_loop(
    state: AdwState,
    *,
    test_cmd: str,
    max_attempts: int,
    runner: str,
    runner_bin: str,
    cli_model: str,
    thinking: str,
    passthru: Sequence[str],
    env: "dict[str, str] | None",
    timeout: int,
    progress,
) -> bool:
    """Run the test gate, asking the agent to fix failures, until green.

    Returns True if the gate is green, False if it is still failing after the
    bound or the agent makes no progress.
    """

    gate = shlex.split(test_cmd)
    attempt = 0
    while True:
        rc, output = run_cmd(gate)
        if rc == 0:
            progress("resolve", "test gate is green")
            return True
        if attempt >= max_attempts:
            progress("resolve", f"test gate still failing after {max_attempts} attempt(s)")
            return False
        attempt += 1
        progress("resolve", f"test gate failed; resolve attempt {attempt}/{max_attempts}")
        data = _phases.run_agent_phase(
            "resolve",
            [truncate(output)],
            state=state,
            runner=runner,
            runner_bin=runner_bin,
            cli_model=cli_model,
            thinking=thinking,
            passthru=passthru,
            env=env,
            timeout=timeout,
        )
        result = _phases.to_result("resolve", data)
        if result.resolved == 0:
            progress("resolve", "agent resolved nothing; stopping")
            return False


def patch_loop(
    state: AdwState,
    findings: Sequence,
    *,
    max_attempts: int,
    runner: str,
    runner_bin: str,
    cli_model: str,
    thinking: str,
    passthru: Sequence[str],
    env: "dict[str, str] | None",
    timeout: int,
    progress,
) -> bool:
    """Patch blocker findings (only) until none remain. Returns True when clear."""

    blockers = [f for f in findings if getattr(f, "severity", "") == "blocker"]
    others = len(findings) - len(blockers)
    if others:
        progress("patch", f"{others} non-blocker finding(s) reported, not auto-fixed")
    if not blockers:
        progress("patch", "no blocker findings")
        return True

    remaining = len(blockers)
    blockers_text = render_findings(blockers)
    # On retries the count, not the list, shrinks; tell the agent the full list
    # may be partly fixed so it re-checks each instead of re-editing fixed ones.
    retry_note = (
        "Some of these may already be resolved by a previous attempt. Re-check each "
        "against the current working tree and only fix the ones that still apply.\n\n"
    )
    attempt = 0
    while remaining > 0 and attempt < max_attempts:
        attempt += 1
        progress("patch", f"resolving {remaining} blocker(s); attempt {attempt}/{max_attempts}")
        prompt_text = blockers_text if attempt == 1 else retry_note + blockers_text
        data = _phases.run_agent_phase(
            "patch",
            [prompt_text],
            state=state,
            runner=runner,
            runner_bin=runner_bin,
            cli_model=cli_model,
            thinking=thinking,
            passthru=passthru,
            env=env,
            timeout=timeout,
        )
        result = _phases.to_result("patch", data)
        if result.resolved == 0 or result.remaining >= remaining:
            remaining = result.remaining
            break
        remaining = result.remaining
    return remaining == 0


def ci_fix_loop(
    state: AdwState,
    pr: "int | str",
    *,
    gh_bin: str,
    repo: str,
    max_attempts: int,
    runner: str,
    runner_bin: str,
    cli_model: str,
    thinking: str,
    passthru: Sequence[str],
    env: "dict[str, str] | None",
    timeout: int,
    poll_interval: int,
    max_polls: int,
    progress,
) -> bool:
    """Watch CI and ask the agent to fix red checks until green. Returns success."""

    attempt = 0
    polls = 0
    none_polls = 0  # tolerate a short window where no checks have registered yet
    while True:
        status = _git.ci_status(pr, gh_bin, repo)
        state_str = status.get("state")
        if state_str == "success":
            progress("ci-fix", "CI is green")
            return True
        if state_str == "none":
            # Query succeeded but the PR has no checks. Right after `gh pr create`
            # they may not be registered yet, so settle briefly before concluding
            # there is genuinely nothing to gate on (treated as green).
            none_polls += 1
            if none_polls > _NO_CHECKS_SETTLE_POLLS:
                progress("ci-fix", "no CI checks registered; treating as green")
                return True
            if poll_interval > 0:
                time.sleep(poll_interval)
            continue
        if state_str == "unknown":
            progress("ci-fix", "could not determine CI status")
            return False
        if state_str == "pending":
            polls += 1
            if polls > max_polls:
                progress("ci-fix", "CI still pending after polling budget")
                return False
            if poll_interval > 0:
                time.sleep(poll_interval)
            continue
        # failure
        if attempt >= max_attempts:
            progress("ci-fix", f"CI still red after {max_attempts} fix attempt(s)")
            return False
        attempt += 1
        names = ", ".join(j["name"] for j in status.get("failing_jobs", [])) or "unknown jobs"
        progress("ci-fix", f"CI red ({names}); fix attempt {attempt}/{max_attempts}")
        data = _phases.run_agent_phase(
            "resolve",
            [f"CI is failing for these checks: {names}. Fix the cause."],
            state=state,
            runner=runner,
            runner_bin=runner_bin,
            cli_model=cli_model,
            thinking=thinking,
            passthru=passthru,
            env=env,
            timeout=timeout,
        )
        result = _phases.to_result("resolve", data)
        if result.resolved == 0:
            progress("ci-fix", "agent resolved nothing; stopping")
            return False
        # An agent claiming a fix that left no committable change can't move CI;
        # stop instead of re-pushing the same tree and burning the poll budget.
        if not working_tree_dirty():
            progress("ci-fix", "agent reported a fix but changed nothing; stopping")
            return False
        ok, _err = _git.commit_all(f"fix: address CI failures ({names})")
        if ok:
            _git.push(state.branch_name)
            polls = 0  # a new commit kicks off a fresh CI run; reset the budget


# --- phase argument assembly -------------------------------------------------


def _issue_blob(issue: int, ctx: dict) -> str:
    title = ctx.get("title", "")
    body = ctx.get("body", "")
    labels = " ".join(ctx.get("labels", []))
    return f"GitHub issue #{issue}: {title}\nLabels: {labels}\n\n{body}".strip()


def _phase_args(phase: str, issue: int, state: AdwState, ctx: dict, review, files: Sequence[str]) -> list[str]:
    """Assemble template arguments, injecting context the token-less agent lacks."""

    blob = _issue_blob(issue, ctx)
    if phase == "classify":
        return [str(issue), blob]
    if phase == "plan":
        return [blob]
    if phase == "implement":
        return [state.plan_file or "(no spec; implement directly from the issue)", blob]
    if phase == "tests":
        return [f"Issue #{issue} on branch {state.branch_name}: add focused coverage for this change.\n\n{blob}"]
    if phase == "e2e":
        return [f"Issue #{issue} on branch {state.branch_name}: add e2e coverage if warranted.\n\n{blob}"]
    if phase == "review":
        # review_phase.md: $1 = spec file (may be empty), ${@:2} = issue/change context.
        return [state.plan_file or "", blob]
    if phase == "document":
        return [f"Change for issue #{issue}; files changed: {', '.join(files) or 'n/a'}.\n\n{blob}"]
    return [blob]


def _apply_result(state: AdwState, phase: str, result) -> None:
    """Fold a phase result back into run state."""

    if phase == "classify":
        state.issue_class = result.issue_class
    elif phase == "plan":
        if result.plan_file:
            state.plan_file = result.plan_file


def _absorb_authored_text(state: AdwState) -> None:
    """Read the agent-authored commit message / PR body artifacts into state.

    Free-form text is authored to workspace files (not inlined in JSON) by the
    `review` and `document` phases; `document` overwrites `review`, so the last
    authoring phase wins. Best effort — a missing/unreadable file is ignored.
    """

    for path, attr in ((_phases.commit_message_path(state), "commit_message"), (_phases.pr_body_path(state), "pr_body")):
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8").strip()
                if text:
                    setattr(state, attr, text)
        except OSError:
            pass


# --- setup / finalize --------------------------------------------------------


def _setup(state: AdwState, gh_bin: "str | None", repo: str, issue: int, ctx: dict, args, progress) -> None:
    """Python setup phase: branch from base, assign, move board to In Progress."""

    branch = work_issue.derive_branch(issue, ctx.get("title", ""), ctx.get("labels", []), state.adw_id)
    state.branch_name = branch
    ok, err = _git.create_or_checkout_branch(branch, args.base)
    if not ok:
        raise AdwError(f"failed to create/checkout branch {branch}: {err}")
    progress("setup", f"on branch {branch}")
    if gh_bin:
        edit = [gh_bin, "issue", "edit", str(issue), "--add-assignee", "@me"]
        if repo:
            edit += ["--repo", repo]
        capture(edit)
        owner = repo.split("/", 1)[0] if repo else ""
        if owner:
            try:
                work_issue.set_status(gh_bin, owner, issue, "In Progress")
            except Exception:  # noqa: BLE001 - board update is best effort
                note("could not update board status")


def finalize_gates(args) -> list[str]:
    """Pre-merge gate commands.

    `--test-cmd` overrides only the *test* gate (the first entry); fmt/clippy/
    build still run, so narrowing the tests never silently drops the other
    quality gates before the irreversible squash-merge.
    """

    gates = list(DEFAULT_FINALIZE_GATES)
    if args.test_cmd:
        gates[0] = args.test_cmd
    return gates


def _finalize_and_merge(
    state: AdwState,
    args,
    *,
    gh_bin: "str | None",
    repo: str,
    issue: int,
    runner: str,
    runner_bin: str,
    env,
    passthru,
    progress,
) -> int:
    """Run gates, commit, push, open PR, watch CI, gate-merge, verify, report."""

    # Resume guard: if this run already merged, the branch is gone and the PR is
    # closed — re-running finalize would fail on push or re-merge. Just re-verify.
    if state.is_done("merge"):
        progress("report", f"merge already completed for {state.adw_id}; nothing to finalize")
        if args.verify and gh_bin:
            st = issue_state(gh_bin, issue, repo)
            if st != "CLOSED":
                raise AdwError(f"issue #{issue} is {st} despite a recorded merge; treating as failure")
        return 0

    # Final verification gates (Python-owned). Merge only on green.
    for gate in finalize_gates(args):
        rc, _out = run_cmd(shlex.split(gate))
        if rc != 0:
            progress("finalize", f"gate failed: {gate}; not merging")
            raise AdwError(f"pre-merge gate failed: {gate}")
    progress("finalize", "all pre-merge gates green")

    commit_message = state.commit_message or f"feat: implement issue #{issue}\n\ncloses #{issue}"
    ok, err = _git.commit_all(commit_message)
    if not ok:
        raise AdwError(f"commit failed: {err}")
    ok, err = _git.push(state.branch_name)
    if not ok:
        raise AdwError(f"push failed: {err}")

    if not gh_bin:
        raise AdwError("gh not found; cannot open or merge a PR (install gh or set GH_BIN)")

    pr_url = _git.pr_for_branch(state.branch_name, gh_bin, repo)
    if pr_url:
        state.pr_url = pr_url
        state.pr_number = _git.pr_number_from_url(pr_url)
    else:
        title = (state.commit_message or f"Implement issue #{issue}").splitlines()[0]
        body = state.pr_body or f"Closes #{issue}"
        number, url, err = _git.create_pr(state.branch_name, title, body, args.base, gh_bin, repo)
        if err:
            raise AdwError(f"failed to open PR: {err}")
        state.pr_number, state.pr_url = number, url
    state.save()
    progress("finalize", f"PR ready: {state.pr_url}")

    # CI watch + fix loop.
    if state.pr_number is not None:
        ci_ok = ci_fix_loop(
            state,
            state.pr_number,
            gh_bin=gh_bin,
            repo=repo,
            max_attempts=args.max_ci_fix,
            runner=runner,
            runner_bin=runner_bin,
            cli_model=args.model,
            thinking=args.thinking,
            passthru=passthru,
            env=env,
            timeout=args.timeout,
            poll_interval=args.ci_poll_interval,
            max_polls=args.ci_max_polls,
            progress=progress,
        )
        if not ci_ok:
            raise AdwError("CI is not green; refusing to merge")

    # Merge gate (Python) — confirmation; non-tty without --yes aborts.
    confirm_merge(yes=assume_yes(args.yes), isatty=sys.stdin.isatty())
    ok, err = _git.squash_merge(state.pr_number or state.pr_url, gh_bin, repo)
    if not ok:
        raise AdwError(f"merge failed: {err}")
    _git.pull_rebase(args.base)
    state.mark_done("merge")
    state.save()

    # Verify.
    if args.verify:
        st = issue_state(gh_bin, issue, repo)
        if st != "CLOSED":
            raise AdwError(f"issue #{issue} is still {st} after merge; treating as failure")
        progress("report", f"verified: issue #{issue} is CLOSED")
    progress("report", f"phased run {state.adw_id} complete")
    return 0


# --- plan rendering / entry --------------------------------------------------


def _print_plan(issue: int, runner: str, phases: Sequence[str], args) -> None:
    chain = ["setup(python)"] + list(phases) + ["finalize(python)", "ci-fix(python)", "merge(python)", "report(python)"]
    print(f"[dry-run] phased run for issue #{issue} via {runner}")
    print("[dry-run] phases: " + " -> ".join(chain))
    print(f"[dry-run] agent env: GH_TOKEN withheld (allow_gh_token=False){'; inherited (--inherit-env)' if args.inherit_env else ''}")
    print(f"[dry-run] test gate: {args.test_cmd or DEFAULT_TEST_CMD}")


def _resolve_state(args: argparse.Namespace, issue: int) -> "tuple[AdwState, bool]":
    """Mint a fresh run state or resume an existing one; return `(state, resumed)`.

    `--resume` requires `--adw-id` and loads the saved state (starting fresh, with
    a note, if none is found). A bare `--adw-id` without `--resume` must not
    clobber existing state. A resumed run is bound to its original issue and
    refuses a mismatched number rather than retargeting the wrong issue onto the
    existing branch.
    """

    if args.resume and not args.adw_id:
        raise AdwError("--resume requires --adw-id <id>")
    existing = AdwState.load(args.adw_id) if args.adw_id else None
    state: Optional[AdwState] = None
    if args.resume:
        state = existing
        if state is None:
            note(f"no state for adw_id {args.adw_id}; starting fresh")
    elif existing is not None:
        raise AdwError(f"adw_id {args.adw_id} already has saved state; pass --resume to continue it")
    resumed = state is not None
    if state is None:
        state = AdwState(adw_id=args.adw_id or make_adw_id(), issue_number=str(issue), base=args.base)
    if resumed and state.issue_number and state.issue_number != str(issue):
        raise AdwError(f"adw_id {state.adw_id} belongs to issue #{state.issue_number}, not #{issue}")
    state.issue_number = str(issue)
    state.save()
    return state, resumed


def run(args: argparse.Namespace, passthru: Sequence[str], issue: int) -> int:
    """Execute the phased pipeline for one issue."""

    runner = args.runner
    if runner not in RUNNERS:
        raise AdwError(f"unknown --runner: {runner} (want: pi or claude)")

    phases = _phases.parse_phases(args.phases)

    if args.dry_run:
        _print_plan(issue, runner, phases, args)
        return 0

    gh_bin = resolve_gh_bin()
    repo = args.repo or detect_repo(gh_bin)

    # Preflight: skip already-closed issues; fail fast on unknown numbers.
    if args.verify or not args.force:
        if not gh_bin:
            if args.verify:
                raise AdwError("gh not found but verification is on; install gh, set GH_BIN, or pass --no-verify")
        else:
            st = issue_state(gh_bin, issue, repo)
            if st == "CLOSED" and not args.force:
                note(f"issue #{issue} is already CLOSED; skipping (use --force to run anyway)")
                return 0
            if st == "UNKNOWN":
                raise AdwError(f"issue #{issue} not found in {repo or 'the current repo'} (is gh authenticated?)")

    # State: mint a fresh run or resume an existing one (rules in _resolve_state).
    state, resumed = _resolve_state(args, issue)
    note(f"phased run id: {state.adw_id} (workspace: {state.workspace()})")

    # A resumed run legitimately carries the prior run's uncommitted edits (Python
    # only commits at finalize), so the clean-tree precondition applies to fresh
    # runs only.
    if not args.allow_dirty and not resumed and working_tree_dirty():
        raise AdwError("working tree is dirty; commit/stash first or pass --allow-dirty")

    runner_bin = resolve_runner_bin(runner)
    env = None if args.inherit_env else safe_subprocess_env(allow_gh_token=False)

    post = not args.no_progress

    def progress(phase: str, message: str) -> None:
        if post:
            post_progress(gh_bin, issue, repo, state.adw_id, phase, message)

    progress("ops", f"starting phased run {state.adw_id}")

    # Issue context (fetched by Python; injected into token-less agent phases).
    ctx = work_issue.fetch_issue(gh_bin, issue, repo) or {}

    if not state.is_done("setup"):
        _setup(state, gh_bin, repo, issue, ctx, args, progress)
        state.mark_done("setup")
        state.save()

    files = changed_files(args.base)
    signal = " ".join([ctx.get("title", ""), ctx.get("body", ""), " ".join(ctx.get("labels", [])), " ".join(files)])

    review_result = None
    for phase in phases:
        if state.is_done(phase):
            note(f"skipping {phase} (already completed)")
            continue

        if phase in _phases.CONDITIONAL_PHASES:
            run_it, reason = _phases.gate_conditional(phase, signal, files)
            if not run_it:
                progress(phase, f"skipped: {reason}")
                state.mark_done(phase)
                state.save()
                continue

        if phase == "resolve":
            resolve_loop(
                state,
                test_cmd=args.test_cmd or DEFAULT_TEST_CMD,
                max_attempts=args.max_resolve,
                runner=runner,
                runner_bin=runner_bin,
                cli_model=args.model,
                thinking=args.thinking,
                passthru=passthru,
                env=env,
                timeout=args.timeout,
                progress=progress,
            )
            state.mark_done(phase)
            state.save()
            continue

        if phase == "patch":
            # On a resume the review phase is skipped, so reconstruct its findings
            # from persisted state rather than silently patching nothing.
            if review_result is not None:
                findings = review_result.findings
            else:
                # Tolerant reconstruction (mirrors _phases.to_result): state.json
                # is the cross-language contract and permits additive keys inside
                # findings, so never ReviewFinding(**f) a persisted dict.
                findings = [
                    _phases.ReviewFinding(
                        severity=str(f.get("severity", "skippable")),
                        description=str(f.get("description", "")),
                        location=str(f.get("location", "")),
                    )
                    for f in state.review_findings
                    if isinstance(f, dict)
                ]
            patch_loop(
                state,
                findings,
                max_attempts=args.max_patch,
                runner=runner,
                runner_bin=runner_bin,
                cli_model=args.model,
                thinking=args.thinking,
                passthru=passthru,
                env=env,
                timeout=args.timeout,
                progress=progress,
            )
            state.mark_done(phase)
            state.save()
            continue

        # Normal agent phase.
        data = _phases.run_agent_phase(
            phase,
            _phase_args(phase, issue, state, ctx, review_result, files),
            state=state,
            runner=runner,
            runner_bin=runner_bin,
            cli_model=args.model,
            thinking=args.thinking,
            passthru=passthru,
            env=env,
            timeout=args.timeout,
        )
        result = _phases.to_result(phase, data)
        _apply_result(state, phase, result)
        if phase in ("review", "document"):
            _absorb_authored_text(state)
        if phase == "review":
            review_result = result
            # Persist findings so a later --resume can still drive the patch phase.
            state.review_findings = [
                {"severity": f.severity, "description": f.description, "location": f.location}
                for f in result.findings
            ]
        if phase == "implement":
            files = result.files_changed or files
            signal = signal + " " + " ".join(files)
        state.mark_done(phase)
        state.save()
        progress(phase, "done")

    return _finalize_and_merge(
        state,
        args,
        gh_bin=gh_bin,
        repo=repo,
        issue=issue,
        runner=runner,
        runner_bin=runner_bin,
        env=env,
        passthru=passthru,
        progress=progress,
    )
