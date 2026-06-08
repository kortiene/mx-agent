"""Phase registry, structured-output contracts, and model routing.

Each agent phase renders one `.pi/prompts` (or `.claude/commands`) template,
invokes the runner once, and parses a trailing fenced-JSON reply into a per-phase
dataclass. Python owns sequencing/looping/git (see `_orchestrator`); this module
is the catalog the orchestrator drives.

Stdlib only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from adw.common import REPO_ROOT, AdwError, parse_json, render_prompt_file
from adw._runner import build_runner_command, run_agent_capture, wrap_timeout

# --- phase catalog -----------------------------------------------------------

# Configurable agent-phase chain (Python-only setup/finalize/ci-fix/merge/report
# always wrap this in the orchestrator and are not listed here).
AGENT_PHASES = (
    "classify",
    "plan",
    "implement",
    "tests",
    "resolve",
    "e2e",
    "review",
    "patch",
    "document",
)
DEFAULT_PHASES: list[str] = list(AGENT_PHASES)
CONDITIONAL_PHASES = {"e2e", "document"}
LOOP_PHASES = {"resolve", "patch"}

# Phase -> prompt-template basename (without .md).
TEMPLATE = {
    "classify": "classify",
    "plan": "plan",
    "implement": "implement",
    "tests": "tests",
    "resolve": "resolve_failed_test",
    "e2e": "e2e_tests",
    "review": "review_phase",  # dedicated phased body (the PR-oriented review.md stays for interactive use)
    "patch": "patch",
    "document": "document",
}

# Phase -> model tier; tiers resolve to concrete model strings per runner.
PHASE_TIER = {
    "classify": "cheap",
    "plan": "capable",
    "implement": "capable",
    "tests": "mid",
    "resolve": "mid",
    "e2e": "mid",
    "review": "capable",
    "patch": "capable",
    "document": "mid",
}
TIER_MODELS = {
    "claude": {"cheap": "haiku", "mid": "sonnet", "capable": "opus"},
    # pi accepts bare model names too; users typically override via --model,
    # PI_MODEL, or MX_AGENT_MODEL_<PHASE> for pi's `name:thinking` patterns.
    "pi": {"cheap": "haiku", "mid": "sonnet", "capable": "opus"},
}


def parse_phases(csv: "str | None") -> list[str]:
    """Parse a `--phases` CSV into a validated ordered phase list."""

    if not csv:
        return list(DEFAULT_PHASES)
    items = [p.strip() for p in csv.split(",") if p.strip()]
    if not items:
        raise AdwError("no phases given")
    for phase in items:
        if phase not in AGENT_PHASES:
            raise AdwError(f"unknown phase: {phase} (known: {', '.join(AGENT_PHASES)})")
    return items


def model_for_phase(phase: str, runner: str, cli_model: str = "") -> str:
    """Resolve the model for `phase`: --model > MX_AGENT_MODEL_<PHASE> > tier default."""

    if cli_model:
        return cli_model
    override = os.environ.get(f"MX_AGENT_MODEL_{phase.upper()}")
    if override:
        return override
    tier = PHASE_TIER.get(phase, "mid")
    return TIER_MODELS.get(runner, TIER_MODELS["claude"]).get(tier, "")


def template_path(runner: str, name: str) -> Path:
    """Resolve a phase template path, preferring `.claude/commands` for claude."""

    if runner == "claude":
        claude = REPO_ROOT / ".claude" / "commands" / f"{name}.md"
        if claude.is_file():
            return claude
    return REPO_ROOT / ".pi" / "prompts" / f"{name}.md"


# --- conditional gates -------------------------------------------------------

# Whole words in the change signal (issue text + changed paths) that mean a change
# crosses a user-visible boundary worth end-to-end coverage. Matched on word
# boundaries (see `_hint_in`), so the helper file path `adw/_exec.py` does NOT
# trip "exec" and "design"/"assignee" do NOT trip a signing hint. Ambiguous short
# stems are spelled out as their meaningful forms for the same reason.
_CROSS_BOUNDARY_HINTS = (
    "ipc",
    "daemon",
    "matrix",
    "signing",
    "signed",
    "signature",
    "trust",
    "policy",
    "sandbox",
    "pty",
    "stream",
    "artifact",
    "exec",
    "login",
    "sync",
    "scheduler",
)
# Whole words meaning the change is user-visible / API / protocol and warrants docs.
_DOC_HINTS = (
    "cli",
    "help",
    "public api",
    "protocol",
    "schema",
    "user-visible",
    "user facing",
    "user-facing",
    "config",
    "command",
    "flag",
)


def _hint_in(text: str, hints: "tuple[str, ...]") -> "str | None":
    """Return the first hint that occurs as a whole word in `text`, else `None`.

    Word-boundary matching (not bare `in`) prevents incidental-substring false
    positives — e.g. the path `adw/_exec.py` must not trigger the "exec" hint,
    and "design"/"assignee" must not trigger a signing hint.
    """

    for hint in hints:
        if re.search(rf"\b{re.escape(hint)}\b", text):
            return hint
    return None


def gate_e2e(signal: str) -> "tuple[bool, str]":
    """Decide whether the e2e phase should run, with a recorded reason."""

    low = (signal or "").lower()
    hit = _hint_in(low, _CROSS_BOUNDARY_HINTS)
    if hit:
        return True, f"change touches cross-boundary flows ({hit})"
    return False, "no cross-boundary surface detected"


def gate_document(signal: str, changed_files: Sequence[str] = ()) -> "tuple[bool, str]":
    """Decide whether the document phase should run, with a recorded reason."""

    low = (signal or "").lower()
    doc_like = any(
        f == "README.md" or f.startswith("docs/") or f.startswith("wiki/") or f.endswith(".md")
        for f in changed_files
    )
    if doc_like:
        return True, "documentation files changed"
    hit = _hint_in(low, _DOC_HINTS)
    if hit:
        return True, f"user-visible/API/protocol surface affected ({hit})"
    return False, "internal-only change; no docs update needed"


def gate_conditional(phase: str, signal: str, changed_files: Sequence[str] = ()) -> "tuple[bool, str]":
    """Decide a conditional phase via its gate; return `(run_it, reason)`.

    Dispatches `e2e`/`document` to the matching gate so the orchestrator has one
    skip path for both. Raises `AdwError` for any non-conditional phase so a
    miswired caller fails loudly instead of silently running it.
    """

    if phase == "e2e":
        return gate_e2e(signal)
    if phase == "document":
        return gate_document(signal, changed_files)
    raise AdwError(f"not a conditional phase: {phase}")


# --- structured outputs ------------------------------------------------------


@dataclass
class ClassifyResult:
    issue_class: str
    reason: str = ""


@dataclass
class PlanResult:
    plan_file: Optional[str] = None
    spec_created: bool = False
    summary: str = ""


@dataclass
class ImplementResult:
    summary: str = ""
    files_changed: list[str] = field(default_factory=list)


@dataclass
class TestsResult:
    tests_added: bool = False
    summary: str = ""


@dataclass
class ResolveResult:
    resolved: int = 0
    remaining: int = 0
    summary: str = ""


@dataclass
class E2EResult:
    e2e_added: bool = False
    summary: str = ""


@dataclass
class ReviewFinding:
    severity: str
    description: str = ""
    location: str = ""


@dataclass
class ReviewResult:
    findings: list[ReviewFinding] = field(default_factory=list)
    # Commit message / PR body are authored to workspace files, not inlined in JSON.
    wrote_commit_message: bool = False
    wrote_pr_body: bool = False


@dataclass
class PatchResult:
    resolved: int = 0
    remaining: int = 0
    summary: str = ""


@dataclass
class DocumentResult:
    docs_updated: bool = False
    files: list[str] = field(default_factory=list)
    summary: str = ""
    wrote_commit_message: bool = False
    wrote_pr_body: bool = False


def _as_int(value, field: str) -> int:
    """Coerce an agent-supplied value to int, raising `AdwError` on garbage.

    `int("two")` raises a bare `ValueError`; since `AdwError` *subclasses*
    `ValueError`, that bare error would slip past callers' `except AdwError`
    and crash the run with a traceback. Normalising it to `AdwError` keeps
    malformed structured output a graceful, reported failure.
    """

    try:
        return int(value or 0)
    except (TypeError, ValueError):
        raise AdwError(f"expected an integer for {field!r}, got {value!r}")


def to_result(phase: str, data: dict):
    """Map a parsed JSON object to its per-phase dataclass (missing keys default)."""

    if not isinstance(data, dict):
        raise AdwError(f"{phase} phase output must be a JSON object")
    if phase == "classify":
        issue_class = str(data.get("issue_class") or "").strip()
        if not issue_class:
            raise AdwError("classify output missing 'issue_class'")
        return ClassifyResult(issue_class=issue_class, reason=str(data.get("reason", "")))
    if phase == "plan":
        return PlanResult(
            plan_file=data.get("plan_file"),
            spec_created=bool(data.get("spec_created", False)),
            summary=str(data.get("summary", "")),
        )
    if phase == "implement":
        return ImplementResult(
            summary=str(data.get("summary", "")),
            files_changed=list(data.get("files_changed", []) or []),
        )
    if phase == "tests":
        return TestsResult(tests_added=bool(data.get("tests_added", False)), summary=str(data.get("summary", "")))
    if phase == "resolve":
        return ResolveResult(
            resolved=_as_int(data.get("resolved", 0), "resolved"),
            remaining=_as_int(data.get("remaining", 0), "remaining"),
            summary=str(data.get("summary", "")),
        )
    if phase == "e2e":
        return E2EResult(e2e_added=bool(data.get("e2e_added", False)), summary=str(data.get("summary", "")))
    if phase == "review":
        findings = [
            ReviewFinding(
                severity=str(f.get("severity", "skippable")),
                description=str(f.get("description", "")),
                location=str(f.get("location", "")),
            )
            for f in (data.get("findings", []) or [])
            if isinstance(f, dict)
        ]
        return ReviewResult(
            findings=findings,
            wrote_commit_message=bool(data.get("wrote_commit_message", False)),
            wrote_pr_body=bool(data.get("wrote_pr_body", False)),
        )
    if phase == "patch":
        return PatchResult(
            resolved=_as_int(data.get("resolved", 0), "resolved"),
            remaining=_as_int(data.get("remaining", 0), "remaining"),
            summary=str(data.get("summary", "")),
        )
    if phase == "document":
        return DocumentResult(
            docs_updated=bool(data.get("docs_updated", False)),
            files=list(data.get("files", []) or []),
            summary=str(data.get("summary", "")),
            wrote_commit_message=bool(data.get("wrote_commit_message", False)),
            wrote_pr_body=bool(data.get("wrote_pr_body", False)),
        )
    raise AdwError(f"no result mapping for phase: {phase}")


# --- phased envelope ---------------------------------------------------------
#
# The reused templates (plan/implement/tests/e2e_tests/review) were written for
# interactive/one-shot use and are also consumed by the render-only wrappers and
# the monolithic issue.md, so they must not be edited for phased mode. Instead,
# the orchestrator composes each phase prompt as:
#
#     [shared preamble] + [per-phase reframing] + [domain template body] + [JSON footer]
#
# The preamble/footer (owned here, in code) supply the phased rules — Python owns
# git/gh; no GitHub access; emit a trailing JSON contract — and override stale
# framing in the reused bodies. The four phase-native templates carry only domain
# guidance; their output contract also comes from the footer, so there is one
# source of truth per phase (kept in sync with `to_result`).

PHASE_PREAMBLE_SHARED = (
    "You are running as a single automated phase of the mx-agent ADW pipeline.\n"
    "Python performs ALL git and GitHub work for this run: do NOT run git or gh, do NOT "
    "create/switch/commit/push branches, and do NOT open, merge, or comment on pull requests. "
    "If the task section below tells you to do any of that, skip those steps.\n"
    "You have no GitHub access in this phase; all issue context you need is provided inline.\n"
)

# Per-phase reframing prepended after the shared preamble; overrides stale framing
# carried by the reused interactive templates.
PHASE_CONTEXT = {
    "implement": "Scope for this phase: make the code change only. Focused tests are added in a "
    "separate `tests` phase — do not do broad test work here. If $1 names a spec file that exists, "
    "treat it as the source of truth; otherwise (e.g. $1 is a placeholder note, not a path) treat "
    "the inline issue context as the spec and implement directly — do NOT stop merely because no "
    "spec file path was provided.\n",
    "tests": "Scope for this phase: add or strengthen focused, non-e2e tests for the change.\n",
    "e2e": "The orchestrator already decided this phase should run; do the work rather than "
    "re-deciding whether e2e coverage is warranted.\n",
    # `review` uses a dedicated phased template (review_phase.md) that is already
    # working-tree-oriented, so it needs no reframing here.
    "document": "The orchestrator already decided documentation is warranted; update the existing "
    "docs surface (README/docs/wiki/help) only. Do not create an app_docs/ tree.\n",
}

# Per-phase JSON output schema — the single source of truth, kept in sync with `to_result`.
OUTPUT_CONTRACT = {
    "classify": '{"issue_class": "feat|fix|docs|chore|ci|test|refactor", "reason": "<one sentence>"}',
    "plan": '{"plan_file": "specs/<file>.md", "spec_created": true, "summary": "<short>"}',
    "implement": '{"summary": "<short>", "files_changed": ["<path>", "..."]}',
    "tests": '{"tests_added": true, "summary": "<short>"}',
    "resolve": '{"resolved": 0, "remaining": 0, "summary": "<short>"}',
    "e2e": '{"e2e_added": true, "summary": "<short>"}',
    "review": (
        '{"findings": [{"severity": "blocker|tech_debt|skippable", "description": "<what>", '
        '"location": "<file:line>"}], "wrote_commit_message": true, "wrote_pr_body": true}'
    ),
    "patch": '{"resolved": 0, "remaining": 0, "summary": "<short>"}',
    "document": '{"docs_updated": true, "files": ["docs/<file>"], "wrote_commit_message": true, "wrote_pr_body": true}',
}

# Phases that author free-form text to workspace files instead of inlining it in JSON.
ARTIFACT_PHASES = {"review", "document"}


def commit_message_path(state) -> Path:
    """Workspace path where the authoring phase writes the commit message."""

    return state.workspace() / "commit_message.txt"


def pr_body_path(state) -> Path:
    """Workspace path where the authoring phase writes the PR body."""

    return state.workspace() / "pr_body.md"


def _build_footer(phase: str, state) -> str:
    """Build the per-phase output-contract footer (and artifact instructions)."""

    lines: list[str] = []
    if phase in ARTIFACT_PHASES:
        lines += [
            "Author these files first (this keeps large free-form text out of the JSON, which",
            "the pipeline parses mechanically):",
            f"- Write the full commit message (subject + body, ending with a line `closes #<issue>`) to: "
            f"{commit_message_path(state)}",
            f"- Write the complete PR body (Markdown) to: {pr_body_path(state)}",
            "Set the matching wrote_* booleans to true once each file is written.",
            "",
        ]
    lines += [
        "## Required output",
        "",
        "End your reply with EXACTLY one fenced ```json block matching this shape, and nothing after it:",
        "",
        "```json",
        OUTPUT_CONTRACT[phase],
        "```",
    ]
    return "\n".join(lines)


def compose_phase_prompt(phase: str, template_args: Sequence[str], state, runner: str = "pi") -> str:
    """Compose the full phased prompt for `phase` (pure; used by the self-test too).

    Shared preamble + per-phase reframing + the (reused or new) domain template
    body + the JSON output-contract footer.
    """

    tpath = template_path(runner, TEMPLATE[phase])
    if not tpath.is_file():
        raise AdwError(f"prompt template not found for phase {phase}: {tpath}")
    body = render_prompt_file(tpath, list(template_args))
    preamble = PHASE_PREAMBLE_SHARED + PHASE_CONTEXT.get(phase, "")
    footer = _build_footer(phase, state)
    return f"{preamble}\n---\n\n{body}\n\n---\n\n{footer}\n"


# --- single-phase execution --------------------------------------------------

_NUDGE = "\n\nRespond with ONLY the required JSON object in a ```json fenced block, nothing else."

# Exit codes that mean the runner was killed by `timeout`/a signal rather than
# replying — re-invoking with the same time box would just time out again, so we
# fail fast instead of burning a second full timeout on the nudge retry.
# (GNU `timeout` returns 124 on expiry; 128+SIGINT=130 with --signal=INT; 137 on
# SIGKILL.)
_TIMEOUT_EXIT_CODES = frozenset({124, 130, 137})


def run_agent_phase(
    phase: str,
    template_args: Sequence[str],
    *,
    state,
    runner: str,
    runner_bin: str,
    cli_model: str = "",
    thinking: str = "",
    passthru: Sequence[str] = (),
    env: "dict[str, str] | None" = None,
    timeout: int = 0,
) -> dict:
    """Render+run one agent phase and return its parsed JSON object.

    Retries once with a "respond with JSON only" nudge if the first reply does
    not parse; a second failure raises `AdwError`.
    """

    prompt = compose_phase_prompt(phase, template_args, state, runner)
    pdir = state.phase_dir(phase)
    (pdir / "prompt.txt").write_text(prompt, encoding="utf-8")
    model = model_for_phase(phase, runner, cli_model)

    rc, text = _invoke(runner, runner_bin, prompt, model, thinking, passthru, env, pdir / "transcript.log", timeout)
    try:
        return parse_json(text, expect=dict)
    except AdwError:
        # A timed-out/killed runner won't do better on a re-run with the same
        # time box — fail fast rather than spend a second full timeout.
        if rc in _TIMEOUT_EXIT_CODES:
            raise AdwError(f"{phase} phase runner exited {rc} (timed out) without parseable output")
        _, text2 = _invoke(
            runner, runner_bin, prompt + _NUDGE, model, thinking, passthru, env, pdir / "transcript-2.log", timeout
        )
        return parse_json(text2, expect=dict)


def _invoke(
    runner: str,
    runner_bin: str,
    prompt: str,
    model: str,
    thinking: str,
    passthru: Sequence[str],
    env: "dict[str, str] | None",
    transcript: Path,
    timeout: int,
) -> "tuple[int, str]":
    """Build, time-box, and run one runner command; return (exit code, text)."""

    cmd = build_runner_command(
        runner, runner_bin, json_mode=False, model=model, thinking=thinking, passthru=passthru, prompt=prompt
    )
    cmd = wrap_timeout(cmd, timeout)
    return run_agent_capture(cmd, transcript, env=env)
