"""Persistent run state for the phased ADW pipeline.

Each phased run gets an 8-character `adw_id` and an isolated workspace at
`agents/{adw_id}/` holding a `state.json` plus per-phase transcripts. The state
threads minimal identifiers between phases and records which phases have
completed so a run can be resumed with `--adw-id <id> --resume`.

Stdlib only (`dataclasses` + `json`); no third-party dependencies. The workspace
is ephemeral developer-workflow output, not daemon/app state — the daemon still
owns all long-lived Matrix state, credentials, crypto, and policy.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Optional

from adw.common import REPO_ROOT, AdwError

# Overridable in tests via `mock.patch.object(_state, "AGENTS_DIR", tmp)`; methods
# read the module global at call time so patching takes effect.
AGENTS_DIR = REPO_ROOT / "agents"
STATE_FILENAME = "state.json"

_ADW_ID_RE = re.compile(r"[0-9a-f]{8}")


def make_adw_id() -> str:
    """Generate a short 8-character hex run id (e.g. ``a1b2c3d4``)."""

    return uuid.uuid4().hex[:8]


def validate_adw_id(adw_id: str) -> str:
    """Return `adw_id` if it is a valid 8-char hex id, else raise `AdwError`.

    Guards against path injection before `adw_id` is used as a filesystem path
    segment under `agents/`.
    """

    if not adw_id or not _ADW_ID_RE.fullmatch(adw_id):
        raise AdwError(f"invalid adw_id (want 8 hex chars): {adw_id!r}")
    return adw_id


@dataclass
class AdwState:
    """Minimal persistent state connecting phased-run steps."""

    adw_id: str
    # Version of the on-disk state.json contract (adw/state.schema.json). Bump
    # only on a breaking change; additive fields keep the same version. Files
    # written before versioning load as 1 via this default.
    schema_version: int = 1
    issue_number: Optional[str] = None
    issue_class: Optional[str] = None  # feat/fix/docs/chore/...
    branch_name: Optional[str] = None
    base: str = "main"
    plan_file: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    commit_message: Optional[str] = None  # agent-authored, executed by Python
    pr_body: Optional[str] = None  # agent-authored, executed by Python
    # Review findings as plain dicts ({severity, description, location}) so they
    # survive a --resume and the patch phase can still see blockers it must fix.
    review_findings: list = field(default_factory=list)
    completed_phases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        validate_adw_id(self.adw_id)

    # --- paths ---------------------------------------------------------------

    def workspace(self) -> Path:
        """Return this run's workspace directory `agents/{adw_id}/`."""

        return AGENTS_DIR / self.adw_id

    def state_path(self) -> Path:
        """Return the path to this run's `state.json`."""

        return self.workspace() / STATE_FILENAME

    def phase_dir(self, phase: str) -> Path:
        """Return (creating) the per-phase artifact directory for `phase`."""

        directory = self.workspace() / _safe_phase(phase)
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    # --- phase bookkeeping ---------------------------------------------------

    def is_done(self, phase: str) -> bool:
        """Whether `phase` has already completed in this run."""

        return phase in self.completed_phases

    def mark_done(self, phase: str) -> None:
        """Record `phase` as completed (idempotent)."""

        if phase not in self.completed_phases:
            self.completed_phases.append(phase)

    # --- persistence ---------------------------------------------------------

    def save(self) -> None:
        """Persist state to `agents/{adw_id}/state.json` (best effort).

        State is a convenience for resume/observability; a write failure must
        never abort a run, so I/O errors are swallowed.
        """

        try:
            path = self.state_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass

    @classmethod
    def load(cls, adw_id: str) -> "Optional[AdwState]":
        """Load state for `adw_id`, or `None` if it is missing or unreadable."""

        validate_adw_id(adw_id)
        path = AGENTS_DIR / adw_id / STATE_FILENAME
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(data, dict) or "adw_id" not in data:
            return None
        # Forward-compatible: keep only declared fields, ignore unknown keys.
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        try:
            return cls(**filtered)
        except (TypeError, AdwError):
            return None


def _safe_phase(phase: str) -> str:
    """Sanitize a phase name for use as a path segment."""

    if not re.fullmatch(r"[a-zA-Z0-9_\-]+", phase or ""):
        raise AdwError(f"invalid phase name: {phase!r}")
    return phase
