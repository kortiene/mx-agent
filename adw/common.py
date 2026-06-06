"""Shared helpers for Agent Development Workflow scripts.

The ADW scripts intentionally keep `.pi/prompts/*.md` as the workflow source of
truth. They load a prompt template, apply the same small argument substitutions
that Pi prompt templates support, and print the rendered workflow for use by an
agent or operator.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
PROMPT_DIR = REPO_ROOT / ".pi" / "prompts"


class AdwError(ValueError):
    """Raised when ADW input cannot be rendered safely."""


def prompt_path(command: str) -> Path:
    """Return the prompt template path for a slash-command name."""

    if not re.fullmatch(r"[a-zA-Z0-9_\-]+", command):
        raise AdwError(f"invalid command name: {command!r}")
    return PROMPT_DIR / f"{command}.md"


def strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter from a prompt template body if present."""

    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 4)
    if end == -1:
        return text
    return text[end + len("\n---\n") :]


def load_prompt(command: str) -> str:
    """Load a prompt template body for `command` without frontmatter."""

    path = prompt_path(command)
    try:
        return strip_frontmatter(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdwError(f"prompt template not found: {path}") from exc


def _slice_args(args: Sequence[str], start: str, length: str | None = None) -> str:
    """Render a Pi-style `${@:N}` or `${@:N:L}` slice."""

    index = int(start) - 1
    if index < 0:
        raise AdwError("argument slices are 1-indexed")
    selected = args[index:] if length is None else args[index : index + int(length)]
    return " ".join(selected)


def substitute_args(text: str, args: Sequence[str]) -> str:
    """Apply Pi-style positional substitution to prompt-template text.

    Supported substitutions are `$1`, `$2`, `$@`, `$ARGUMENTS`, `${@:N}`, and
    `${@:N:L}`. This is the single substitution engine shared by every renderer
    in this package, so named-template and path-based rendering stay consistent.
    """

    all_args = " ".join(args)
    text = text.replace("$ARGUMENTS", all_args).replace("$@", all_args)

    def replace_slice(match: re.Match[str]) -> str:
        return _slice_args(args, match.group(1), match.group(2))

    text = re.sub(r"\$\{@:(\d+)(?::(\d+))?\}", replace_slice, text)

    def replace_positional(match: re.Match[str]) -> str:
        index = int(match.group(1)) - 1
        return args[index] if 0 <= index < len(args) else ""

    return re.sub(r"\$(\d+)", replace_positional, text)


def render_prompt(command: str, args: Sequence[str]) -> str:
    """Render a named prompt template with Pi-style positional substitutions.

    The rendered workflow is printed by the render-only command wrappers; those
    wrappers do not execute the workflow themselves.
    """

    return substitute_args(load_prompt(command), args)


def render_prompt_file(path: "str | Path", args: Sequence[str]) -> str:
    """Render a prompt template selected by filesystem path.

    Unlike `render_prompt`, the template is chosen by path rather than
    slash-command name, so callers can render either the `.pi/prompts` or the
    `.claude/commands` variant. YAML frontmatter is stripped before rendering.
    """

    path = Path(path)
    try:
        text = strip_frontmatter(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdwError(f"prompt template not found: {path}") from exc
    return substitute_args(text, args)


def print_rendered(command: str, args: Sequence[str]) -> int:
    """Print a rendered prompt and return a process exit code."""

    try:
        print(render_prompt(command, args), end="")
        return 0
    except AdwError as exc:
        print(f"adw: {exc}")
        return 2


def command_parser(command: str, description: str) -> argparse.ArgumentParser:
    """Build a parser for a wrapper that renders one prompt command."""

    parser = argparse.ArgumentParser(
        prog=f"python adw/{command}.py",
        description=description,
        epilog=(
            "This script renders the corresponding .pi/prompts template. "
            "It does not execute GitHub, Cargo, merge, or destructive workflow steps."
        ),
    )
    parser.add_argument("args", nargs="*", help="arguments passed to the prompt template")
    return parser


def wrapper_main(command: str, description: str, argv: Sequence[str] | None = None) -> int:
    """Entry point for a simple prompt-rendering wrapper script."""

    parser = command_parser(command, description)
    ns = parser.parse_args(argv)
    return print_rendered(command, ns.args)


def split_notes(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split arguments into selectors and shared notes at `--`."""

    if "--" not in argv:
        return list(argv), []
    index = list(argv).index("--")
    return list(argv[:index]), list(argv[index + 1 :])


def expand_issue_selectors(selectors: Iterable[str]) -> list[int]:
    """Expand issue IDs and inclusive ranges, preserving order and de-duping.

    Supported selectors are `12`, `12-15`, and `12..15`. Ranges are ascending
    only to avoid accidental reverse-order batch work.
    """

    seen: set[int] = set()
    expanded: list[int] = []
    for selector in selectors:
        values = _expand_one_selector(selector)
        for value in values:
            if value not in seen:
                seen.add(value)
                expanded.append(value)
    return expanded


def _expand_one_selector(selector: str) -> list[int]:
    """Expand one issue selector."""

    if re.fullmatch(r"\d+", selector):
        value = int(selector)
        if value <= 0:
            raise AdwError(f"issue IDs must be positive: {selector}")
        return [value]

    match = re.fullmatch(r"(\d+)(?:-|\.\.)(\d+)", selector)
    if not match:
        raise AdwError(f"invalid issue selector: {selector}")

    start = int(match.group(1))
    end = int(match.group(2))
    if start <= 0 or end <= 0:
        raise AdwError(f"issue IDs must be positive: {selector}")
    if end < start:
        raise AdwError(f"descending issue ranges are not supported: {selector}")
    return list(range(start, end + 1))
