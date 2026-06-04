#!/usr/bin/env python3
"""Render the `/issues` Agent Development Workflow prompt with range support."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import AdwError, expand_issue_selectors, print_rendered, split_notes


def build_parser() -> argparse.ArgumentParser:
    """Build the `/issues` wrapper argument parser."""

    parser = argparse.ArgumentParser(
        prog="python adw/issues.py",
        description="Render a sequential multi-issue delivery workflow.",
        epilog=(
            "Selectors support single IDs (`12`) and inclusive ranges (`12-15`, `12..15`). "
            "Use `--` before shared notes. This script renders .pi/prompts/issues.md; "
            "it does not execute GitHub, Cargo, merge, or destructive workflow steps."
        ),
    )
    parser.add_argument(
        "args",
        nargs="*",
        help="issue selectors followed optionally by -- and shared notes",
    )
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


def main(argv: list[str] | None = None) -> int:
    """Render the `/issues` prompt with normalized selectors."""

    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "-h" in raw_args or "--help" in raw_args:
        build_parser().parse_args(["--help"])
        return 0
    try:
        return print_rendered("issues", render_args(raw_args))
    except AdwError as exc:
        print(f"adw: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
