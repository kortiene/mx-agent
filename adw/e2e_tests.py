#!/usr/bin/env python3
"""Render the `/e2e_tests` Agent Development Workflow prompt."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adw.common import wrapper_main


if __name__ == "__main__":
    raise SystemExit(wrapper_main("e2e_tests", "Render an end-to-end testing workflow.", sys.argv[1:]))
