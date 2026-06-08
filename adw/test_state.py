"""Tests for adw/_state.py (run id + persisted state).

State is written under a temporary AGENTS_DIR so tests never touch the repo.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adw import _state
from adw._state import AdwState, make_adw_id, validate_adw_id
from adw.common import AdwError


class MakeAdwIdTests(unittest.TestCase):
    def test_shape(self) -> None:
        adw_id = make_adw_id()
        self.assertEqual(len(adw_id), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in adw_id))

    def test_unique(self) -> None:
        self.assertNotEqual(make_adw_id(), make_adw_id())


class ValidateAdwIdTests(unittest.TestCase):
    def test_accepts_valid(self) -> None:
        self.assertEqual(validate_adw_id("a1b2c3d4"), "a1b2c3d4")

    def test_rejects_path_traversal_and_junk(self) -> None:
        for bad in ["../etc", "a1b2c3d4/x", "ABCDEF12", "short", "", "g1b2c3d4"]:
            with self.assertRaises(AdwError):
                validate_adw_id(bad)

    def test_constructor_validates(self) -> None:
        with self.assertRaises(AdwError):
            AdwState(adw_id="../bad")


class SaveLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_round_trip(self) -> None:
        state = AdwState(adw_id="a1b2c3d4", issue_number="15", branch_name="feat/15-x")
        state.mark_done("setup")
        state.save()
        loaded = AdwState.load("a1b2c3d4")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.issue_number, "15")
        self.assertEqual(loaded.branch_name, "feat/15-x")
        self.assertEqual(loaded.completed_phases, ["setup"])

    def test_missing_returns_none(self) -> None:
        self.assertIsNone(AdwState.load("deadbeef"))

    def test_corrupt_returns_none(self) -> None:
        ws = Path(self.tmp) / "a1b2c3d4"
        ws.mkdir(parents=True)
        (ws / "state.json").write_text("{not json", encoding="utf-8")
        self.assertIsNone(AdwState.load("a1b2c3d4"))

    def test_unknown_keys_ignored(self) -> None:
        ws = Path(self.tmp) / "a1b2c3d4"
        ws.mkdir(parents=True)
        (ws / "state.json").write_text(
            json.dumps({"adw_id": "a1b2c3d4", "issue_number": "9", "future_field": 123}), encoding="utf-8"
        )
        loaded = AdwState.load("a1b2c3d4")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.issue_number, "9")

    def test_phase_dir_created_under_workspace(self) -> None:
        state = AdwState(adw_id="a1b2c3d4")
        pdir = state.phase_dir("implement")
        self.assertTrue(pdir.is_dir())
        self.assertEqual(pdir, Path(self.tmp) / "a1b2c3d4" / "implement")

    def test_mark_done_idempotent(self) -> None:
        state = AdwState(adw_id="a1b2c3d4")
        state.mark_done("plan")
        state.mark_done("plan")
        self.assertEqual(state.completed_phases, ["plan"])
        self.assertTrue(state.is_done("plan"))


if __name__ == "__main__":
    unittest.main()
