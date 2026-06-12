"""Tests for adw/_state.py (run id + persisted state).

State is written under a temporary AGENTS_DIR so tests never touch the repo.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from dataclasses import asdict, fields
from pathlib import Path
from unittest import mock

from adw import _state
from adw._state import AdwState, make_adw_id, validate_adw_id
from adw.common import AdwError

SCHEMA_PATH = Path(__file__).resolve().parent / "state.schema.json"


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


class SchemaVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_default_and_persisted(self) -> None:
        state = AdwState(adw_id="a1b2c3d4")
        self.assertEqual(state.schema_version, 1)
        state.save()
        raw = json.loads(state.state_path().read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], 1)

    def test_legacy_file_without_version_loads_as_v1(self) -> None:
        ws = Path(self.tmp) / "a1b2c3d4"
        ws.mkdir(parents=True)
        (ws / "state.json").write_text(json.dumps({"adw_id": "a1b2c3d4", "issue_number": "9"}), encoding="utf-8")
        loaded = AdwState.load("a1b2c3d4")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.schema_version, 1)

    def test_future_version_still_loads(self) -> None:
        # The reader is forward-tolerant: a higher version from a newer engine
        # must not brick resume from the v1 fields.
        ws = Path(self.tmp) / "a1b2c3d4"
        ws.mkdir(parents=True)
        (ws / "state.json").write_text(
            json.dumps({"adw_id": "a1b2c3d4", "schema_version": 99, "issue_number": "9"}), encoding="utf-8"
        )
        loaded = AdwState.load("a1b2c3d4")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.schema_version, 99)
        self.assertEqual(loaded.issue_number, "9")


def _is_type(value: object, json_type: str) -> bool:
    """JSON-Schema primitive type check (bool is not an integer/number)."""

    if json_type == "string":
        return isinstance(value, str)
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if json_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if json_type == "boolean":
        return isinstance(value, bool)
    if json_type == "null":
        return value is None
    if json_type == "array":
        return isinstance(value, list)
    if json_type == "object":
        return isinstance(value, dict)
    return False


def _validate(instance: object, schema: dict, path: str = "$") -> list[str]:
    """Validate `instance` against the subset of JSON Schema state.schema.json
    uses (type/required/properties/items/pattern/minimum).

    Stdlib-only on purpose: adw/ takes no third-party dependencies, and this is
    the Python half of the cross-language contract test (the TS engine validates
    the same schema file from its own test suite).
    """

    errors: list[str] = []
    declared = schema.get("type")
    if declared is not None:
        types = declared if isinstance(declared, list) else [declared]
        if not any(_is_type(instance, t) for t in types):
            return [f"{path}: {instance!r} is not of type {types}"]
    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                errors.append(f"{path}: missing required key {required!r}")
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                errors.extend(_validate(instance[key], subschema, f"{path}.{key}"))
    if isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, element in enumerate(instance):
                errors.extend(_validate(element, items, f"{path}[{i}]"))
    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if pattern and not re.search(pattern, instance):
            errors.append(f"{path}: {instance!r} does not match pattern {pattern!r}")
    if isinstance(instance, int) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            errors.append(f"{path}: {instance} is below minimum {minimum}")
    return errors


class SchemaContractTests(unittest.TestCase):
    """Drift guard between AdwState and adw/state.schema.json.

    state.schema.json is the sole cross-language contract with the TypeScript
    adw_sdlc/ engine; these tests are the Python side of the dual-language
    check that keeps two no-shared-code implementations from drifting.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(_state, "AGENTS_DIR", Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_dataclass_field_is_codified(self) -> None:
        # Python ⊆ schema: every field AdwState writes must be declared. The
        # schema may additionally declare TS-only additive properties, which
        # Python intentionally never reads (load() drops unknown keys).
        python_fields = {f.name for f in fields(AdwState)}
        missing = python_fields - set(self.schema["properties"])
        self.assertEqual(missing, set(), f"fields missing from state.schema.json: {sorted(missing)}")

    def test_required_keys_are_writable_by_python(self) -> None:
        # required ⊆ Python fields: Python's writer must always be able to
        # produce a valid document.
        python_fields = {f.name for f in fields(AdwState)}
        self.assertLessEqual(set(self.schema["required"]), python_fields)
        self.assertIn("adw_id", self.schema["required"])
        self.assertIn("schema_version", self.schema["required"])

    def test_additive_evolution_is_permitted(self) -> None:
        # The whole coexistence story rests on unknown keys being legal.
        self.assertIs(self.schema.get("additionalProperties"), True)

    def test_minimal_saved_state_validates(self) -> None:
        state = AdwState(adw_id="a1b2c3d4")
        state.save()
        raw = json.loads(state.state_path().read_text(encoding="utf-8"))
        self.assertEqual(_validate(raw, self.schema), [])

    def test_fully_populated_saved_state_validates(self) -> None:
        state = AdwState(
            adw_id="a1b2c3d4",
            issue_number="15",
            issue_class="feat",
            branch_name="feat/15-x",
            base="main",
            plan_file="specs/15-x.md",
            pr_number=42,
            pr_url="https://github.com/kortiene/mx-agent/pull/42",
            commit_message="feat: x",
            pr_body="body",
            review_findings=[{"severity": "blocker", "description": "d", "location": "a.py:1"}],
        )
        state.mark_done("setup")
        state.mark_done("plan")
        state.save()
        raw = json.loads(state.state_path().read_text(encoding="utf-8"))
        self.assertEqual(_validate(raw, self.schema), [])

    def test_validator_rejects_contract_breaks(self) -> None:
        # Sanity-check the mini validator itself so a green contract test
        # actually means something.
        base = asdict(AdwState(adw_id="a1b2c3d4"))
        self.assertEqual(_validate(base, self.schema), [])
        for mutation, expect in [
            ({"adw_id": "NOTHEX!!"}, "pattern"),
            ({"schema_version": 0}, "minimum"),
            ({"schema_version": "1"}, "type"),
            ({"pr_number": "42"}, "type"),
            ({"completed_phases": "plan"}, "type"),
            ({"review_findings": [["not-an-object"]]}, "type"),
        ]:
            mutated = {**base, **mutation}
            errors = _validate(mutated, self.schema)
            self.assertTrue(errors, f"expected a violation for {mutation}")
            self.assertIn(expect, " ".join(errors))
        dropped = dict(base)
        del dropped["schema_version"]
        self.assertIn("missing required", " ".join(_validate(dropped, self.schema)))


if __name__ == "__main__":
    unittest.main()
