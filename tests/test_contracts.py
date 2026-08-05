from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "contracts" / "v1"
FIXTURE_DIR = ROOT / "fixtures" / "v1"


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.name.removesuffix(".schema.json"): json.loads(path.read_text())
            for path in SCHEMA_DIR.glob("*.schema.json")
        }

    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        self.assertEqual(8, len(self.schemas))
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)

    def test_valid_synthetic_fixtures_pass(self) -> None:
        fixtures = sorted((FIXTURE_DIR / "valid").glob("*.json"))
        self.assertEqual(8, len(fixtures))
        for fixture in fixtures:
            with self.subTest(fixture=fixture.name):
                payload = json.loads(fixture.read_text())
                validator = Draft202012Validator(
                    self.schemas[fixture.stem], format_checker=FormatChecker()
                )
                self.assertEqual([], list(validator.iter_errors(payload)))

    def test_invalid_synthetic_fixtures_are_rejected(self) -> None:
        fixtures = sorted((FIXTURE_DIR / "invalid").glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 7)
        for fixture in fixtures:
            with self.subTest(fixture=fixture.name):
                contract_name = fixture.stem.split("__", 1)[0]
                payload = json.loads(fixture.read_text())
                validator = Draft202012Validator(
                    self.schemas[contract_name], format_checker=FormatChecker()
                )
                self.assertTrue(list(validator.iter_errors(payload)))

    def test_task_contract_has_no_caller_supplied_network_location(self) -> None:
        task_schema = json.dumps(self.schemas["diagnostic-task"])
        self.assertNotIn("document_url", task_schema)
        self.assertNotIn("callback_url", task_schema)


if __name__ == "__main__":
    unittest.main()
