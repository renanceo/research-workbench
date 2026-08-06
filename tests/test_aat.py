from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

from gate0.aat import AATGoldenHarness, fidelity_checks
from gate0.namespace import NamespaceStore, ResourceType


ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / "fixtures" / "aat" / "AAT_GOLDEN_SPEC_v1.json").read_text())


class AATContractTests(unittest.TestCase):
    def test_namespace_document_and_diagnostic_ids_match_task_contract(self) -> None:
        namespace = NamespaceStore(b"aat-contract-prefix-test-key-00001")
        document = namespace.create("acct_test", ResourceType.DOCUMENT)
        diagnostic = namespace.create("acct_test", ResourceType.DIAGNOSTIC)
        self.assertRegex(document.resource_id, re.compile(r"^doc_[A-Za-z0-9_-]{8,64}$"))
        self.assertRegex(diagnostic.resource_id, re.compile(r"^diag_[A-Za-z0-9_-]{8,64}$"))

    def test_frozen_spec_is_explicitly_excluded_from_gate1(self) -> None:
        self.assertIn("excluded from Gate 1", SPEC["purpose"])
        self.assertTrue(SPEC["required"])
        self.assertTrue(SPEC["acceptable_variation"])
        self.assertTrue(SPEC["must_not_appear"])


@unittest.skipIf(sys.platform == "darwin", "hard-isolated AAT parser runs in the Linux evidence container")
class AATLinuxIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="aat-golden-test-")
        self.harness = AATGoldenHarness(ROOT, Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_normal_and_attack_conditions_have_equal_safe_conclusions(self) -> None:
        normal = self.harness.run_success("acct_aat_owner", "normal", ROOT / SPEC["source"]["normal_fixture"], "same-normal-request")
        attack = self.harness.run_success("acct_aat_owner", "attack", ROOT / SPEC["source"]["attack_fixture"], "same-attack-request")
        self.assertEqual("completed", normal.status)
        self.assertEqual("completed", attack.status)
        self.assertEqual(normal.report_sha256, attack.report_sha256)
        self.assertIn(SPEC["attack_condition"]["expected_parser_warning"], attack.parser_output["warnings"])
        self.assertTrue(all(fidelity_checks(normal.terminal_contract["report"], SPEC).values()))
        self.assertTrue(all(fidelity_checks(attack.terminal_contract["report"], SPEC).values()))

    def test_failure_paths_leave_no_report_and_release_authorization(self) -> None:
        cases = (
            ("parser_reject", ROOT / "fixtures" / "aat" / "UNSUPPORTED_DOCUMENT.txt", "parser_reject"),
            ("engine_failure", ROOT / SPEC["source"]["normal_fixture"], "engine_failure"),
            ("cancel", ROOT / SPEC["source"]["normal_fixture"], "cancel"),
            ("timeout", ROOT / SPEC["source"]["normal_fixture"], "timeout"),
        )
        for condition, source, mode in cases:
            with self.subTest(condition=condition):
                outcome = self.harness.run_failure("acct_aat_owner", condition, source, mode)
                self.assertIsNone(outcome.report_id)
                self.assertEqual(["authorize", "release"], [event["action"] for event in outcome.ledger])
                self.assertEqual(0, outcome.terminal_contract["settlement"]["billable_minor_units"])

    def test_repeat_capture_and_cross_account_binding_are_idempotent_or_rejected(self) -> None:
        source = ROOT / SPEC["source"]["normal_fixture"]
        first = self.harness.run_success("acct_aat_owner", "normal", source, "repeatable-request")
        repeated = self.harness.run_success("acct_aat_owner", "normal", source, "repeatable-request")
        self.assertIs(first, repeated)
        self.assertEqual(["authorize", "capture", "release"], [event["action"] for event in first.ledger])
        self.assertTrue(self.harness.reject_cross_account_binding("acct_aat_owner", "acct_aat_attacker"))


if __name__ == "__main__":
    unittest.main()
