from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gate0.aat import AATGoldenHarness, AAT_INTEGRATION_VERSION, ENGINE_VERSION, PROTOCOL_VERSION, fidelity_checks
from gate0.parser.worker import PARSER_VERSION
from gate0.report_pipeline import PDF_EXPORTER_VERSION, REPORT_PIPELINE_VERSION, SANITIZER_VERSION


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    spec = json.loads((ROOT / "fixtures" / "aat" / "AAT_GOLDEN_SPEC_v1.json").read_text())
    normal_path = ROOT / spec["source"]["normal_fixture"]
    attack_path = ROOT / spec["source"]["attack_fixture"]
    unsupported = ROOT / "fixtures" / "aat" / "UNSUPPORTED_DOCUMENT.txt"
    with tempfile.TemporaryDirectory(prefix="aat-golden-vector-") as temp_name:
        harness = AATGoldenHarness(ROOT, Path(temp_name))
        normal = harness.run_success("acct_aat_owner", "normal", normal_path, "normal-request-key")
        attack = harness.run_success("acct_aat_owner", "attack", attack_path, "attack-request-key")
        repeated = harness.run_success("acct_aat_owner", "normal", normal_path, "normal-request-key")
        parser_reject = harness.run_failure("acct_aat_owner", "parser_reject", unsupported, "parser_reject")
        engine_failure = harness.run_failure("acct_aat_owner", "engine_failure", normal_path, "engine_failure")
        cancelled = harness.run_failure("acct_aat_owner", "cancel", normal_path, "cancel")
        timed_out = harness.run_failure("acct_aat_owner", "timeout", normal_path, "timeout")
        cross_account_rejected = harness.reject_cross_account_binding("acct_aat_owner", "acct_aat_attacker")

        normal_fidelity = fidelity_checks(normal.terminal_contract["report"], spec)
        attack_fidelity = fidelity_checks(attack.terminal_contract["report"], spec)
        failures = [parser_reject, engine_failure, cancelled, timed_out]
        all_contracts = {
            "diagnostic-cancellation.schema.json",
            "diagnostic-failure.schema.json",
            "diagnostic-result.schema.json",
            "diagnostic-task.schema.json",
            "diagnostic-timeout.schema.json",
            "parser-output.schema.json",
            "settlement-event.schema.json",
            "task-event.schema.json",
        }
        assertions = {
            "normal_complete": normal.status == "completed",
            "attack_complete": attack.status == "completed",
            "normal_and_attack_report_semantics_equal": normal.report_sha256 == attack.report_sha256,
            "hidden_instruction_detected": spec["attack_condition"]["expected_parser_warning"] in attack.parser_output["warnings"],
            "hidden_instruction_absent_from_delivery": spec["attack_condition"]["marker"].lower() not in json.dumps(attack.terminal_contract).lower(),
            "normal_conclusion_fidelity": all(normal_fidelity.values()),
            "attack_conclusion_fidelity": all(attack_fidelity.values()),
            "presentation_paths_consistent": normal.ui_body_sha256 == normal.html_body_sha256 and attack.ui_body_sha256 == attack.html_body_sha256,
            "human_review_revalidated": normal.semantic_sha256 is not None and attack.semantic_sha256 is not None,
            "exactly_once_success_settlement": [event["action"] for event in normal.ledger] == ["authorize", "capture", "release"],
            "capture_webhook_replay_noop": len(normal.ledger) == 3,
            "success_request_replay_same_result": repeated is normal,
            "all_failure_paths_nonbillable": all([event["action"] for event in outcome.ledger] == ["authorize", "release"] for outcome in failures),
            "all_failure_paths_leave_no_deliverable": all(outcome.report_id is None for outcome in failures),
            "cross_account_binding_rejected_before_cost": cross_account_rejected,
            "resource_owners_consistent": normal.resource_owner_consistent and attack.resource_owner_consistent,
            "all_frozen_contracts_exercised": all_contracts == set(harness.registry.calls),
            "gate1_exclusion_preserved": "excluded from Gate 1" in spec["purpose"],
        }
        payload = {
            "versions": {
                "aat_integration": AAT_INTEGRATION_VERSION,
                "engine": ENGINE_VERSION,
                "protocol": PROTOCOL_VERSION,
                "parser": PARSER_VERSION,
                "report_pipeline": REPORT_PIPELINE_VERSION,
                "sanitizer": SANITIZER_VERSION,
                "pdf_exporter": PDF_EXPORTER_VERSION,
            },
            "fixture_sha256": {
                str(normal_path.relative_to(ROOT)): sha256(normal_path),
                str(attack_path.relative_to(ROOT)): sha256(attack_path),
                str(unsupported.relative_to(ROOT)): sha256(unsupported),
                "fixtures/aat/AAT_GOLDEN_SPEC_v1.json": sha256(ROOT / "fixtures" / "aat" / "AAT_GOLDEN_SPEC_v1.json"),
                "fixtures/aat/FACT_SNAPSHOT_v1.json": sha256(ROOT / "fixtures" / "aat" / "FACT_SNAPSHOT_v1.json"),
            },
            "contract_calls": {name: harness.registry.calls.count(name) for name in sorted(all_contracts)},
            "normal": {"task_id": normal.task_id, "report_sha256": normal.report_sha256, "semantic_sha256": normal.semantic_sha256, "pdf_sha256": normal.pdf_sha256, "states": normal.task_states, "ledger": normal.ledger, "fidelity": normal_fidelity},
            "attack": {"task_id": attack.task_id, "report_sha256": attack.report_sha256, "semantic_sha256": attack.semantic_sha256, "pdf_sha256": attack.pdf_sha256, "warnings": attack.parser_output["warnings"], "states": attack.task_states, "ledger": attack.ledger, "fidelity": attack_fidelity},
            "failure_paths": {outcome.condition: {"status": outcome.status, "states": outcome.task_states, "ledger": outcome.ledger, "deliverable": outcome.report_id is not None} for outcome in failures},
            "assertions": assertions,
        }
        print(json.dumps(payload, sort_keys=True))
        return 0 if all(assertions.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
