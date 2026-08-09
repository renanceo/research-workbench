"""Validate and print the offline, entirely synthetic public preview."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "public-preview"
CONTRACTS = ROOT / "contracts" / "v1"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(contract_name: str, value: dict[str, Any]) -> None:
    schema = load(CONTRACTS / contract_name)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def assert_entirely_synthetic(task: dict[str, Any], result: dict[str, Any]) -> None:
    notes = task["input"]["decision_constraints"]["notes"].lower()
    limitations = " ".join(result["report"]["coverage_limitations"]).lower()
    if "synthetic" not in notes or "no real manuscript" not in notes:
        raise ValueError("preview task is not explicitly synthetic")
    if "synthetic" not in limitations or "no real paper" not in limitations:
        raise ValueError("preview result lacks its synthetic limitation")
    if not result["versions"]["engine"].startswith("synthetic-"):
        raise ValueError("preview engine is not a synthetic adapter")
    if result["metering"] != {
        "provider_cost_minor_units": 0,
        "retrieval_cost_minor_units": 0,
        "allocated_variable_cost_minor_units": 0,
        "currency": "USD",
    }:
        raise ValueError("preview metering must remain zero")
    for fact in result["report"]["current_facts"]:
        if not (urlparse(fact["source_url"]).hostname or "").endswith(".example"):
            raise ValueError("preview fact source is not in the reserved example domain")


def build_preview() -> dict[str, Any]:
    task_path = FIXTURES / "synthetic-task.json"
    result_path = FIXTURES / "synthetic-result.json"
    task = load(task_path)
    result = load(result_path)
    validate("diagnostic-task.schema.json", task)
    validate("diagnostic-result.schema.json", result)
    assert_entirely_synthetic(task, result)
    return {
        "preview_kind": "public_research_preview",
        "disclaimer": "Synthetic shape demonstration only; not a validated paper-positioning service.",
        "network_requests": 0,
        "real_manuscripts_processed": 0,
        "model_strategy": {
            "strategy_id": "synthetic_demo_strategy",
            "engine": result["versions"]["engine"],
            "actual_model_call": False,
            "provider_route": None,
        },
        "flow": [
            "synthetic_manuscript_reference",
            "structured_intake_validated",
            "synthetic_strategy_selected",
            "mock_diagnostic_completed",
            "report_contract_validated",
        ],
        "input_contract": task,
        "diagnostic_result": result,
        "fixture_sha256": {
            "synthetic-task.json": sha256(task_path),
            "synthetic-result.json": sha256(result_path),
        },
        "checks": {
            "task_contract_valid": True,
            "result_contract_valid": True,
            "entirely_synthetic": True,
            "zero_cost": True,
            "official_fact_provenance_shape_present": bool(result["report"]["current_facts"]),
            "false_friend_shape_present": bool(result["report"]["not_recommended"]),
            "abstention_shape_present": bool(result["report"]["abstentions"]),
        },
        "gate1_performance_claim": False,
        "real_manuscript_diagnostic_available": False,
        "paid_use_available": False,
    }


def main() -> int:
    print(json.dumps(build_preview(), indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
