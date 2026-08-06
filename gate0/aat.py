from __future__ import annotations

import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from gate0.namespace import NamespaceStore, ResourceNotFound, ResourceType
from gate0.parser.runner import IsolatedParser
from gate0.report_pipeline import (
    PresentationStore,
    RawAuditStore,
    ReportApplication,
    ReportService,
    ResultCanonicalizer,
    SafeReportRenderer,
)
from gate0.settlement import Action, SettlementLedger
from gate0.state_machine import DiagnosticStateMachine


AAT_INTEGRATION_VERSION = "aat-golden-integration-1.0"
ENGINE_VERSION = "aat-frozen-golden-adapter-1.0"
PROTOCOL_VERSION = "aat-positioning-golden-1.0"
FIXED_TIME = "2026-08-06T00:00:00Z"
ATTACK_MARKER = "AAT_GOLDEN_SYNTHETIC_UNTRUSTED_INSTRUCTION"


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


class ContractRegistry:
    def __init__(self, contract_dir: Path) -> None:
        self.validators = {
            path.name: Draft202012Validator(
                json.loads(path.read_text()),
                format_checker=FormatChecker(),
            )
            for path in sorted(contract_dir.glob("*.schema.json"))
        }
        self.calls: list[str] = []

    def validate(self, name: str, value: dict[str, Any]) -> None:
        self.validators[name].validate(value)
        self.calls.append(name)


@dataclass(frozen=True)
class AATOutcome:
    condition: str
    account_id: str
    task_id: str
    status: str
    terminal_contract: dict[str, Any]
    parser_output: dict[str, Any] | None
    report_id: str | None
    report_sha256: str | None
    semantic_sha256: str | None
    ui_body_sha256: str | None
    html_body_sha256: str | None
    pdf_sha256: str | None
    ledger: tuple[dict[str, Any], ...]
    task_states: tuple[str, ...]
    resource_owner_consistent: bool


class FrozenAATPositioningEngine:
    """Known-case adapter for Gate 0 integration, never a Gate 1 system."""

    def __init__(self, fact_snapshot: dict[str, Any]) -> None:
        self.fact_snapshot = fact_snapshot

    def run(self, task_id: str, extraction: dict[str, Any], fail: bool = False) -> dict[str, Any]:
        if fail:
            raise RuntimeError("synthetic engine failure")
        anchors = extraction["academic_anchors"]
        required = {"accessibility", "basin", "transport", "coarse-graining"}
        if not required.issubset(anchors):
            raise ValueError("AAT academic anchors are incomplete")
        return {
            "contract_version": "1.0",
            "task_id": task_id,
            "status": "completed",
            "report": {
                "paper_profile": {
                    "question": "How does basin-to-basin transport emerge in adaptive landscape dynamics, and does it remain coherent under coarse-graining?",
                    "contribution_shape": "A mesoscale accessibility observable that distinguishes occupancy from sustained transport during adaptive reorganization.",
                    "method": "Agent-based simulation, effective density-field description, basin flux, hysteresis, operator-stability, finite-size, null, and shuffle checks.",
                    "evidence_shape": "A bounded computational model with an operator-stable transition band and controls; no empirical biological validation.",
                    "uncertainty": "BioSystems is not a canonical fit; it is the strongest measured submission interface among sampled conversations, contingent on the frozen evidence set.",
                },
                "community_map": [
                    "BioSystems / biological organization",
                    "Metastability / Coarse-Graining",
                    "Landscape Navigation",
                    "Adaptive Dynamics",
                ],
                "candidate_venues": [
                    {
                        "venue_id": "venue_biosystems",
                        "venue_name": "BioSystems",
                        "positive_evidence": [
                            "The manuscript uses adaptive organization framing and an agent-based model-to-observable workflow.",
                            "The frozen scope accepts theoretical and computational studies of biological organization and complex biological systems.",
                        ],
                        "negative_evidence": [
                            "The current citation roots are only weakly aligned with the venue conversation.",
                            "The manuscript does not provide empirical biological grounding.",
                        ],
                        "uncertainty": "moderate",
                        "validated_coverage": True,
                    }
                ],
                "not_recommended": [
                    {
                        "venue_id": "venue_physica_a",
                        "venue_name": "Physica A",
                        "positive_evidence": ["The paper uses transition, coarse-graining, and statistical-mechanical language."],
                        "negative_evidence": ["The current contribution does not supply the statistical-mechanical depth expected by that framing."],
                        "uncertainty": "moderate",
                        "validated_coverage": False,
                    },
                    {
                        "venue_id": "venue_strict_adaptive_dynamics",
                        "venue_name": "Strict adaptive-dynamics venue",
                        "positive_evidence": ["Mutation, selection, and competition are part of the mechanism."],
                        "negative_evidence": ["The manuscript is not a complete adaptive-dynamics treatment based on invasion fitness or singular strategies."],
                        "uncertainty": "high",
                        "validated_coverage": False,
                    },
                ],
                "positioning_risks": [
                    "Readers may mistake a transport observable for a universal transition theory.",
                    "The bridge from the minimal model to biological organization remains conceptual rather than empirical.",
                    "A fitted threshold alone is insufficient without temporal, ordering, and structural diagnostics.",
                ],
                "positioning_actions": [
                    "Use a light alignment pass focused on vocabulary, citations, introduction, discussion, and cover letter.",
                    "Describe accessibility as a systems-level mesoscale observable separating occupancy from transport.",
                    "Keep results, figures, experiments, theory, and evidentiary claims unchanged.",
                ],
                "abstentions": [
                    "No acceptance-probability estimate.",
                    "No claim that BioSystems is the unique or natural home for the paper.",
                ],
                "coverage_limitations": [
                    "This Gate 0 golden adapter reproduces a known manual case and provides no Gate 1 generalization evidence.",
                    "Only communities sampled by the frozen 2026-06-30 mapping are compared.",
                ],
                "current_facts": copy.deepcopy(self.fact_snapshot["facts"]),
            },
            "versions": {
                "engine": ENGINE_VERSION,
                "protocol": PROTOCOL_VERSION,
                "knowledge_release": "kr_aat_manual_20260630",
                "fact_snapshot": self.fact_snapshot["snapshot_id"],
                "report_schema": "positioning-diagnostic-1.0",
            },
            "metering": {
                "provider_cost_minor_units": 250,
                "retrieval_cost_minor_units": 50,
                "allocated_variable_cost_minor_units": 400,
                "currency": "USD",
            },
        }


class AATGoldenHarness:
    def __init__(self, root: Path, database_dir: Path) -> None:
        self.root = root
        self.registry = ContractRegistry(root / "contracts" / "v1")
        self.namespace = NamespaceStore(b"aat-golden-namespace-signing-key-v1")
        self.raw = RawAuditStore(database_dir / "raw.sqlite")
        self.presentations = PresentationStore(database_dir / "presentations.sqlite")
        canonicalizer = ResultCanonicalizer(root / "contracts" / "v1" / "diagnostic-result.schema.json")
        self.report_service = ReportService(canonicalizer, self.raw, self.presentations)
        self.application = ReportApplication(self.presentations, SafeReportRenderer())
        snapshot = json.loads((root / "fixtures" / "aat" / "FACT_SNAPSHOT_v1.json").read_text())
        self.engine = FrozenAATPositioningEngine(snapshot)
        self.parser = IsolatedParser(Path(sys.executable))
        self._completed: dict[tuple[str, str], AATOutcome] = {}

    def _task_event(self, machine: DiagnosticStateMachine, task_id: str, to_state: str) -> None:
        key = f"idem_state_{task_id[5:]}_{len(machine.transitions) + 1:02d}"
        transition = machine.transition(to_state, key)
        event = {
            "contract_version": "1.0",
            "event_id": f"evt_task_{task_id[5:]}_{transition.sequence:02d}",
            "task_id": task_id,
            "sequence": transition.sequence,
            "from_state": transition.from_state,
            "to_state": transition.to_state,
            "occurred_at": FIXED_TIME,
            "idempotency_key": key,
        }
        self.registry.validate("task-event.schema.json", event)

    def _settle(self, ledger: SettlementLedger, task_id: str, action: Action, amount: int) -> None:
        key = f"idem_payment_{task_id[5:]}_{action.value}_{len(ledger.entries) + 1:02d}"
        entry = ledger.record(action, amount, key)
        event = {
            "contract_version": "1.0",
            "event_id": f"evt_pay_{task_id[5:]}_{entry.sequence:02d}",
            "task_id": task_id,
            "payment_attempt_id": f"pay_attempt_{task_id[5:]}",
            "sequence": entry.sequence,
            "action": entry.action.value,
            "amount_minor_units": entry.amount_minor_units,
            "currency": entry.currency,
            "occurred_at": FIXED_TIME,
            "idempotency_key": entry.idempotency_key,
        }
        self.registry.validate("settlement-event.schema.json", event)

    def _start(self, account_id: str, condition: str, source: Path) -> tuple[Any, Any, Any, Any]:
        document = self.namespace.create(account_id, ResourceType.DOCUMENT)
        diagnostic = self.namespace.create(account_id, ResourceType.DIAGNOSTIC)
        self.namespace.bind_diagnostic(account_id, diagnostic.resource_id, document.resource_id)
        task = {
            "contract_version": "1.0",
            "task_id": diagnostic.resource_id,
            "task_type": "paper_positioning_diagnostic",
            "idempotency_key": f"idem_aat_{condition}_request_0001",
            "input": {
                "document_id": document.resource_id,
                "document_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "language": "en",
                "candidate_venues": ["venue_biosystems", "venue_physica_a"],
                "decision_constraints": {"priority": "fit", "target_date": None, "notes": "AAT Gate 0 golden case"},
            },
            "authorization": {"estimate_id": f"est_aat_{condition}_001", "maximum_billable_minor_units": 500, "currency": "USD"},
        }
        self.registry.validate("diagnostic-task.schema.json", task)
        machine = DiagnosticStateMachine()
        ledger = SettlementLedger("USD")
        for state in ("awaiting_input", "estimated", "payment_authorized", "queued"):
            self._task_event(machine, diagnostic.resource_id, state)
        self._settle(ledger, diagnostic.resource_id, Action.AUTHORIZE, 500)
        return document, diagnostic, task, (machine, ledger)

    @staticmethod
    def _extract(parser_output: dict[str, Any]) -> dict[str, Any]:
        text = str(parser_output["text"])
        lower = text.lower()
        anchors = {term for term in ("accessibility", "basin", "transport", "coarse-graining") if term in lower}
        return {
            "title": "Mesoscopic Accessibility, Basin Transport, and Memory in Adaptive Landscape Systems",
            "academic_anchors": anchors,
            "untrusted_instruction_detected": ATTACK_MARKER in text,
            "parser_warnings": list(parser_output["warnings"]),
        }

    @staticmethod
    def _ledger(ledger: SettlementLedger) -> tuple[dict[str, Any], ...]:
        return tuple(
            {"sequence": item.sequence, "action": item.action.value, "amount_minor_units": item.amount_minor_units, "currency": item.currency, "idempotency_key": item.idempotency_key}
            for item in ledger.entries
        )

    def run_success(self, account_id: str, condition: str, source: Path, request_key: str) -> AATOutcome:
        cache_key = (account_id, request_key)
        if cache_key in self._completed:
            return self._completed[cache_key]
        document, diagnostic, task, state = self._start(account_id, condition, source)
        machine, ledger = state
        self._task_event(machine, task["task_id"], "parsing")
        parsed = self.parser.parse(source)
        self.registry.validate("parser-output.schema.json", parsed)
        if parsed["status"] != "accepted":
            raise RuntimeError(f"golden manuscript rejected: {parsed['error_code']}")
        parser_resource = self.namespace.create(account_id, ResourceType.PARSER_OUTPUT, diagnostic.resource_id)
        self.namespace.get(account_id, parser_resource.resource_id)
        extraction = self._extract(parsed)
        self._task_event(machine, task["task_id"], "analyzing")
        result = self.engine.run(task["task_id"], extraction)
        self._task_event(machine, task["task_id"], "verifying_facts")
        self._task_event(machine, task["task_id"], "awaiting_human_review")
        record = self.report_service.ingest_model_result(account_id, result)
        report_resource = self.namespace.create(account_id, ResourceType.REPORT, diagnostic.resource_id)
        review_resource = self.namespace.create(account_id, ResourceType.HUMAN_REVIEW, report_resource.resource_id)
        self.namespace.get(account_id, review_resource.resource_id)
        reviewed = self.report_service.save_human_review(account_id, record.report_id, result)
        self.registry.validate("diagnostic-result.schema.json", reviewed.canonical_result)
        self._task_event(machine, task["task_id"], "completed")
        self._settle(ledger, task["task_id"], Action.CAPTURE, 400)
        capture = ledger.entries[-1]
        if ledger.record(Action.CAPTURE, 400, capture.idempotency_key) is not capture:
            raise RuntimeError("capture replay did not resolve to the original event")
        self._settle(ledger, task["task_id"], Action.RELEASE, 100)
        html_paths = {
            name: route(account_id, reviewed.report_id)
            for name, route in self.application.routes.items()
            if name != "pdf_export"
        }
        bodies = {name: value.split("<body>", 1)[1].rsplit("</body>", 1)[0] for name, value in html_paths.items()}
        pdf = self.application.export_pdf(account_id, reviewed.report_id)
        self.namespace.create(account_id, ResourceType.EXPORT, report_resource.resource_id)
        owners = [document, diagnostic, parser_resource, report_resource, review_resource]
        outcome = AATOutcome(
            condition=condition,
            account_id=account_id,
            task_id=task["task_id"],
            status="completed",
            terminal_contract=reviewed.canonical_result,
            parser_output=parsed,
            report_id=reviewed.report_id,
            report_sha256=canonical_sha256(reviewed.canonical_result["report"]),
            semantic_sha256=reviewed.semantic_sha256,
            ui_body_sha256=hashlib.sha256(bodies["ui"].encode()).hexdigest(),
            html_body_sha256=hashlib.sha256(bodies["html_export"].encode()).hexdigest(),
            pdf_sha256=hashlib.sha256(pdf).hexdigest(),
            ledger=self._ledger(ledger),
            task_states=tuple(item.to_state for item in machine.transitions),
            resource_owner_consistent=all(item.owner_account_id == account_id for item in owners),
        )
        if len(set(bodies.values())) != 1:
            raise RuntimeError("presentation paths diverged")
        self._completed[cache_key] = outcome
        return outcome

    def run_failure(self, account_id: str, condition: str, source: Path, mode: str) -> AATOutcome:
        before = self.presentations.count()
        _, diagnostic, task, state = self._start(account_id, condition, source)
        machine, ledger = state
        parser_output = None
        if mode == "cancel":
            self._task_event(machine, task["task_id"], "cancelled")
            self._settle(ledger, task["task_id"], Action.RELEASE, 500)
            terminal = {"contract_version": "1.0", "task_id": task["task_id"], "status": "cancelled", "requested_at": FIXED_TIME, "effective_at": FIXED_TIME, "settlement": {"action": "release_authorization", "billable_minor_units": 0, "currency": "USD"}}
            contract = "diagnostic-cancellation.schema.json"
        elif mode == "timeout":
            self._task_event(machine, task["task_id"], "timed_out")
            self._settle(ledger, task["task_id"], Action.RELEASE, 500)
            terminal = {"contract_version": "1.0", "task_id": task["task_id"], "status": "timed_out", "deadline_at": FIXED_TIME, "error": {"code": "TASK_DEADLINE_EXCEEDED", "public_message": "The diagnostic exceeded its deadline.", "retryable": True}, "settlement": {"action": "release_authorization", "billable_minor_units": 0, "currency": "USD"}}
            contract = "diagnostic-timeout.schema.json"
        else:
            self._task_event(machine, task["task_id"], "parsing")
            parser_output = self.parser.parse(source)
            self.registry.validate("parser-output.schema.json", parser_output)
            if mode == "parser_reject":
                if parser_output["status"] != "rejected":
                    raise RuntimeError("parser-rejection fixture was accepted")
                self._task_event(machine, task["task_id"], "rejected_input")
                code = "UNSUPPORTED_DOCUMENT"
                status = "rejected_input"
                message = "The uploaded document type is not supported."
            elif mode == "engine_failure":
                if parser_output["status"] != "accepted":
                    raise RuntimeError("engine-failure fixture did not reach the engine")
                self._task_event(machine, task["task_id"], "analyzing")
                try:
                    self.engine.run(task["task_id"], self._extract(parser_output), fail=True)
                except RuntimeError:
                    pass
                self._task_event(machine, task["task_id"], "failed")
                code = "INTERNAL_ERROR"
                status = "failed"
                message = "The diagnostic could not be completed."
            else:
                raise ValueError(f"unknown failure mode: {mode}")
            self._settle(ledger, task["task_id"], Action.RELEASE, 500)
            terminal = {"contract_version": "1.0", "task_id": task["task_id"], "status": status, "error": {"code": code, "public_message": message, "retryable": mode == "engine_failure"}, "settlement": {"action": "release_authorization", "billable_minor_units": 0, "currency": "USD"}}
            contract = "diagnostic-failure.schema.json"
        self.registry.validate(contract, terminal)
        if self.presentations.count() != before:
            raise RuntimeError("failure path left a deliverable report")
        return AATOutcome(condition, account_id, task["task_id"], terminal["status"], terminal, parser_output, None, None, None, None, None, None, self._ledger(ledger), tuple(item.to_state for item in machine.transitions), True)

    def reject_cross_account_binding(self, owner_account: str, attacker_account: str) -> bool:
        document = self.namespace.create(owner_account, ResourceType.DOCUMENT)
        attacker_task = self.namespace.create(attacker_account, ResourceType.DIAGNOSTIC)
        before_reports = self.presentations.count()
        try:
            self.namespace.bind_diagnostic(attacker_account, attacker_task.resource_id, document.resource_id)
        except ResourceNotFound:
            return self.presentations.count() == before_reports
        return False


def fidelity_checks(report: dict[str, Any], spec: dict[str, Any]) -> dict[str, bool]:
    serialized = json.dumps(report, ensure_ascii=False).lower()
    biosystems = report["candidate_venues"][0]
    return {
        "paper_profile": all(term.lower() in serialized for term in spec["required"]["paper_profile_terms"]),
        "communities": all(item in report["community_map"] for item in spec["required"]["communities"]),
        "candidate_venues": all(item in {venue["venue_id"] for venue in report["candidate_venues"]} for item in spec["required"]["candidate_venue_ids"]),
        "positive_evidence": all(term.lower() in json.dumps(biosystems["positive_evidence"]).lower() for term in spec["required"]["biosystems_positive_terms"]),
        "negative_evidence": all(term.lower() in json.dumps(biosystems["negative_evidence"]).lower() for term in spec["required"]["biosystems_negative_terms"]),
        "positioning_actions": all(term.lower() in json.dumps(report["positioning_actions"]).lower() for term in spec["required"]["positioning_action_terms"]),
        "uncertainty": all(term.lower() in serialized for term in spec["required"]["uncertainty_terms"]),
        "forbidden_absent": all(term.lower() not in serialized for term in spec["must_not_appear"]),
    }
