from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from pypdf import PdfReader

from gate0.report_pipeline import (
    AuditAccessDenied,
    AuditPrincipal,
    ContentPolicyError,
    HTML_RENDERER_VERSION,
    PDF_EXPORTER_VERSION,
    REPORT_PIPELINE_VERSION,
    SANITIZER_VERSION,
    PresentationStore,
    RawAuditStore,
    ReportApplication,
    ReportService,
    ResultCanonicalizer,
    SafeReportRenderer,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_SCHEMA = ROOT / "contracts" / "v1" / "diagnostic-result.schema.json"
VALID_RESULT = ROOT / "fixtures" / "v1" / "valid" / "diagnostic-result.json"
ATTACKS = ROOT / "fixtures" / "report-security" / "ATTACKS_v1.json"


class SecurityHTMLParser(HTMLParser):
    allowed_tags = {"html", "head", "meta", "title", "body", "dl", "dt", "dd", "ol", "li", "a", "br"}

    def __init__(self) -> None:
        super().__init__()
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in self.allowed_tags:
            self.errors.append(f"disallowed tag: {tag}")
        for name, value in attrs:
            if name.lower().startswith("on") or name.lower() in {"style", "srcdoc"}:
                self.errors.append(f"disallowed attribute: {name}")
            if name == "href":
                parsed = urlsplit(value or "")
                if parsed.scheme != "https" or not parsed.hostname:
                    self.errors.append("disallowed link scheme")


def body(document: str) -> str:
    return document.split("<body>", 1)[1].rsplit("</body>", 1)[0]


class ReportPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rw-report-security-")
        directory = Path(self.temp.name)
        self.raw_store = RawAuditStore(directory / "raw-audit.sqlite")
        self.presentation_store = PresentationStore(directory / "presentation.sqlite")
        self.canonicalizer = ResultCanonicalizer(RESULT_SCHEMA)
        self.service = ReportService(self.canonicalizer, self.raw_store, self.presentation_store)
        self.renderer = SafeReportRenderer()
        self.application = ReportApplication(self.presentation_store, self.renderer)
        self.valid = json.loads(VALID_RESULT.read_text())
        self.attacks = json.loads(ATTACKS.read_text())
        self.account = "acct_report_security"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def with_action(self, value: str) -> dict:
        result = copy.deepcopy(self.valid)
        result["report"]["positioning_actions"] = [value]
        return result

    def assert_no_persistence(self) -> None:
        self.assertEqual(0, self.raw_store.count())
        self.assertEqual(0, self.presentation_store.count())

    def assert_safe_html(self, document: str) -> None:
        parser = SecurityHTMLParser()
        parser.feed(document)
        self.assertEqual([], parser.errors)
        self.assertIn("default-src 'none'", document)

    def test_schema_rejects_unknown_fields_and_wrong_types_before_persistence(self) -> None:
        unknown = copy.deepcopy(self.valid)
        unknown["report"]["debug_raw_output"] = "secret"
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, unknown)
        self.assert_no_persistence()

        wrong_type = copy.deepcopy(self.valid)
        wrong_type["report"]["candidate_venues"] = "not-an-array"
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, wrong_type)
        self.assert_no_persistence()

    def test_resource_limits_reject_array_depth_recursion_and_strings_before_persistence(self) -> None:
        oversized_array = copy.deepcopy(self.valid)
        oversized_array["report"]["positioning_actions"] = ["x"] * 101
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, oversized_array)

        deep: dict = {}
        cursor = deep
        for _ in range(25):
            cursor["next"] = {}
            cursor = cursor["next"]
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, deep)

        recursive: dict = {}
        recursive["self"] = recursive
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, recursive)

        oversized_string = self.with_action("x" * 20_001)
        with self.assertRaises(ContentPolicyError):
            self.service.ingest_model_result(self.account, oversized_string)
        self.assert_no_persistence()

    def test_raw_audit_and_presentation_are_separate_and_access_controlled(self) -> None:
        record = self.service.ingest_model_result(self.account, self.valid)
        self.assertNotEqual(self.raw_store.database_path, self.presentation_store.database_path)
        self.assertNotIn("raw", record.canonical_result)
        self.assertEqual("plain_text", record.content_mode)
        self.assertEqual(SANITIZER_VERSION, record.sanitizer_version)
        self.assertNotEqual(record.raw_sha256, record.semantic_sha256)

        ordinary = AuditPrincipal(self.account, "human_reviewer")
        with self.assertRaises(AuditAccessDenied):
            self.raw_store.ids(ordinary)

        auditor = AuditPrincipal(self.account, "security_auditor")
        audit_ids = self.raw_store.ids(auditor)
        self.assertEqual(1, len(audit_ids))
        self.assertEqual(self.valid, self.raw_store.read(auditor, audit_ids[0]))

    def test_all_web_and_export_paths_render_attacks_inert(self) -> None:
        for attack in self.attacks["render_inert"]:
            with self.subTest(attack=attack["id"]):
                record = self.service.ingest_model_result(self.account, self.with_action(attack["value"]))
                documents = [
                    self.application.render_ui(self.account, record.report_id),
                    self.application.render_human_review(self.account, record.report_id),
                    self.application.render_admin(self.account, record.report_id),
                    self.application.export_html(self.account, record.report_id),
                ]
                for document in documents:
                    self.assert_safe_html(document)
                self.assertEqual(1, len({body(document) for document in documents}))

                pdf = self.application.export_pdf(self.account, record.report_id)
                self.assertNotIn(b"/JavaScript", pdf)
                self.assertNotIn(b"/OpenAction", pdf)
                self.assertNotIn(b"/URI", pdf)
                self.assertTrue(PdfReader(io.BytesIO(pdf), strict=True).pages)

    def test_rejected_semantic_attacks_never_persist(self) -> None:
        for attack in self.attacks["reject"]:
            with self.subTest(attack=attack["id"]):
                with self.assertRaises((ContentPolicyError, ValueError)):
                    self.service.ingest_model_result(self.account, self.with_action(attack["value"]))
        self.assert_no_persistence()

    def test_source_links_use_https_allowlist_and_safe_attributes(self) -> None:
        record = self.service.ingest_model_result(self.account, self.valid)
        document = self.application.render_ui(self.account, record.report_id)
        self.assert_safe_html(document)
        self.assertIn('rel="nofollow noopener noreferrer"', document)

        for url in (
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://publisher.example/scope",
            "https://user:password@publisher.example/scope",
            "https://publisher.example/" + "x" * 2_100,
        ):
            with self.subTest(url=url[:40]):
                result = copy.deepcopy(self.valid)
                result["report"]["current_facts"][0]["source_url"] = url
                with self.assertRaises(ContentPolicyError):
                    self.service.ingest_model_result(self.account, result)

    def test_human_review_reenters_validation_and_cannot_recontaminate(self) -> None:
        record = self.service.ingest_model_result(self.account, self.valid)
        malicious_edit = self.with_action("<script>humanReviewAttack()</script>")
        updated = self.service.save_human_review(self.account, record.report_id, malicious_edit)
        self.assertEqual(2, updated.version)
        self.assert_safe_html(self.application.render_human_review(self.account, record.report_id))
        self.assert_safe_html(self.application.export_html(self.account, record.report_id))

        rejected_edit = self.with_action("Read /srv/private/prompt.txt")
        with self.assertRaises((ContentPolicyError, ValueError)):
            self.service.save_human_review(self.account, record.report_id, rejected_edit)
        self.assertEqual(2, self.presentation_store.get(self.account, record.report_id).version)

        changed_task = copy.deepcopy(self.valid)
        changed_task["task_id"] = "diag_other001"
        raw_count = self.raw_store.count()
        with self.assertRaises(ContentPolicyError):
            self.service.save_human_review(self.account, record.report_id, changed_task)
        self.assertEqual(raw_count, self.raw_store.count())

    def test_same_payload_has_same_safe_semantics_across_paths_and_resave(self) -> None:
        payload = self.with_action("</dd><script>differential()</script><dd>")
        record = self.service.ingest_model_result(self.account, payload)
        initial_hash = record.semantic_sha256
        documents = {
            name: route(self.account, record.report_id)
            for name, route in self.application.routes.items()
            if name != "pdf_export"
        }
        self.assertEqual(1, len({body(document) for document in documents.values()}))

        updated = self.service.save_human_review(self.account, record.report_id, payload)
        self.assertEqual(initial_hash, updated.semantic_sha256)
        self.assertEqual(body(documents["ui"]), body(self.application.export_html(self.account, record.report_id)))
        self.assertEqual(
            self.application.export_pdf(self.account, record.report_id),
            self.application.export_pdf(self.account, record.report_id),
        )

    def test_no_product_route_exposes_raw_or_debug_output(self) -> None:
        self.assertEqual(
            {"ui", "human_review", "admin", "html_export", "pdf_export"},
            set(self.application.routes),
        )
        self.assertFalse(any("raw" in route or "debug" in route for route in self.application.routes))

    def test_security_component_versions_are_frozen(self) -> None:
        self.assertEqual("report-pipeline-1.0", REPORT_PIPELINE_VERSION)
        self.assertEqual("plain-text-sanitizer-1.0", SANITIZER_VERSION)
        self.assertEqual("safe-html-renderer-1.0", HTML_RENDERER_VERSION)
        self.assertEqual("safe-pdf-exporter-1.0", PDF_EXPORTER_VERSION)


if __name__ == "__main__":
    unittest.main()
