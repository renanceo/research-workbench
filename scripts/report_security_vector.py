from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gate0.report_pipeline import (
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


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_text(value: str) -> str:
    return digest_bytes(value.encode("utf-8"))


def body(document: str) -> str:
    return document.split("<body>", 1)[1].rsplit("</body>", 1)[0]


def main() -> None:
    valid = json.loads((ROOT / "fixtures" / "v1" / "valid" / "diagnostic-result.json").read_text())
    attacks = json.loads((ROOT / "fixtures" / "report-security" / "ATTACKS_v1.json").read_text())
    attack = next(item for item in attacks["render_inert"] if item["id"] == "RS-009-export-differential")
    valid["report"]["positioning_actions"] = [attack["value"]]

    with tempfile.TemporaryDirectory(prefix="rw-report-vector-") as temp_name:
        directory = Path(temp_name)
        raw_store = RawAuditStore(directory / "raw.sqlite")
        presentation_store = PresentationStore(directory / "presentation.sqlite")
        service = ReportService(
            ResultCanonicalizer(ROOT / "contracts" / "v1" / "diagnostic-result.schema.json"),
            raw_store,
            presentation_store,
        )
        application = ReportApplication(presentation_store, SafeReportRenderer())
        record = service.ingest_model_result("acct_vector", valid)

        ui = application.render_ui("acct_vector", record.report_id)
        review = application.render_human_review("acct_vector", record.report_id)
        admin = application.render_admin("acct_vector", record.report_id)
        html_export = application.export_html("acct_vector", record.report_id)
        pdf_export = application.export_pdf("acct_vector", record.report_id)

        updated = service.save_human_review("acct_vector", record.report_id, valid)
        resaved_html = application.export_html("acct_vector", record.report_id)
        body_hashes = {
            "ui": digest_text(body(ui)),
            "human_review": digest_text(body(review)),
            "admin": digest_text(body(admin)),
            "html_export": digest_text(body(html_export)),
            "human_resave": digest_text(body(resaved_html)),
        }
        result = {
            "vector_id": "report-security-vector-1.0",
            "attack_fixture_id": attack["id"],
            "versions": {
                "pipeline": REPORT_PIPELINE_VERSION,
                "sanitizer": SANITIZER_VERSION,
                "html_renderer": HTML_RENDERER_VERSION,
                "pdf_exporter": PDF_EXPORTER_VERSION,
                "schema": "positioning-diagnostic-1.0",
            },
            "hashes": {
                "raw_output": record.raw_sha256,
                "canonical_semantic": record.semantic_sha256,
                "ui_document": digest_text(ui),
                "human_review_document": digest_text(review),
                "admin_document": digest_text(admin),
                "html_export": digest_text(html_export),
                "pdf_export": digest_bytes(pdf_export),
                "human_resave_semantic": updated.semantic_sha256,
                "human_resave_html": digest_text(resaved_html),
                "safe_body_by_path": body_hashes,
            },
            "assertions": {
                "semantic_equal_after_human_resave": record.semantic_sha256 == updated.semantic_sha256,
                "raw_and_sanitized_hashes_are_distinct": record.raw_sha256 != record.semantic_sha256,
                "safe_body_equal_across_all_paths": len(set(body_hashes.values())) == 1,
                "pdf_has_no_active_content": not any(
                    marker in pdf_export for marker in (b"/JavaScript", b"/OpenAction", b"/URI")
                ),
                "raw_and_presentation_databases_separate": raw_store.database_path != presentation_store.database_path,
                "script_not_executable_in_html": "<script>" not in body(ui),
            },
        }
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
