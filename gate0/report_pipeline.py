from __future__ import annotations

import copy
import hashlib
import html
import io
import json
import secrets
import sqlite3
import textwrap
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from reportlab.pdfgen import canvas

from gate0.output import UnsafePublicOutput, validate_public_text


REPORT_PIPELINE_VERSION = "report-pipeline-1.0"
SANITIZER_VERSION = "plain-text-sanitizer-1.0"
HTML_RENDERER_VERSION = "safe-html-renderer-1.0"
PDF_EXPORTER_VERSION = "safe-pdf-exporter-1.0"


class ContentPolicyError(ValueError):
    pass


class ReportNotFound(LookupError):
    pass


class AuditAccessDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ContentLimits:
    max_depth: int = 20
    max_nodes: int = 5_000
    max_array_items: int = 100
    max_object_properties: int = 100
    max_string_chars: int = 20_000
    max_total_string_chars: int = 250_000
    max_url_chars: int = 2_048
    max_pdf_bytes: int = 5_000_000


@dataclass(frozen=True)
class AuditPrincipal:
    account_id: str
    role: str


@dataclass(frozen=True)
class PresentationRecord:
    report_id: str
    account_id: str
    task_id: str
    version: int
    content_mode: str
    sanitizer_version: str
    canonical_result: dict[str, Any]
    semantic_sha256: str
    raw_sha256: str


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _guard_structure(value: Any, limits: ContentLimits) -> None:
    seen: set[int] = set()
    nodes = 0
    total_string_chars = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, total_string_chars
        nodes += 1
        if nodes > limits.max_nodes:
            raise ContentPolicyError("report node budget exceeded")
        if depth > limits.max_depth:
            raise ContentPolicyError("report nesting depth exceeded")
        if isinstance(item, str):
            if len(item) > limits.max_string_chars:
                raise ContentPolicyError("report string budget exceeded")
            total_string_chars += len(item)
            if total_string_chars > limits.max_total_string_chars:
                raise ContentPolicyError("report total text budget exceeded")
            return
        if item is None or isinstance(item, (bool, int, float)):
            return
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in seen:
                raise ContentPolicyError("recursive report structure is not allowed")
            seen.add(identity)
            if len(item) > limits.max_object_properties:
                raise ContentPolicyError("report object property budget exceeded")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ContentPolicyError("report object keys must be strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
            seen.remove(identity)
            return
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            identity = id(item)
            if identity in seen:
                raise ContentPolicyError("recursive report structure is not allowed")
            seen.add(identity)
            if len(item) > limits.max_array_items:
                raise ContentPolicyError("report array item budget exceeded")
            for child in item:
                visit(child, depth + 1)
            seen.remove(identity)
            return
        raise ContentPolicyError(f"unsupported report value type: {type(item).__name__}")

    visit(value, 0)


def _validate_public_values(value: Any, limits: ContentLimits, key: str | None = None) -> None:
    if isinstance(value, str):
        validate_public_text(value)
        if key == "source_url":
            parsed = urlsplit(value)
            if (
                len(value) > limits.max_url_chars
                or parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise UnsafePublicOutput("source URL is not renderable")
        return
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            _validate_public_values(child, limits, child_key)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_public_values(child, limits, key)


def _normalize_public_values(value: Any) -> Any:
    if isinstance(value, str):
        normalized = value.replace("\r\n", "\n").replace("\r", "\n")
        return unicodedata.normalize("NFC", normalized)
    if isinstance(value, Mapping):
        return {key: _normalize_public_values(child) for key, child in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize_public_values(child) for child in value]
    return value


class ResultCanonicalizer:
    def __init__(self, schema_path: Path, limits: ContentLimits | None = None) -> None:
        self.schema_path = schema_path
        self.limits = limits or ContentLimits()
        self.validator = Draft202012Validator(
            json.loads(schema_path.read_text()),
            format_checker=FormatChecker(),
        )

    def canonicalize(self, untrusted: Mapping[str, Any]) -> tuple[dict[str, Any], str, str]:
        _guard_structure(untrusted, self.limits)
        errors = sorted(self.validator.iter_errors(untrusted), key=lambda error: repr(list(error.path)))
        if errors:
            raise ContentPolicyError(f"report schema rejected payload: {errors[0].message}")
        canonical = _normalize_public_values(copy.deepcopy(dict(untrusted)))
        try:
            _validate_public_values(canonical, self.limits)
        except UnsafePublicOutput as error:
            raise ContentPolicyError("report semantic policy rejected payload") from error
        raw_bytes = _canonical_json(untrusted)
        presentation_envelope = {
            "content_mode": "plain_text",
            "sanitizer_version": SANITIZER_VERSION,
            "result": canonical,
        }
        canonical_bytes = _canonical_json(presentation_envelope)
        return (
            canonical,
            hashlib.sha256(raw_bytes).hexdigest(),
            hashlib.sha256(canonical_bytes).hexdigest(),
        )


class RawAuditStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.connection = sqlite3.connect(database_path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS raw_audit (
                audit_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_json BLOB NOT NULL,
                raw_sha256 TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def append(self, account_id: str, source: str, raw_result: Mapping[str, Any]) -> tuple[str, str]:
        payload = _canonical_json(raw_result)
        digest = hashlib.sha256(payload).hexdigest()
        audit_id = f"audit_{secrets.token_urlsafe(18)}"
        self.connection.execute(
            "INSERT INTO raw_audit VALUES (?, ?, ?, ?, ?)",
            (audit_id, account_id, source, payload, digest),
        )
        self.connection.commit()
        return audit_id, digest

    def read(self, principal: AuditPrincipal, audit_id: str) -> dict[str, Any]:
        if principal.role != "security_auditor":
            raise AuditAccessDenied("raw audit access denied")
        row = self.connection.execute(
            "SELECT account_id, raw_json FROM raw_audit WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if row is None or row[0] != principal.account_id:
            raise AuditAccessDenied("raw audit access denied")
        return json.loads(row[1])

    def ids(self, principal: AuditPrincipal) -> list[str]:
        if principal.role != "security_auditor":
            raise AuditAccessDenied("raw audit access denied")
        rows = self.connection.execute(
            "SELECT audit_id FROM raw_audit WHERE account_id = ? ORDER BY rowid",
            (principal.account_id,),
        ).fetchall()
        return [row[0] for row in rows]

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM raw_audit").fetchone()[0])


class PresentationStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.connection = sqlite3.connect(database_path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS presentations (
                report_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                content_mode TEXT NOT NULL,
                sanitizer_version TEXT NOT NULL,
                canonical_json BLOB NOT NULL,
                semantic_sha256 TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def create(
        self,
        account_id: str,
        canonical_result: dict[str, Any],
        semantic_sha256: str,
        raw_sha256: str,
    ) -> PresentationRecord:
        report_id = f"report_{secrets.token_urlsafe(18)}"
        task_id = canonical_result["task_id"]
        self.connection.execute(
            "INSERT INTO presentations VALUES (?, ?, ?, 1, 'plain_text', ?, ?, ?, ?)",
            (
                report_id,
                account_id,
                task_id,
                SANITIZER_VERSION,
                _canonical_json(canonical_result),
                semantic_sha256,
                raw_sha256,
            ),
        )
        self.connection.commit()
        return self.get(account_id, report_id)

    def replace(
        self,
        account_id: str,
        report_id: str,
        canonical_result: dict[str, Any],
        semantic_sha256: str,
        raw_sha256: str,
    ) -> PresentationRecord:
        prior = self.get(account_id, report_id)
        if canonical_result["task_id"] != prior.task_id:
            raise ContentPolicyError("human review cannot change task identity")
        self.connection.execute(
            """UPDATE presentations
               SET version = ?, content_mode = 'plain_text', sanitizer_version = ?, canonical_json = ?, semantic_sha256 = ?, raw_sha256 = ?
               WHERE report_id = ? AND account_id = ?""",
            (
                prior.version + 1,
                SANITIZER_VERSION,
                _canonical_json(canonical_result),
                semantic_sha256,
                raw_sha256,
                report_id,
                account_id,
            ),
        )
        self.connection.commit()
        return self.get(account_id, report_id)

    def get(self, account_id: str, report_id: str) -> PresentationRecord:
        row = self.connection.execute(
            """SELECT account_id, task_id, version, content_mode, sanitizer_version, canonical_json, semantic_sha256, raw_sha256
               FROM presentations WHERE report_id = ? AND account_id = ?""",
            (report_id, account_id),
        ).fetchone()
        if row is None:
            raise ReportNotFound("report not found")
        return PresentationRecord(
            report_id=report_id,
            account_id=row[0],
            task_id=row[1],
            version=row[2],
            content_mode=row[3],
            sanitizer_version=row[4],
            canonical_result=json.loads(row[5]),
            semantic_sha256=row[6],
            raw_sha256=row[7],
        )

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM presentations").fetchone()[0])


class ReportService:
    def __init__(
        self,
        canonicalizer: ResultCanonicalizer,
        raw_audit: RawAuditStore,
        presentations: PresentationStore,
    ) -> None:
        self.canonicalizer = canonicalizer
        self._raw_audit = raw_audit
        self.presentations = presentations

    def ingest_model_result(self, account_id: str, untrusted: Mapping[str, Any]) -> PresentationRecord:
        canonical, raw_sha256, semantic_sha256 = self.canonicalizer.canonicalize(untrusted)
        _, stored_raw_sha256 = self._raw_audit.append(account_id, "model", untrusted)
        if stored_raw_sha256 != raw_sha256:
            raise RuntimeError("raw audit hash mismatch")
        return self.presentations.create(
            account_id,
            canonical,
            semantic_sha256,
            raw_sha256,
        )

    def save_human_review(
        self,
        account_id: str,
        report_id: str,
        untrusted_edit: Mapping[str, Any],
    ) -> PresentationRecord:
        prior = self.presentations.get(account_id, report_id)
        canonical, raw_sha256, semantic_sha256 = self.canonicalizer.canonicalize(untrusted_edit)
        if canonical["task_id"] != prior.task_id:
            raise ContentPolicyError("human review cannot change task identity")
        _, stored_raw_sha256 = self._raw_audit.append(account_id, "human_review", untrusted_edit)
        if stored_raw_sha256 != raw_sha256:
            raise RuntimeError("raw audit hash mismatch")
        return self.presentations.replace(
            account_id,
            report_id,
            canonical,
            semantic_sha256,
            raw_sha256,
        )


class SafeReportRenderer:
    def __init__(self, limits: ContentLimits | None = None) -> None:
        self.limits = limits or ContentLimits()

    def _render_value(self, value: Any, key: str | None = None) -> str:
        if isinstance(value, str):
            escaped = html.escape(value, quote=True).replace("\n", "<br>\n")
            if key == "source_url":
                parsed = urlsplit(value)
                if parsed.scheme != "https" or not parsed.hostname or len(value) > self.limits.max_url_chars:
                    raise UnsafePublicOutput("unsafe link reached renderer")
                return (
                    f'<a href="{html.escape(value, quote=True)}" '
                    'rel="nofollow noopener noreferrer">'
                    f"{escaped}</a>"
                )
            return escaped
        if isinstance(value, Mapping):
            parts = ["<dl>"]
            for child_key, child in value.items():
                parts.append(f"<dt>{html.escape(str(child_key))}</dt>")
                parts.append(f"<dd>{self._render_value(child, str(child_key))}</dd>")
            parts.append("</dl>")
            return "".join(parts)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return "<ol>" + "".join(f"<li>{self._render_value(item, key)}</li>" for item in value) + "</ol>"
        return html.escape(json.dumps(value))

    def fragment(self, canonical_result: Mapping[str, Any]) -> str:
        _guard_structure(canonical_result, self.limits)
        _validate_public_values(canonical_result, self.limits)
        return self._render_value(canonical_result)

    def document(self, canonical_result: Mapping[str, Any], title: str) -> str:
        fragment = self.fragment(canonical_result)
        policy = "default-src 'none'; img-src 'none'; style-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
        return (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
            f"<title>{html.escape(title)}</title></head><body>{fragment}</body></html>"
        )

    def semantic_lines(self, canonical_result: Mapping[str, Any]) -> list[str]:
        serialized = json.dumps(canonical_result, ensure_ascii=False, sort_keys=True, indent=2)
        lines: list[str] = []
        for source_line in serialized.splitlines():
            lines.extend(textwrap.wrap(source_line, width=60, replace_whitespace=False) or [""])
        return lines

    def pdf(self, canonical_result: Mapping[str, Any]) -> bytes:
        _guard_structure(canonical_result, self.limits)
        _validate_public_values(canonical_result, self.limits)
        buffer = io.BytesIO()
        document = canvas.Canvas(buffer, pagesize=(612, 792), invariant=1, pageCompression=1)
        document.setTitle("Paper Positioning Diagnostic")
        y = 756
        for line in self.semantic_lines(canonical_result):
            if y < 36:
                document.showPage()
                y = 756
            document.setFont("Helvetica", 9)
            document.drawString(36, y, line)
            y -= 12
        document.save()
        payload = buffer.getvalue()
        if len(payload) > self.limits.max_pdf_bytes:
            raise ContentPolicyError("PDF export size budget exceeded")
        return payload


class ReportApplication:
    def __init__(self, presentations: PresentationStore, renderer: SafeReportRenderer) -> None:
        self.presentations = presentations
        self.renderer = renderer
        self.routes = {
            "ui": self.render_ui,
            "human_review": self.render_human_review,
            "admin": self.render_admin,
            "html_export": self.export_html,
            "pdf_export": self.export_pdf,
        }

    def _record(self, account_id: str, report_id: str) -> PresentationRecord:
        record = self.presentations.get(account_id, report_id)
        if record.content_mode != "plain_text":
            raise ContentPolicyError("unsupported presentation content mode")
        if record.sanitizer_version != SANITIZER_VERSION:
            raise ContentPolicyError("unsupported presentation sanitizer version")
        return record

    def render_ui(self, account_id: str, report_id: str) -> str:
        return self.renderer.document(self._record(account_id, report_id).canonical_result, "Report")

    def render_human_review(self, account_id: str, report_id: str) -> str:
        return self.renderer.document(self._record(account_id, report_id).canonical_result, "Human review")

    def render_admin(self, account_id: str, report_id: str) -> str:
        return self.renderer.document(self._record(account_id, report_id).canonical_result, "Admin report")

    def export_html(self, account_id: str, report_id: str) -> str:
        return self.renderer.document(self._record(account_id, report_id).canonical_result, "Report export")

    def export_pdf(self, account_id: str, report_id: str) -> bytes:
        return self.renderer.pdf(self._record(account_id, report_id).canonical_result)
