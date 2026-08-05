from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sys
from pathlib import Path

from pypdf import PdfReader


ACTIVE_MARKERS = (b"/JavaScript", b"/JS ", b"/Launch", b"/OpenAction", b"/AA ")
ATTACHMENT_MARKERS = (b"/EmbeddedFile", b"/Filespec", b"/EmbeddedFiles")
EXTERNAL_MARKERS = (b"/URI", b"/GoToR", b"/SubmitForm", b"/ImportData")
EXTERNAL_FILE_REFERENCE = re.compile(
    rb"/(?:F|UF|DOS|Mac|Unix)\s*\((?:https?://|file:|\\\\)", re.IGNORECASE
)
WHITE_TEXT = re.compile(rb"(?:^|\s)(?:1(?:\.0+)?\s+){3}(?:rg|RG)\b[\s\S]{0,256}\bBT\b")
TEXT_SHOW = re.compile(rb"\(((?:\\.|[^\\)])*)\)\s*(?:Tj|['\"])")


def result(document_hash: str, status: str, **values: object) -> dict[str, object]:
    return {
        "schema_version": "parser-output-1.0",
        "status": status,
        "document_sha256": document_hash,
        "page_count": values.get("page_count", 0),
        "text": values.get("text", ""),
        "warnings": values.get("warnings", []),
        "error_code": values.get("error_code"),
    }


def reject(document_hash: str, code: str) -> dict[str, object]:
    return result(document_hash, "rejected", error_code=code)


def parse_pdf(path: Path, args: argparse.Namespace) -> dict[str, object]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > args.max_file_bytes:
        return reject(digest, "INPUT_TOO_LARGE")
    if not raw.startswith(b"%PDF-"):
        return reject(digest, "UNSUPPORTED_DOCUMENT")
    if any(marker in raw for marker in ACTIVE_MARKERS):
        return reject(digest, "UNSAFE_ACTIVE_CONTENT")
    if any(marker in raw for marker in ATTACHMENT_MARKERS):
        return reject(digest, "EMBEDDED_ATTACHMENT")
    if any(marker in raw for marker in EXTERNAL_MARKERS) or EXTERNAL_FILE_REFERENCE.search(raw):
        return reject(digest, "EXTERNAL_RESOURCE")

    try:
        reader = PdfReader(path, strict=True)
        if reader.is_encrypted:
            return reject(digest, "UNSUPPORTED_DOCUMENT")
        if len(reader.pages) > args.max_pages:
            return reject(digest, "PAGE_LIMIT_EXCEEDED")

        extracted: list[str] = []
        total_decoded = 0
        total_text = 0
        total_text_operator_bytes = 0
        for page in reader.pages:
            width = float(page.mediabox.width)
            height = float(page.mediabox.height)
            if width <= 0 or height <= 0 or width > args.max_page_points or height > args.max_page_points:
                return reject(digest, "PAGE_DIMENSION_EXCEEDED")
            contents = page.get_contents()
            if contents is not None:
                decoded = contents.get_data()
                total_decoded += len(decoded)
                if total_decoded > args.max_decoded_bytes:
                    return reject(digest, "DECOMPRESSION_LIMIT_EXCEEDED")
                total_text_operator_bytes += sum(
                    len(match.group(1)) for match in TEXT_SHOW.finditer(decoded)
                )
                if total_text_operator_bytes > args.max_text_chars:
                    return reject(digest, "TEXT_LIMIT_EXCEEDED")
            text = page.extract_text() or ""
            extracted.append(text)
            total_text += len(text)
            if total_text > args.max_text_chars:
                return reject(digest, "TEXT_LIMIT_EXCEEDED")
    except Exception:
        return reject(digest, "DOCUMENT_PARSE_FAILED")

    warnings: list[str] = []
    if WHITE_TEXT.search(raw):
        warnings.append("POSSIBLE_HIDDEN_TEXT")
    text = "\n\f\n".join(extracted)
    normalized = text.encode("utf-8", "replace").decode("utf-8")
    if normalized != text:
        warnings.append("MALFORMED_UNICODE_REPLACED")
    return result(
        digest,
        "accepted",
        page_count=len(reader.pages),
        text=normalized,
        warnings=sorted(set(warnings)),
    )


def network_probe() -> dict[str, object]:
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=0.1)
    except PermissionError:
        return {"network_denied": True}
    except OSError as exc:
        return {"network_denied": False, "error_type": type(exc).__name__}
    return {"network_denied": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--probe-network", action="store_true")
    parser.add_argument("--probe-environment", action="store_true")
    parser.add_argument("--probe-read", type=Path)
    parser.add_argument("--max-file-bytes", type=int, default=20_000_000)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--max-page-points", type=int, default=20_000)
    parser.add_argument("--max-text-chars", type=int, default=1_000_000)
    parser.add_argument("--max-decoded-bytes", type=int, default=100_000_000)
    args = parser.parse_args()

    if args.probe_network:
        payload = network_probe()
    elif args.probe_environment:
        payload = {"environment_keys": sorted(os.environ)}
    elif args.probe_read:
        try:
            args.probe_read.read_bytes()
        except PermissionError:
            payload = {"read_denied": True}
        except OSError as exc:
            payload = {"read_denied": False, "error_type": type(exc).__name__}
        else:
            payload = {"read_denied": False}
    elif args.input:
        payload = parse_pdf(args.input, args)
    else:
        payload = {"protocol_error": True}
    json.dump(payload, sys.stdout, separators=(",", ":"), ensure_ascii=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
