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
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject


PARSER_VERSION = "isolated-parser-2.0"

# Byte markers are a fast first pass over uncompressed bytes only. Names that
# legitimate papers carry (hyperref's /OpenAction /GoTo and /URI link
# annotations) are not byte markers; they are judged structurally below, which
# also covers objects compressed inside object streams (/ObjStm).
ACTIVE_MARKERS = (b"/JavaScript", b"/JS ", b"/Launch")
ATTACHMENT_MARKERS = (b"/EmbeddedFile", b"/Filespec", b"/EmbeddedFiles")
EXTERNAL_MARKERS = (b"/GoToR", b"/SubmitForm", b"/ImportData")
EXTERNAL_FILE_REFERENCE = re.compile(
    rb"/(?:F|UF|DOS|Mac|Unix)\s*\((?:https?://|file:|\\\\)", re.IGNORECASE
)
WHITE_TEXT = re.compile(rb"(?:^|\s)(?:1(?:\.0+)?\s+){3}(?:rg|RG)\b[\s\S]{0,256}\bBT\b")
TEXT_SHOW = re.compile(rb"\(((?:\\.|[^\\)])*)\)\s*(?:Tj|['\"])")
ALLOWED_ACTIONS = {"/GoTo", "/URI"}
EXTERNAL_ACTIONS = {"/GoToR", "/GoToE", "/SubmitForm", "/ImportData"}
MAX_STRUCTURE_DEPTH = 64


def _action_violation(action: object) -> str | None:
    """Allow-list action types: in-document jumps and inert URI links only.

    A /URI link is kept as data and never followed: the parser has no fetch
    path and runs without network.
    """
    if not isinstance(action, DictionaryObject):
        return "UNSAFE_ACTIVE_CONTENT"
    kind = action.get("/S")
    if kind in ALLOWED_ACTIONS:
        return None
    if kind in EXTERNAL_ACTIONS:
        return "EXTERNAL_RESOURCE"
    return "UNSAFE_ACTIVE_CONTENT"


def _is_annotation(node: DictionaryObject) -> bool:
    return node.get("/Type") == "/Annot" or ("/Subtype" in node and "/Rect" in node)


def _structure_violation(node: object, depth: int = 0) -> str | None:
    """Reject code for an unsafe object and its direct children.

    Keys are only read where the PDF spec gives them a meaning (annotations,
    outline items, pages, form fields, actions, file specifications), because
    name-keyed dictionaries such as Type3 /CharProcs may use any key, e.g. a
    glyph named /A or /S. Action values are resolved through indirect
    references; every other indirect object, including those inside object
    streams, is visited on its own by structure_check.
    """
    if depth > MAX_STRUCTURE_DEPTH:
        return "DOCUMENT_PARSE_FAILED"
    if isinstance(node, DictionaryObject):
        kind = node.get("/Type")
        if kind in {"/EmbeddedFile", "/Filespec"} or ("/EF" in node and ("/F" in node or "/UF" in node)):
            return "EMBEDDED_ATTACHMENT"
        holds_actions = _is_annotation(node) or "/Title" in node or "/FT" in node or kind in {"/Page", "/Catalog"}
        if holds_actions and "/AA" in node:
            return "UNSAFE_ACTIVE_CONTENT"
        if kind == "/Action" or (isinstance(node.get("/S"), NameObject) and "/JS" in node):
            code = _action_violation(node)
            if code:
                return code
        if holds_actions and "/A" in node:
            code = _action_chain_violation(node["/A"])
            if code:
                return code
        children = node.values()
    elif isinstance(node, ArrayObject):
        children = node
    else:
        return None
    for child in children:
        if isinstance(child, IndirectObject):
            continue
        code = _structure_violation(child, depth + 1)
        if code:
            return code
    return None


def _action_chain_violation(action: object) -> str | None:
    """Check an action and everything it chains to through /Next."""
    pending = [action]
    seen = 0
    while pending:
        seen += 1
        if seen > MAX_STRUCTURE_DEPTH:
            return "UNSAFE_ACTIVE_CONTENT"
        current = pending.pop().get_object()
        if isinstance(current, ArrayObject):
            pending.extend(current)
            continue
        code = _action_violation(current)
        if code:
            return code
        if "/Next" in current:
            pending.append(current["/Next"])
    return None


def _open_action_violation(reader: PdfReader) -> str | None:
    """Only a page jump may run when the document opens."""
    action = reader.trailer["/Root"].get("/OpenAction")
    if action is None or isinstance(action.get_object(), ArrayObject):
        return None
    pending = [action]
    seen = 0
    while pending:
        seen += 1
        if seen > MAX_STRUCTURE_DEPTH:
            return "UNSAFE_ACTIVE_CONTENT"
        current = pending.pop().get_object()
        if isinstance(current, ArrayObject):
            pending.extend(current)
        elif current.get("/S") != "/GoTo":
            return "EXTERNAL_RESOURCE" if current.get("/S") == "/URI" else "UNSAFE_ACTIVE_CONTENT"
        elif "/Next" in current:
            pending.append(current["/Next"])
    return None


def structure_check(reader: PdfReader) -> str | None:
    """Inspect every object, so compressed object streams are covered too."""
    code = _open_action_violation(reader)
    if code:
        return code
    names = reader.trailer["/Root"].get("/Names")
    if names is not None:
        names = names.get_object()
        if "/JavaScript" in names:
            return "UNSAFE_ACTIVE_CONTENT"
        if "/EmbeddedFiles" in names:
            return "EMBEDDED_ATTACHMENT"
    object_numbers: set[tuple[int, int]] = set()
    for generation, entries in reader.xref.items():
        object_numbers.update((number, generation) for number in entries)
    object_numbers.update((number, 0) for number in reader.xref_objStm)
    for number, generation in sorted(object_numbers):
        obj = reader.get_object(IndirectObject(number, generation, reader))
        code = _structure_violation(obj)
        if code:
            return code
    return None


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
        structure_code = structure_check(reader)
        if structure_code:
            return reject(digest, structure_code)
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
        socket.create_connection(("192.0.2.1", 9), timeout=0.1)
    except PermissionError:
        return {"network_denied": True}
    except OSError as exc:
        if getattr(exc, "errno", None) in {1, 13, 51, 65, 101}:
            return {"network_denied": True}
        return {"network_denied": False, "error_type": type(exc).__name__}
    return {"network_denied": False}


def install_read_guard(roots: list[Path]) -> None:
    protected = [root.absolute() for root in roots]

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "open" or not arguments or not isinstance(arguments[0], (str, bytes)):
            return
        candidate = Path(arguments[0]).absolute()
        for root in protected:
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            raise PermissionError(f"parser read denied: {root}")

    sys.addaudithook(audit)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--probe-network", action="store_true")
    parser.add_argument("--probe-environment", action="store_true")
    parser.add_argument("--probe-read", type=Path)
    parser.add_argument("--forbid-read-root", action="append", type=Path, default=[])
    parser.add_argument("--max-file-bytes", type=int, default=20_000_000)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--max-page-points", type=int, default=20_000)
    parser.add_argument("--max-text-chars", type=int, default=1_000_000)
    parser.add_argument("--max-decoded-bytes", type=int, default=100_000_000)
    args = parser.parse_args()
    install_read_guard(args.forbid_read_root)

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
