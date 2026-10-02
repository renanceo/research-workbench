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
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NumberObject


PARSER_VERSION = "isolated-parser-2.1"

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
    kind = _action_kind(action)
    if kind in ALLOWED_ACTIONS:
        return None
    if kind in EXTERNAL_ACTIONS:
        return "EXTERNAL_RESOURCE"
    return "UNSAFE_ACTIVE_CONTENT"


# Dictionaries whose keys are arbitrary names chosen by the producer (glyph
# names in Type3 /CharProcs, resource names, named destinations), so a key
# such as /A, /AA or /JS inside them is a name, not an action. Only the map
# itself is exempt; its values are still checked.
NAME_KEYED = {
    "/CharProcs", "/Font", "/XObject", "/ExtGState", "/ColorSpace", "/Pattern",
    "/Shading", "/Properties", "/Dests", "/RoleMap", "/ClassMap",
}
# Annotations that carry a file or play media; their content is never needed for text.
BLOCKED_ANNOTATIONS = {"/FileAttachment", "/Sound", "/Movie", "/Screen", "/RichMedia", "/3D"}


def _is_structure_attributes(value: object) -> bool:
    """Tagged-PDF structure elements use /A for attribute objects, not actions.

    An attribute object names its owner with /O; an action always has /S.
    Attribute arrays may interleave revision numbers.
    """
    value = value.get_object()
    items = value if isinstance(value, ArrayObject) else [value]
    for item in items:
        item = item.get_object()
        if isinstance(item, NumberObject) and isinstance(value, ArrayObject):
            continue
        if not isinstance(item, DictionaryObject) or "/O" not in item or "/S" in item:
            return False
    return True


def _dictionary_violation(node: DictionaryObject) -> str | None:
    """Default-deny reading of one dictionary's own keys, whatever its /Type.

    Field and annotation types can be inherited or omitted, and /S can be an
    indirect reference, so nothing here depends on the dictionary declaring
    what it is.
    """
    if "/JS" in node or "/AA" in node:
        return "UNSAFE_ACTIVE_CONTENT"
    kind = _resolved(node, "/Type")
    if kind in {"/EmbeddedFile", "/Filespec"} or "/EF" in node:
        return "EMBEDDED_ATTACHMENT"
    if _resolved(node, "/Subtype") in BLOCKED_ANNOTATIONS:
        return "EMBEDDED_ATTACHMENT"
    if "/FS" in node:
        return "EXTERNAL_RESOURCE"
    if kind == "/Action":
        code = _action_violation(node)
        if code:
            return code
    for key in ("/A", "/PA"):
        if key in node and not _is_structure_attributes(node[key]):
            code = _action_chain_violation(node[key])
            if code:
                return code
    return None


def _structure_violation(node: object, name_keyed: bool = False, depth: int = 0) -> str | None:
    """Reject code for an object and its direct (non-referenced) children.

    Every indirect object, including those inside object streams, is visited
    on its own by structure_check, which also decides whether it is a name map.
    """
    if depth > MAX_STRUCTURE_DEPTH:
        return "DOCUMENT_PARSE_FAILED"
    if isinstance(node, DictionaryObject):
        if not name_keyed:
            code = _dictionary_violation(node)
            if code:
                return code
        children = [(key, value) for key, value in node.items()]
    elif isinstance(node, ArrayObject):
        children = [(None, value) for value in node]
    else:
        return None
    for key, child in children:
        if isinstance(child, IndirectObject):
            continue
        code = _structure_violation(child, not name_keyed and key in NAME_KEYED, depth + 1)
        if code:
            return code
    return None


def _references(node: object, uses: dict[int, set[bool]], name_keyed: bool = False, depth: int = 0) -> None:
    """Record, per referenced object, whether each reference is from a name-map slot."""
    if depth > MAX_STRUCTURE_DEPTH:
        return
    if isinstance(node, DictionaryObject):
        items = [(key, value) for key, value in node.items()]
    elif isinstance(node, ArrayObject):
        items = [(None, value) for value in node]
    else:
        return
    for key, child in items:
        child_name_keyed = not name_keyed and key in NAME_KEYED
        if isinstance(child, IndirectObject):
            uses.setdefault(child.idnum, set()).add(child_name_keyed)
        else:
            _references(child, uses, child_name_keyed, depth + 1)


def _resolved(node: DictionaryObject, key: str) -> object:
    value = node.get(key)
    return None if value is None else value.get_object()


def _action_kind(action: object) -> object:
    return _resolved(action, "/S") if isinstance(action, DictionaryObject) else None


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
        elif _action_kind(current) != "/GoTo":
            return "EXTERNAL_RESOURCE" if _action_kind(current) == "/URI" else "UNSAFE_ACTIVE_CONTENT"
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
    objects = [
        reader.get_object(IndirectObject(number, generation, reader))
        for number, generation in sorted(object_numbers)
    ]
    uses: dict[int, set[bool]] = {}
    _references(reader.trailer, uses)
    for obj in objects:
        _references(obj, uses)
    for (number, _), obj in zip(sorted(object_numbers), objects):
        # A map is exempt only if every reference to it is from a name-map slot.
        code = _structure_violation(obj, uses.get(number) == {True})
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
