from __future__ import annotations

import html
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


MAX_PUBLIC_TEXT_CHARS = 20_000
BIDI_CONTROLS = frozenset(chr(code) for code in range(0x202A, 0x202F)) | frozenset(
    chr(code) for code in range(0x2066, 0x206A)
)
SENSITIVE_PATTERNS = (
    re.compile(r"(?:^|\s)(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?:^|\s)/(?:Users|home|srv|var/lib|private)/\S+"),
    re.compile(r"[A-Za-z]:\\(?:Users|Windows|ProgramData)\\", re.IGNORECASE),
    re.compile(r"^\s*(?:SYSTEM(?: MESSAGE)?|DEVELOPER(?: MESSAGE)?|TRACEBACK)\s*[:\[]", re.IGNORECASE),
)


class UnsafePublicOutput(ValueError):
    pass


def validate_public_text(value: str) -> None:
    if len(value) > MAX_PUBLIC_TEXT_CHARS:
        raise UnsafePublicOutput("public text exceeds size limit")
    if any(character in BIDI_CONTROLS for character in value):
        raise UnsafePublicOutput("bidirectional control character is not allowed")
    for character in value:
        category = unicodedata.category(character)
        if category == "Cc" and character not in "\n\r\t":
            raise UnsafePublicOutput("control character is not allowed")
    if any(pattern.search(value) for pattern in SENSITIVE_PATTERNS):
        raise UnsafePublicOutput("sensitive or internal content is not allowed")


def render_plain_text(value: str) -> str:
    validate_public_text(value)
    return html.escape(value, quote=True).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>\n")


def sanitize_report(value: Any) -> Any:
    if isinstance(value, str):
        return render_plain_text(value)
    if isinstance(value, Mapping):
        return {key: sanitize_report(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [sanitize_report(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise UnsafePublicOutput(f"unsupported output type: {type(value).__name__}")


def validate_and_render_result(result: Mapping[str, Any], schema_path: Path) -> dict[str, Any]:
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(schema).validate(result)
    rendered = dict(result)
    rendered["report"] = sanitize_report(result["report"])
    return rendered
