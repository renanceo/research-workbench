from __future__ import annotations

import unittest
import json
from pathlib import Path

from jsonschema import ValidationError

from gate0.output import (
    UnsafePublicOutput,
    render_plain_text,
    sanitize_report,
    validate_and_render_result,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_SCHEMA = ROOT / "contracts" / "v1" / "diagnostic-result.schema.json"
VALID_RESULT = ROOT / "fixtures" / "v1" / "valid" / "diagnostic-result.json"


class OutputSanitizationTests(unittest.TestCase):
    def test_active_html_and_svg_are_rendered_as_plain_text(self) -> None:
        attacks = [
            '<script>alert(1)</script>',
            '<img src=x onerror="alert(1)">',
            '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
            '<iframe src="data:text/html,evil"></iframe>',
            '<object data="https://evil.example"></object>',
            '<embed src="https://evil.example">',
            '<style>body{background:url(https://evil.example/x)}</style>',
        ]
        for attack in attacks:
            with self.subTest(attack=attack):
                rendered = render_plain_text(attack)
                self.assertNotIn("<script", rendered)
                self.assertNotIn("<svg", rendered)
                self.assertNotIn("<iframe", rendered)
                self.assertTrue(rendered.startswith("&lt;"))

    def test_markdown_and_dangerous_urls_do_not_become_links(self) -> None:
        for attack in (
            "[click](javascript:alert(1))",
            "[click](data:text/html,<script>alert(1)</script>)",
            "![remote](https://evil.example/track)",
            "<https://evil.example/track>",
        ):
            with self.subTest(attack=attack):
                rendered = render_plain_text(attack)
                self.assertNotIn("href=", rendered)
                self.assertNotIn("src=", rendered)

    def test_bidi_controls_internal_details_and_fake_notices_are_rejected(self) -> None:
        attacks = [
            "safe\u202etxt.exe",
            "Traceback: provider failed",
            "SYSTEM MESSAGE: payment succeeded",
            "read /srv/private/prompt.txt",
            "token sk-secretvalue12345",
            "bad\x00control",
        ]
        for attack in attacks:
            with self.subTest(attack=attack):
                with self.assertRaises(UnsafePublicOutput):
                    render_plain_text(attack)

    def test_extremely_large_output_is_rejected(self) -> None:
        with self.assertRaises(UnsafePublicOutput):
            render_plain_text("x" * 20_001)

    def test_nested_report_is_sanitized_without_mutating_structure(self) -> None:
        report = {"positioning_actions": ["Use <strong>clear evidence</strong>."], "score": 1}
        sanitized = sanitize_report(report)
        self.assertEqual(1, sanitized["score"])
        self.assertEqual(
            "Use &lt;strong&gt;clear evidence&lt;/strong&gt;.",
            sanitized["positioning_actions"][0],
        )

    def test_result_is_schema_validated_before_rendering(self) -> None:
        result = json.loads(VALID_RESULT.read_text())
        result["report"]["positioning_actions"] = ["Use <script>alert(1)</script> evidence."]
        rendered = validate_and_render_result(result, RESULT_SCHEMA)
        self.assertIn("&lt;script&gt;", rendered["report"]["positioning_actions"][0])

        result["report"]["unexpected_model_field"] = "looks harmless"
        with self.assertRaises(ValidationError):
            validate_and_render_result(result, RESULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
