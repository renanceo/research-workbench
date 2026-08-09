from __future__ import annotations

import unittest

from scripts.run_public_preview import build_preview


class PublicPreviewTests(unittest.TestCase):
    def test_preview_is_contract_valid_entirely_synthetic_and_offline(self) -> None:
        preview = build_preview()
        self.assertEqual("public_research_preview", preview["preview_kind"])
        self.assertEqual(0, preview["network_requests"])
        self.assertEqual(0, preview["real_manuscripts_processed"])
        self.assertFalse(preview["model_strategy"]["actual_model_call"])
        self.assertIsNone(preview["model_strategy"]["provider_route"])
        self.assertTrue(all(preview["checks"].values()))
        self.assertFalse(preview["gate1_performance_claim"])
        self.assertFalse(preview["real_manuscript_diagnostic_available"])
        self.assertFalse(preview["paid_use_available"])


if __name__ == "__main__":
    unittest.main()
