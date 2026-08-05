from __future__ import annotations

import unittest

from gate0.settlement import Action, SettlementError, SettlementLedger


class SettlementTests(unittest.TestCase):
    def authorized_ledger(self, amount: int = 500) -> SettlementLedger:
        ledger = SettlementLedger(currency="USD")
        ledger.record(Action.AUTHORIZE, amount, "authorize-1")
        return ledger

    def test_replayed_provider_operation_does_not_double_charge(self) -> None:
        ledger = self.authorized_ledger()
        first = ledger.record(Action.CAPTURE, 400, "capture-1")
        replay = ledger.record(Action.CAPTURE, 400, "capture-1")
        self.assertIs(first, replay)
        self.assertEqual(400, ledger.captured)
        self.assertEqual(2, len(ledger.entries))

    def test_second_capture_with_new_key_is_rejected(self) -> None:
        ledger = self.authorized_ledger()
        ledger.record(Action.CAPTURE, 300, "capture-1")
        with self.assertRaises(SettlementError):
            ledger.record(Action.CAPTURE, 100, "capture-2")

    def test_capture_cannot_exceed_authorization(self) -> None:
        ledger = self.authorized_ledger()
        with self.assertRaises(SettlementError):
            ledger.record(Action.CAPTURE, 501, "capture-too-much")

    def test_partial_capture_releases_remainder_once(self) -> None:
        ledger = self.authorized_ledger()
        first = ledger.settle_success(320, "success-1")
        replay = ledger.settle_success(320, "success-1")
        self.assertEqual(first, replay)
        self.assertEqual(320, ledger.captured)
        self.assertEqual(180, ledger.released)
        self.assertEqual(3, len(ledger.entries))

    def test_internal_failure_before_capture_releases_authorization(self) -> None:
        ledger = self.authorized_ledger()
        first = ledger.settle_internal_failure("failure-1")
        replay = ledger.settle_internal_failure("failure-1")
        self.assertIs(first, replay)
        self.assertEqual(Action.RELEASE, first.action)
        self.assertEqual(500, ledger.released)
        self.assertEqual(0, ledger.captured)

    def test_internal_failure_after_capture_refunds_capture(self) -> None:
        ledger = self.authorized_ledger()
        ledger.record(Action.CAPTURE, 300, "capture-1")
        refund = ledger.settle_internal_failure("failure-1")
        self.assertEqual(Action.REFUND, refund.action)
        self.assertEqual(300, ledger.refunded)

    def test_conflicting_idempotency_key_is_rejected(self) -> None:
        ledger = self.authorized_ledger()
        with self.assertRaises(SettlementError):
            ledger.record(Action.AUTHORIZE, 400, "authorize-1")


if __name__ == "__main__":
    unittest.main()

