from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SettlementError(ValueError):
    pass


class Action(str, Enum):
    AUTHORIZE = "authorize"
    CAPTURE = "capture"
    RELEASE = "release"
    REFUND = "refund"


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    action: Action
    amount_minor_units: int
    currency: str
    idempotency_key: str


@dataclass
class SettlementLedger:
    currency: str
    entries: list[LedgerEntry] = field(default_factory=list)
    _seen: dict[str, LedgerEntry] = field(default_factory=dict, init=False)

    @property
    def authorized(self) -> int:
        return sum(e.amount_minor_units for e in self.entries if e.action == Action.AUTHORIZE)

    @property
    def captured(self) -> int:
        return sum(e.amount_minor_units for e in self.entries if e.action == Action.CAPTURE)

    @property
    def released(self) -> int:
        return sum(e.amount_minor_units for e in self.entries if e.action == Action.RELEASE)

    @property
    def refunded(self) -> int:
        return sum(e.amount_minor_units for e in self.entries if e.action == Action.REFUND)

    def record(self, action: Action, amount_minor_units: int, idempotency_key: str) -> LedgerEntry:
        if amount_minor_units < 0:
            raise SettlementError("amount cannot be negative")
        if not idempotency_key:
            raise SettlementError("idempotency_key is required")

        prior = self._seen.get(idempotency_key)
        if prior is not None:
            if prior.action != action or prior.amount_minor_units != amount_minor_units:
                raise SettlementError("idempotency key conflicts with an existing operation")
            return prior

        self._validate(action, amount_minor_units)
        entry = LedgerEntry(
            sequence=len(self.entries) + 1,
            action=action,
            amount_minor_units=amount_minor_units,
            currency=self.currency,
            idempotency_key=idempotency_key,
        )
        self.entries.append(entry)
        self._seen[idempotency_key] = entry
        return entry

    def _validate(self, action: Action, amount: int) -> None:
        if action == Action.AUTHORIZE:
            if self.entries:
                raise SettlementError("a task can have only one authorization")
            if amount == 0:
                raise SettlementError("authorization must be positive")
            return

        if self.authorized == 0:
            raise SettlementError("authorization is required before settlement")

        if action == Action.CAPTURE:
            if self.captured > 0:
                raise SettlementError("a task can have at most one capture")
            if amount == 0:
                raise SettlementError("capture must be positive")
            if amount > self.authorized - self.released:
                raise SettlementError("capture exceeds available authorization")
        elif action == Action.RELEASE:
            if self.released + amount > self.authorized - self.captured:
                raise SettlementError("release exceeds uncaptured authorization")
        elif action == Action.REFUND:
            if self.refunded + amount > self.captured:
                raise SettlementError("refund exceeds captured amount")

    def settle_success(self, final_amount: int, idempotency_prefix: str) -> tuple[LedgerEntry, ...]:
        capture = self.record(Action.CAPTURE, final_amount, f"{idempotency_prefix}:capture")
        remainder = self.authorized - self.captured - self.released
        entries = [capture]
        if remainder:
            entries.append(self.record(Action.RELEASE, remainder, f"{idempotency_prefix}:release"))
        elif release := self._seen.get(f"{idempotency_prefix}:release"):
            entries.append(release)
        return tuple(entries)

    def settle_internal_failure(self, idempotency_prefix: str) -> LedgerEntry:
        if self.captured:
            if prior := self._seen.get(f"{idempotency_prefix}:refund"):
                return prior
            refundable = self.captured - self.refunded
            return self.record(Action.REFUND, refundable, f"{idempotency_prefix}:refund")
        if prior := self._seen.get(f"{idempotency_prefix}:release"):
            return prior
        releasable = self.authorized - self.released
        return self.record(Action.RELEASE, releasable, f"{idempotency_prefix}:release")
