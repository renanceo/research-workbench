from __future__ import annotations

from dataclasses import dataclass, field


TERMINAL_STATES = frozenset(
    {
        "completed",
        "rejected_input",
        "cancelled",
        "timed_out",
        "failed",
        "payment_failed",
        "expired",
    }
)

ALLOWED_TRANSITIONS = {
    "draft": {"awaiting_input", "cancelled"},
    "awaiting_input": {"estimated", "rejected_input", "cancelled", "expired"},
    "estimated": {"payment_authorized", "payment_failed", "cancelled", "expired"},
    "payment_authorized": {"queued", "payment_failed", "cancelled", "expired"},
    "queued": {"parsing", "cancelled", "timed_out", "failed"},
    "parsing": {"analyzing", "rejected_input", "timed_out", "failed"},
    "analyzing": {"verifying_facts", "awaiting_human_review", "timed_out", "failed"},
    "verifying_facts": {"awaiting_human_review", "timed_out", "failed"},
    "awaiting_human_review": {"completed", "payment_failed", "timed_out", "failed"},
}


class InvalidTransition(ValueError):
    pass


@dataclass(frozen=True)
class Transition:
    sequence: int
    from_state: str
    to_state: str
    idempotency_key: str


@dataclass
class DiagnosticStateMachine:
    state: str = "draft"
    transitions: list[Transition] = field(default_factory=list)
    _seen: dict[str, Transition] = field(default_factory=dict, init=False)

    def transition(self, to_state: str, idempotency_key: str) -> Transition:
        if not idempotency_key:
            raise ValueError("idempotency_key is required")

        prior = self._seen.get(idempotency_key)
        if prior is not None:
            if prior.to_state != to_state or prior.to_state != self.state:
                raise InvalidTransition("idempotency key was reused for another transition")
            return prior

        if self.state in TERMINAL_STATES:
            raise InvalidTransition(f"terminal state {self.state!r} cannot transition")
        if to_state not in ALLOWED_TRANSITIONS.get(self.state, set()):
            raise InvalidTransition(f"transition {self.state!r} -> {to_state!r} is not allowed")

        event = Transition(
            sequence=len(self.transitions) + 1,
            from_state=self.state,
            to_state=to_state,
            idempotency_key=idempotency_key,
        )
        self.transitions.append(event)
        self._seen[idempotency_key] = event
        self.state = to_state
        return event
