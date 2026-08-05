from __future__ import annotations

import unittest

from gate0.state_machine import DiagnosticStateMachine, InvalidTransition


class StateMachineTests(unittest.TestCase):
    def test_happy_path_is_ordered_and_append_only(self) -> None:
        machine = DiagnosticStateMachine()
        path = [
            "awaiting_input",
            "estimated",
            "payment_authorized",
            "queued",
            "parsing",
            "analyzing",
            "verifying_facts",
            "awaiting_human_review",
            "completed",
        ]
        for index, state in enumerate(path, start=1):
            event = machine.transition(state, f"transition-{index}")
            self.assertEqual(index, event.sequence)
        self.assertEqual("completed", machine.state)

    def test_immediate_replay_is_idempotent(self) -> None:
        machine = DiagnosticStateMachine()
        first = machine.transition("awaiting_input", "same-key")
        replay = machine.transition("awaiting_input", "same-key")
        self.assertIs(first, replay)
        self.assertEqual(1, len(machine.transitions))

    def test_key_reuse_for_later_transition_is_rejected(self) -> None:
        machine = DiagnosticStateMachine()
        machine.transition("awaiting_input", "used-key")
        machine.transition("estimated", "second-key")
        with self.assertRaises(InvalidTransition):
            machine.transition("payment_authorized", "used-key")

    def test_immediate_key_reuse_with_different_target_is_rejected(self) -> None:
        machine = DiagnosticStateMachine()
        machine.transition("awaiting_input", "used-key")
        with self.assertRaises(InvalidTransition):
            machine.transition("estimated", "used-key")

    def test_cancellation_after_irreversible_execution_is_rejected(self) -> None:
        machine = DiagnosticStateMachine()
        for index, state in enumerate(
            ["awaiting_input", "estimated", "payment_authorized", "queued", "parsing"],
            start=1,
        ):
            machine.transition(state, f"key-{index}")
        with self.assertRaises(InvalidTransition):
            machine.transition("cancelled", "late-cancel")

    def test_timeout_is_terminal(self) -> None:
        machine = DiagnosticStateMachine()
        for index, state in enumerate(
            ["awaiting_input", "estimated", "payment_authorized", "queued", "parsing", "analyzing"],
            start=1,
        ):
            machine.transition(state, f"key-{index}")
        machine.transition("timed_out", "deadline")
        with self.assertRaises(InvalidTransition):
            machine.transition("analyzing", "resume")


if __name__ == "__main__":
    unittest.main()
