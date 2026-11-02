"""Human permission gates G0–G7.

No gate offers "always". A timeout, a closed prompt, an exception or an invalid
answer is ``undecided``, never approval. G0 and G6 are dangerous. Only an
interactive local session in auto mode may auto-approve G0; G6 always waits.
G5 (a finding's final status) is never decided by code or by auto mode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Gate(str, Enum):
    """The gated steps of a review session."""

    G0_SESSION = "G0"
    G1_PLAN = "G1"
    G2_SCAN = "G2"
    G3_TRIAGE = "G3"
    G4_INVESTIGATE = "G4"
    G5_FINDING = "G5"
    G6_FIX = "G6"
    G7_RESCAN = "G7"


CHOICES: dict[Gate, tuple[str, ...]] = {
    Gate.G0_SESSION: ("approve", "reject"),
    Gate.G1_PLAN: ("approve", "edit", "reject"),
    Gate.G2_SCAN: ("approve", "edit", "reject"),
    Gate.G3_TRIAGE: ("approve", "edit", "reject"),
    Gate.G4_INVESTIGATE: ("approve", "edit", "reject"),
    Gate.G5_FINDING: ("confirm", "reject", "need_more"),
    Gate.G6_FIX: ("apply", "reject", "defer"),
    Gate.G7_RESCAN: ("approve", "edit", "reject"),
}

DANGEROUS = frozenset({Gate.G0_SESSION, Gate.G6_FIX})
HUMAN_STATUS = frozenset({Gate.G5_FINDING})
MODES = ("ask", "auto")

_APPROVALS = frozenset({"approve", "edit", "confirm", "apply"})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class GateRequest:
    """What the human is asked to decide."""

    gate: Gate
    title: str
    detail: str
    payload: dict[str, Any] = field(default_factory=dict)
    ai_recommendation: str = ""


@dataclass
class GateDecision:
    """The human's answer. Only ``choice`` carries authority."""

    gate: Gate
    choice: str
    reason: str = ""
    edits: dict[str, Any] = field(default_factory=dict)
    person: str = ""
    at: str = field(default_factory=_now_iso)

    @property
    def approved(self) -> bool:
        return self.choice in _APPROVALS


Asker = Callable[[GateRequest], GateDecision]


def refuse_all(request: GateRequest) -> GateDecision:
    """Asker for non-interactive runs: every gate stays undecided."""
    return GateDecision(
        request.gate,
        "undecided",
        "non-interactive run: no human to ask",
    )


def _auto_local_g0(request: GateRequest, mode: str, interactive: bool) -> bool:
    return (
        request.gate is Gate.G0_SESSION
        and mode == "auto"
        and interactive
        and request.payload.get("local") is True
        and request.payload.get("code_leaves_machine") is False
    )


class GateKeeper:
    """Ask the human before a gated step and record every decision."""

    def __init__(
        self,
        asker: Asker,
        record: Callable[[dict[str, Any]], None],
        person: str = "",
        mode: str = "ask",
        interactive: bool = False,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"unsupported gate mode: {mode!r}")
        self.asker = asker
        self.record = record
        self.person = person
        self.mode = mode
        self.interactive = interactive

    def ask(self, request: GateRequest) -> GateDecision:
        decision = self._decide(request)
        self.record(
            {
                "type": "gate",
                "gate": request.gate.value,
                "title": request.title,
                "payload": request.payload,
                "ai_recommendation": request.ai_recommendation,
                "choice": decision.choice,
                "reason": decision.reason,
                "edits": decision.edits,
                "person": decision.person,
                "mode": self.mode,
                "at": decision.at,
            }
        )
        return decision

    def _decide(self, request: GateRequest) -> GateDecision:
        if _auto_local_g0(request, self.mode, self.interactive):
            return GateDecision(request.gate, "approve", "local provider, auto mode", person="auto")
        if self.mode == "auto":
            if request.gate in HUMAN_STATUS:
                return GateDecision(
                    request.gate,
                    "undecided",
                    "auto mode: awaiting human /review",
                    person="auto",
                )
            if request.gate not in DANGEROUS:
                return GateDecision(request.gate, CHOICES[request.gate][0], person="auto")
        return self._ask(request)

    def _ask(self, request: GateRequest) -> GateDecision:
        try:
            decision = self.asker(request)
        except (EOFError, KeyboardInterrupt):
            return GateDecision(request.gate, "undecided", "prompt closed", person=self.person)
        except Exception as exc:  # noqa: BLE001 - a broken asker must not approve
            return GateDecision(
                request.gate,
                "undecided",
                f"prompt failed: {exc}",
                person=self.person,
            )
        if decision.choice != "undecided" and decision.choice not in CHOICES[request.gate]:
            return GateDecision(
                request.gate,
                "undecided",
                f"invalid choice: {decision.choice}",
                person=decision.person or self.person,
            )
        if not decision.person:
            decision.person = self.person
        if decision.gate is not request.gate:
            decision.gate = request.gate
        return decision


__all__ = [
    "CHOICES",
    "DANGEROUS",
    "HUMAN_STATUS",
    "MODES",
    "Asker",
    "Gate",
    "GateDecision",
    "GateKeeper",
    "GateRequest",
    "refuse_all",
]
