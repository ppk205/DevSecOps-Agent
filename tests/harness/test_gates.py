"""Permission gate tests: modes, dangerous gates, and the decision log."""

from __future__ import annotations

from typing import Any

import pytest

from vulnscan.harness.gates import CHOICES, Gate, GateDecision, GateKeeper, GateRequest


def keeper(mode: str, answers: list[Any]) -> tuple[GateKeeper, list[Gate], list[dict[str, Any]]]:
    asked: list[Gate] = []
    log: list[dict[str, Any]] = []

    def asker(req: GateRequest) -> GateDecision:
        asked.append(req.gate)
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return GateDecision(req.gate, answer)

    return GateKeeper(asker, log.append, person="tester", mode=mode), asked, log


def req(g: Gate) -> GateRequest:
    return GateRequest(g, "t", "d")


def test_ask_mode_asks_every_gate() -> None:
    k, asked, _ = keeper("ask", ["approve"] * 8)
    for g in Gate:
        k.ask(req(g))
    assert asked == list(Gate)


def test_auto_mode_approves_routine_gates_as_auto() -> None:
    k, asked, log = keeper("auto", [])
    for g in (Gate.G1_PLAN, Gate.G2_SCAN, Gate.G3_TRIAGE, Gate.G4_INVESTIGATE, Gate.G7_RESCAN):
        d = k.ask(req(g))
        assert d.approved and d.person == "auto"
    assert asked == [] and all(e["mode"] == "auto" for e in log)


@pytest.mark.parametrize("gate,answer", [(Gate.G0_SESSION, "approve"), (Gate.G6_FIX, "apply")])
def test_auto_mode_still_asks_dangerous_gates(gate: Gate, answer: str) -> None:
    k, asked, _ = keeper("auto", [answer])
    assert k.ask(req(gate)).approved and asked == [gate]


def test_auto_mode_defers_finding_status() -> None:
    k, asked, _ = keeper("auto", [])
    d = k.ask(req(Gate.G5_FINDING))
    assert d.choice == "undecided" and not d.approved and asked == []


@pytest.mark.parametrize("exc", [EOFError(), KeyboardInterrupt()])
def test_closed_prompt_is_undecided(exc: BaseException) -> None:
    k, _, _ = keeper("auto", [exc])
    d = k.ask(req(Gate.G6_FIX))
    assert d.choice == "undecided" and not d.approved


def test_invalid_choice_is_undecided() -> None:
    k, _, _ = keeper("ask", ["always"])
    assert k.ask(req(Gate.G2_SCAN)).choice == "undecided"


def test_no_gate_offers_always() -> None:
    assert all("always" not in c for c in CHOICES.values())


def test_every_decision_is_recorded() -> None:
    k, _, log = keeper("ask", ["reject"])
    k.ask(GateRequest(Gate.G1_PLAN, "plan", "d", {"scope": ["**/*.java"]}, "approve"))
    assert log[0]["gate"] == "G1" and log[0]["choice"] == "reject" and log[0]["person"] == "tester"
    assert set(log[0]) >= {
        "type",
        "title",
        "payload",
        "ai_recommendation",
        "reason",
        "edits",
        "mode",
        "at",
    }
