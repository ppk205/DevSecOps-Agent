"""Permission gate tests: modes, dangerous gates, and the decision log."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from tests.harness.conftest import scripted
from vulnscan.harness.console import console_asker
from vulnscan.harness.gates import CHOICES, Gate, GateDecision, GateKeeper, GateRequest, refuse_all


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


def test_invalid_console_edit_is_logged_as_undecided() -> None:
    log: list[dict[str, Any]] = []
    k = GateKeeper(console_asker(scripted(["e", "{broken"]), lambda _: None), log.append)
    decision = k.ask(GateRequest(Gate.G2_SCAN, "scan", "", {"globs": ["**/*"]}))
    assert decision.choice == "undecided" and not decision.approved
    assert log[0]["choice"] == "undecided" and log[0]["payload"] == {"globs": ["**/*"]}


@pytest.mark.parametrize("mode", ["ask", "auto"])
@pytest.mark.parametrize("local", [True, False])
@pytest.mark.parametrize("interactive", [True, False])
def test_local_g0_auto_matrix(mode: str, local: bool, interactive: bool) -> None:
    log: list[dict[str, Any]] = []
    gatekeeper = GateKeeper(refuse_all, log.append, mode=mode, interactive=interactive)
    decision = gatekeeper.ask(
        GateRequest(
            Gate.G0_SESSION, "Start", "", {"local": local, "code_leaves_machine": not local}
        )
    )
    expected = mode == "auto" and local and interactive
    assert decision.approved is expected
    assert (log[0]["person"] == "auto") is expected
    if expected:
        assert log[0]["reason"] == "local provider, auto mode"


@pytest.mark.parametrize(
    "payload",
    [
        {"local": "true", "code_leaves_machine": False},
        {"local": True},
        {"local": True, "code_leaves_machine": 0},
    ],
)
def test_local_g0_requires_explicit_boolean_payload(payload: dict[str, Any]) -> None:
    gatekeeper = GateKeeper(refuse_all, lambda _: None, mode="auto", interactive=True)
    assert not gatekeeper.ask(GateRequest(Gate.G0_SESSION, "Start", "", payload)).approved


def test_g6_never_auto_even_local_interactive() -> None:
    gatekeeper = GateKeeper(refuse_all, lambda _: None, mode="auto", interactive=True)
    request = GateRequest(Gate.G6_FIX, "Apply", "", {"local": True, "code_leaves_machine": False})
    assert not gatekeeper.ask(request).approved


def test_g7_accepts_explicit_human_edit() -> None:
    gatekeeper = GateKeeper(
        lambda request: GateDecision(request.gate, "edit", edits={"finding_id": "F2"}),
        lambda _: None,
    )
    decision = gatekeeper.ask(GateRequest(Gate.G7_RESCAN, "Rescan", ""))
    assert decision.choice == "edit" and decision.edits == {"finding_id": "F2"}


def test_explicit_undecided_preserves_reason() -> None:
    log = []
    gatekeeper = GateKeeper(
        lambda request: GateDecision(request.gate, "undecided", "confirmation word missing"),
        log.append,
    )
    decision = gatekeeper.ask(GateRequest(Gate.G6_FIX, "Apply", ""))
    assert not decision.approved
    assert decision.reason == log[0]["reason"] == "confirmation word missing"


def test_tui_button_table_matches_choices() -> None:
    source = (Path(__file__).resolve().parents[2] / "internal/chat/dialog.go").read_text(
        encoding="utf-8"
    )
    table = source.split("var buttonTable =", 1)[1].split("\n}", 1)[0]
    actual = {
        Gate(gate): tuple(re.findall(r'\{"[a-z]", "([a-z_]+)"', buttons))
        for gate, buttons in re.findall(r'"(G[0-7])":\s*\{(.*)\}', table)
    }
    assert actual == CHOICES
