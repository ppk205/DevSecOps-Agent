"""Laya triage over harness candidates."""

from __future__ import annotations

from typing import Any

from tests.harness.fakes import BatchAgent
from vulnscan.decisions.config import load_config
from vulnscan.harness.triage import candidate_state, triage_candidates
from vulnscan.harness.workspace import Candidate

C = [
    Candidate("a1", "CWE-89", "sql_concat", "src/A.java", 3, 'q("x" + n)', has_source=True),
    Candidate(
        "b2", "CWE-862", "missing_role_check", "src/B.java", 1, "@WebServlet", route="/api/admin/u"
    ),
]


def test_candidate_state_has_no_scanner_fields() -> None:
    s = candidate_state(C[0])
    assert s["tool_names"] == ["harness"] and s["rule_ids"] == ["sql_concat"]
    assert s["has_request_source"] is True


def test_triage_sets_route_on_every_candidate() -> None:
    routes = triage_candidates(C, load_config("config/laya.json"), agent=BatchAgent())
    assert set(routes) == {"a1", "b2"} and all(c.laya_route for c in C)
    assert all(r.affects_finding_status is False for r in routes.values())


def test_laya_failure_sends_everything_to_human_review() -> None:
    class Broken:
        def predict_batch(self, *a: Any, **k: Any) -> list[Any]:
            raise RuntimeError("boom")

    routes = triage_candidates(C, load_config("config/laya.json"), agent=Broken())
    assert {r.route for r in routes.values()} == {"human_review"}


def test_shipped_laya_timeout_is_300() -> None:
    assert load_config("config/laya.json").timeout_seconds == 300
