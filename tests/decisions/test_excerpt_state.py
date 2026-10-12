"""Laya sees a bounded, redacted code excerpt — never raw source."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnscan.decisions.triage import finding_to_state


def _obs(excerpt: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        location=SimpleNamespace(file_path="src/main/java/x/Foo.java", line_start=42),
        tool="SEMGREP",
        metadata={"code_excerpt": excerpt} if excerpt is not None else {},
    )


def _finding(obs: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        finding_id="abc123",
        rule_id="java-sql-concatenation",
        cwe_category="CWE-89",
        severity="HIGH",
        message="SQL built by concatenation",
        tool="SEMGREP",
        location=obs.location,
        observations=(obs,),
    )


def test_excerpt_reaches_state() -> None:
    code = 'stmt.execute("SELECT * FROM u WHERE n=\'" + req.getParameter("n") + "\'");'
    state = finding_to_state(_finding(_obs(code)))
    assert state["code_excerpt"] == code
    assert state["excerpt_truncated"] is False


def test_long_excerpt_is_truncated_within_bound() -> None:
    state = finding_to_state(_finding(_obs("x = 1;\n" * 500)))
    assert state["excerpt_truncated"] is True
    assert len(state["code_excerpt"]) <= 400
    assert "truncated" in state["code_excerpt"]


def test_missing_excerpt_is_reported_not_invented() -> None:
    state = finding_to_state(_finding(_obs(None)))
    assert state["excerpt_truncated"] is False
    assert state.get("code_excerpt", "") == ""


def test_excerpt_from_observation_metadata_flows_through() -> None:
    raw = 'q = "SELECT " + request.getParameter("id");'
    obs = SimpleNamespace(
        location=SimpleNamespace(file_path="a/B.java", line_start=3),
        tool="SEMGREP",
        metadata={"code_excerpt": raw},
    )
    finding = SimpleNamespace(
        finding_id="m1",
        rule_id="r",
        cwe_category="CWE-89",
        severity="HIGH",
        message="m",
        tool="SEMGREP",
        location=obs.location,
        observations=(obs,),
    )
    state = finding_to_state(finding)
    assert state["code_excerpt"] == raw


@pytest.mark.parametrize("metadata_excerpt", [None, "", "   ", "requires login"])
@pytest.mark.parametrize("tool", ["SEMGREP", "SPOTBUGS"])
def test_fr40_retained_source_snippet_is_used_when_metadata_excerpt_is_empty(
    metadata_excerpt, tool
) -> None:
    obs = _obs(metadata_excerpt)
    obs.tool = tool
    obs.location.snippet = 'stmt.execute(request.getParameter("id"));'

    state = finding_to_state(_finding(obs))

    assert state["code_excerpt"] == obs.location.snippet
    assert state["excerpt_truncated"] is False


def test_fr40_adapter_excerpt_takes_precedence_over_retained_snippet() -> None:
    obs = _obs("adapter source")
    obs.location.snippet = "retained source"
    assert finding_to_state(_finding(obs))["code_excerpt"] == "adapter source"


def test_qr12_retained_snippet_is_redacted_before_it_is_bounded(monkeypatch) -> None:
    secret = "sensitive-credential-" * 5
    monkeypatch.setenv("MODEL_TEST_API_KEY", secret)
    obs = _obs(None)
    obs.location.snippet = "x" * 365 + secret + "y" * 500

    state = finding_to_state(_finding(obs))

    assert state["excerpt_truncated"] is True
    assert len(state["code_excerpt"]) <= 400
    assert "sensitive-credential" not in state["code_excerpt"]
    assert "[REDACTED]" in state["code_excerpt"]
