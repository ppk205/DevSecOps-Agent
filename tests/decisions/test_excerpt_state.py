"""Laya sees a bounded, redacted code excerpt — never raw source."""

from __future__ import annotations

from types import SimpleNamespace

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
