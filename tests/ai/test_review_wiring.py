"""AI review wiring: targets, evidence mapping, validator ownership, exports."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from vulnscan.agent.loop import parse_verdict_text
from vulnscan.ai.review import (
    build_tool_handlers,
    evidence_for,
    pick_review_targets,
    run_ai_review,
)
from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    ExportFormat,
    FindingStatus,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.reporting.final_report import deterministic_narrative, run_final_report
from vulnscan.reporting.reporter import ReportGenerator


def _finding(fid="f1", status=FindingStatus.UNPROCESSED):
    now = datetime.now(UTC)
    return Finding(
        finding_id=fid,
        run_id="r1",
        fingerprint="fp-test",
        title="SQL Injection in login",
        description="User input flows to query",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=status,
        observations=[
            Observation(
                observation_id="obs-1",
                detected_at=now,
                run_id="r1",
                tool=ToolName.SEMGREP,
                tool_version="1.0",
                rule_id="java.lang.security.audit.sqli",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="SQL injection via request param",
                confidence=0.9,
                location=SourceCoordinate(file_path="src/LoginServlet.java", line_start=42),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _assessment(status="confirmed", confidence=0.9):
    return Assessment(
        assessment_id="a1",
        finding_id="f1",
        run_id="r1",
        proposed_status=status,
        rationale="test",
        confidence=confidence,
        provider_id="p",
        model_id="m",
        model_version="v1",
        created_at=datetime.now(UTC),
    )


class TestPickTargets:
    def test_deep_routes_first_and_capped(self):
        f1, f2, f3 = _finding("f1"), _finding("f2"), _finding("f3")
        routing = [
            {"finding_id": "f3", "route": "low_priority"},
            {"finding_id": "f1", "route": "cross_file_analysis"},
        ]
        picked = pick_review_targets([f1, f2, f3], routing, 2)
        assert [f.finding_id for f in picked] == ["f1", "f2"]

    def test_processed_findings_skipped(self):
        f = _finding("f1", FindingStatus.CONFIRMED)
        assert (
            pick_review_targets([f], [{"finding_id": "f1", "route": "cross_file_analysis"}], 5)
            == []
        )


class TestEvidenceMapping:
    def test_confirm_high_confidence_is_strong(self):
        recs = evidence_for(_finding(), _assessment("confirmed", 0.9), "r1")
        kinds = {r.kind.value: r.strength for r in recs}
        assert kinds["static"] == EvidenceStrength.MODERATE
        assert kinds["model"] == EvidenceStrength.STRONG

    def test_reject_marks_counterevidence(self):
        recs = evidence_for(_finding(), _assessment("rejected", 0.85), "r1")
        model = next(r for r in recs if r.kind.value == "model")
        assert "contradicts" in model.source_description
        assert model.strength == EvidenceStrength.STRONG

    def test_unresolved_is_weak(self):
        recs = evidence_for(_finding(), _assessment("unresolved", 0.3), "r1")
        assert next(r for r in recs if r.kind.value == "model").strength == EvidenceStrength.WEAK


class TestRunAiReview:
    def test_no_provider_skips_without_touching(self, monkeypatch):
        findings = [_finding()]
        report = run_ai_review(findings, [], snapshot_root=".", profile_id=None)
        assert report["status"] == "skipped"
        assert findings[0].status == FindingStatus.UNPROCESSED

    def test_fake_loop_confirms_through_validator(self, monkeypatch, tmp_path):
        import vulnscan.ai.review as review_mod

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "LoginServlet.java").write_text("x = 1;\n" * 60)
        fake_loop = MagicMock()
        fake_loop.model_id = "m"
        confirmed = _assessment("confirmed", 0.9)
        confirmed.rationale = (
            '{"proposed_status": "confirmed", "confidence": 0.9, '
            '"rationale": "tainted flow from req to sink"}'
        )
        fake_loop.investigate.return_value = confirmed

        def _fake_builder(*args, **kwargs):
            fake_budget = MagicMock()
            fake_budget.summary.return_value = {}
            return (fake_loop, MagicMock(), MagicMock(id="p"), fake_budget)

        monkeypatch.setattr(review_mod, "build_review_agent", _fake_builder)
        findings = [_finding()]
        routing = [{"finding_id": "f1", "route": "cross_file_analysis"}]
        report = run_ai_review(
            findings, routing, snapshot_root=str(tmp_path), profile_id="p", max_findings=5
        )
        assert report["status"] == "completed"
        assert findings[0].status == FindingStatus.CONFIRMED
        assert report["decisions"][0]["decided_by"] == "independent-validator"

    def test_tool_handlers_jailed_to_snapshot(self, tmp_path):
        handlers = build_tool_handlers(str(tmp_path), [_finding()])
        assert "error" in handlers["inspect_code"]({"file_path": "../outside.java"})
        assert "error" in handlers["get_evidence"]({"finding_id": "nope"})


class TestParseVerdict:
    def test_json_block_is_explicit(self):
        s, c, _r, explicit = parse_verdict_text(
            '{"proposed_status": "confirmed", "confidence": 0.8, "rationale": "x"}'
        )
        assert (s, c, explicit) == ("confirmed", 0.8, True)

    def test_keyword_verdict_is_explicit(self):
        s, _, _, explicit = parse_verdict_text("This is a true positive, confidence 0.85.")
        assert (s, explicit) == ("confirmed", True)

    def test_garbage_is_not_explicit(self):
        s, c, _, explicit = parse_verdict_text('{"file_path": "a.java"}\n</rfl:parameter>')
        assert (s, explicit) == ("unresolved", False)
        assert c == 0.5

    def test_single_shot_fallback_replaces_hollow(self, monkeypatch, tmp_path):
        import vulnscan.ai.review as review_mod

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "LoginServlet.java").write_text("x = 1;\n" * 60)
        hollow = _assessment("unresolved", 0.5)
        hollow.rationale = '{"file_path": "src/LoginServlet.java"}'
        fake_loop = MagicMock()
        fake_loop.model_id = "m"
        fake_loop.investigate.return_value = hollow

        from vulnscan.providers.client import ChatResponse

        answered = ChatResponse(
            content='{"proposed_status": "confirmed", "confidence": 0.85, "rationale": "tainted flow"}',
            usage={"total_tokens": 10},
            model="m",
        )
        fake_client = MagicMock()
        fake_client.chat.return_value = answered

        def _fake_builder(*args, **kwargs):
            fake_budget = MagicMock()
            fake_budget.summary.return_value = {}
            return (fake_loop, fake_client, MagicMock(id="p"), fake_budget)

        monkeypatch.setattr(review_mod, "build_review_agent", _fake_builder)
        findings = [_finding()]
        routing = [{"finding_id": "f1", "route": "cross_file_analysis"}]
        report = run_ai_review(
            findings, routing, snapshot_root=str(tmp_path), profile_id="p", max_findings=5
        )
        assert findings[0].status == FindingStatus.CONFIRMED
        assert report["assessments"][0]["metadata"]["single_shot"] is True


class TestFinalReport:
    def test_deterministic_fallback_without_provider(self):
        report = run_final_report([_finding()], [], {"target": "t"}, profile_id=None)
        assert report["status"] == "skipped" and not report["ai_written"]
        assert "SQL Injection" in report["markdown"]

    def test_deterministic_narrative_lists_decisions(self):
        md = deterministic_narrative(
            [_finding()], [{"finding_id": "f1", "rationale": "ok"}], {"target": "t"}
        )
        assert "Validator: ok" in md


class TestNewExportFormats:
    def test_txt_and_docx_roundtrip(self, tmp_path):
        gen = ReportGenerator("r1", [_finding()])
        txt = gen.export(ExportFormat.TXT, tmp_path)
        assert txt.artifact_ref.path.endswith(".txt")
        body = Path(txt.artifact_ref.path).read_text(encoding="utf-8")
        assert "SQL Injection" in body and "Unprocessed" in body
        docx = gen.export(ExportFormat.DOCX, tmp_path)
        assert docx.artifact_ref.path.endswith(".docx")
        data = Path(docx.artifact_ref.path).read_bytes()
        assert data[:4] == b"PK\x03\x04"  # zip container
        assert len(data) > 1000
