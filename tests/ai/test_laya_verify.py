"""Laya verification of hunted candidates: attach route/confidence/status."""

from __future__ import annotations

from vulnscan.contracts.decision import (
    DecisionAnswer,
    DecisionResult,
    DecisionStatus,
    DecisionType,
)
from vulnscan.decisions.laya import LayaDecisionBackend


def _completed(route: str = "fast_verification", confidence: float = 0.8) -> DecisionResult:
    return DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="laya-test",
        answers={
            "recommended_action": DecisionAnswer(
                name="recommended_action",
                type=DecisionType.CHOICE,
                choice=route,
                probabilities={route: 0.9, "human_review": 0.1},
                confidence=confidence,
            ),
            "evidence_sufficiency": DecisionAnswer(
                name="evidence_sufficiency",
                type=DecisionType.SCORE,
                score=1.0,
                confidence=0.7,
            ),
            "needs_human_review": DecisionAnswer(
                name="needs_human_review",
                type=DecisionType.NOUL,
                noul=0.1,
                confidence=0.9,
            ),
        },
        state_hash="abc",
        question_set_version="laya-questions-1",
    )


def _candidates() -> list[dict]:
    return [
        {
            "title": "SQL injection",
            "file": "src/LoginServlet.java",
            "line": 14,
            "cwe": "CWE-89",
            "severity": "high",
            "rationale": "tainted flow",
            "evidence": "executeQuery(",
        },
        {
            "title": "XSS",
            "file": "src/Home.java",
            "line": 30,
            "cwe": "CWE-79",
            "severity": "medium",
            "rationale": "unescaped write",
            "evidence": "getWriter().write(",
        },
    ]


class TestLayaVerify:
    def test_attaches_route_confidence_status(self, monkeypatch, tmp_path):
        from vulnscan.ai import laya_verify as mod

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "LoginServlet.java").write_text("x = 1;\n" * 40)
        (tmp_path / "src" / "Home.java").write_text("y = 2;\n" * 40)

        def _fake_predict_many(self, requests):
            assert len(requests) == 2
            return [_completed("fast_verification"), _completed("human_review", 0.6)]

        monkeypatch.setattr(LayaDecisionBackend, "predict_many", _fake_predict_many)
        out = mod.laya_verify_candidates(_candidates(), snapshot_root=str(tmp_path))
        assert len(out) == 2
        assert out[0]["laya_route"] == "fast_verification"
        assert out[0]["laya_confidence"] == 0.8
        assert out[0]["laya_status"] == "completed"
        assert out[1]["laya_route"] == "human_review"
        assert out[1]["laya_confidence"] == 0.6
        assert out[1]["laya_status"] == "completed"
        # Originals untouched, excerpt evidence attached via request state only.
        assert "laya_route" not in _candidates()[0]

    def test_backend_failure_marks_all_skipped(self, monkeypatch, tmp_path):
        from vulnscan.ai import laya_verify as mod

        def _boom(self, requests):
            raise RuntimeError("laya down")

        monkeypatch.setattr(LayaDecisionBackend, "predict_many", _boom)
        out = mod.laya_verify_candidates(_candidates(), snapshot_root=str(tmp_path))
        assert len(out) == 2
        assert all(c["laya_status"] == "skipped" for c in out)

    def test_empty_candidates_returns_empty(self, tmp_path):
        from vulnscan.ai import laya_verify as mod

        assert mod.laya_verify_candidates([], snapshot_root=str(tmp_path)) == []
