"""FR-50/53: actual review wiring keeps proposals unconfirmed and scores vectors."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from tests.ai.test_agent_loop import _mock_provider_client
from tests.ai.test_review_wiring import _finding
from vulnscan.agent.loop import AgentLoop
from vulnscan.ai import review
from vulnscan.contracts import FindingStatus
from vulnscan.providers.client import ChatResponse

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_agent_path_computes_vector_scores_and_preserves_metric_assumptions():
    response = ChatResponse(
        content=json.dumps(
            {
                "proposed_status": "confirmed",
                "confidence": 0.99,
                "rationale": "proposal only",
                "cvss_vector": BASE,
                "assumptions": ["Network reachability needs verification"],
            }
        )
    )
    loop = AgentLoop(_mock_provider_client([response]), {})
    assessment = loop.investigate(_finding(), {})
    assert assessment.cvss.base_score == 9.3
    assert assessment.assumptions == ["Network reachability needs verification"]
    assert assessment.metadata["cvss_score_status"] == "computed"
    assert assessment.cvss.metric_assumptions_verified is False


def test_invalid_model_vector_is_visible_as_unscored_without_echoing_it():
    response = ChatResponse(
        content=json.dumps(
            {
                "proposed_status": "confirmed",
                "confidence": 0.99,
                "rationale": "proposal only",
                "cvss_vector": BASE + "/UNKNOWN:synthetic-secret-value",
            }
        )
    )
    assessment = AgentLoop(_mock_provider_client([response]), {}).investigate(_finding(), {})
    assert assessment.cvss is None
    assert assessment.metadata["cvss_score_status"] == "invalid"
    assert assessment.metadata["cvss_validation_errors"]
    assert "synthetic-secret-value" not in json.dumps(assessment.metadata)


def test_json_braces_in_rationale_do_not_drop_a_valid_vector():
    response = ChatResponse(
        content=json.dumps(
            {
                "proposed_status": "confirmed",
                "confidence": 0.9,
                "rationale": "The route uses an {id} parameter",
                "cvss_vector": BASE,
                "assumptions": ["Validate {id} ownership"],
            }
        )
    )
    assessment = AgentLoop(_mock_provider_client([response]), {}).investigate(_finding(), {})
    assert assessment.cvss is not None and assessment.cvss.base_score == 9.3
    assert assessment.assumptions == ["Validate {id} ownership"]


def test_single_shot_scores_cvss_without_promoting_model_verdict(tmp_path):
    client = MagicMock()
    client.chat.return_value = ChatResponse(
        content=json.dumps(
            {
                "proposed_status": "rejected",
                "confidence": 0.99,
                "rationale": "model counterclaim",
                "cvss_vector": BASE,
                "assumptions": ["Attacker privileges unknown"],
            }
        )
    )
    profile = SimpleNamespace(id="fake", default_model="fixture")
    finding = _finding()
    assessment = review.single_shot_verdict(client, finding, str(tmp_path), profile, None)
    assert assessment.cvss.base_score == 9.3
    assert assessment.assumptions == ["Attacker privileges unknown"]


def test_review_persists_validator_provenance_and_computed_cvss(monkeypatch, tmp_path):
    response = ChatResponse(
        content=json.dumps(
            {
                "proposed_status": "confirmed",
                "confidence": 0.99,
                "rationale": "proposal only",
                "cvss_vector": BASE,
            }
        )
    )
    loop = AgentLoop(_mock_provider_client([response]), {}, provider_id="fake", model_id="fixture")
    budget = MagicMock()
    budget.summary.return_value = {}
    monkeypatch.setattr(
        review,
        "build_review_agent",
        lambda *args, **kwargs: (loop, loop.client, loop.client.profile, budget),
    )
    finding = _finding()
    result = review.run_ai_review([finding], [], snapshot_root=str(tmp_path), profile_id="fake")
    assert finding.status == FindingStatus.UNRESOLVED
    assert result["assessments"][0]["cvss"]["base_score"] == 9.3
    assert finding.metadata["validation_decision"]["new_status"] == "unresolved"
    assert finding.metadata["ai_assessments"][0]["cvss"]["metric_assumptions_verified"] is False
    assert loop.client.chat.call_count == 1
