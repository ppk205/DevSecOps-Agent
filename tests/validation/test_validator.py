"""T05 gate: independent validator — evidence-based finding status changes."""

from datetime import datetime, timezone

from vulnscan.assessment.validator import IndependentValidator
from vulnscan.contracts.validation import EvidenceRecord, ValidationDecision
from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.verification import VerificationObservation
from vulnscan.contracts.enums import (
    EvidenceKind,
    EvidenceStrength,
    FindingStatus,
    VerificationOutcome,
    CWECategory,
    Severity,
)


def _evidence(eid: str, fid: str, strength: EvidenceStrength, desc: str = "scanner detection") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=eid,
        finding_id=fid,
        kind=EvidenceKind.STATIC,
        strength=strength,
        source_description=desc,
        created_at=datetime.now(timezone.utc),
    )


def _assessment(fid: str, proposed_status: str = "unresolved") -> Assessment:
    return Assessment(
        assessment_id=f"ass-{fid}",
        finding_id=fid,
        run_id="r1",
        proposed_status=proposed_status,
        rationale="test",
        evidence_refs=[],
        provider_id="test-provider",
        model_id="test-model",
        model_version="v1",
        confidence=0.0,
        created_at=datetime.now(timezone.utc),
    )


def _verification(vid: str, fid: str, outcome: VerificationOutcome) -> VerificationObservation:
    return VerificationObservation(
        verification_observation_id=vid,
        finding_id=fid,
        run_id="r1",
        procedure_version="v1",
        verification_level="static",
        security_property="prepared statement used",
        observed_behavior="demonstrated: prepared statement in place",
        execution_status="demonstrated",
        is_vulnerable_variant=True,
        evidence_kind=EvidenceKind.STATIC,
        observed_at=datetime.now(timezone.utc),
    )


class TestIndependentValidator:
    def test_confirm_with_sufficient_evidence(self):
        v = IndependentValidator(min_evidence_for_confirm=2)
        ev1 = _evidence("e1", "f1", EvidenceStrength.STRONG, "Semgrep: confirmed at line 42")
        ev2 = _evidence("e2", "f1", EvidenceStrength.MODERATE, "manual review: confirmed pattern")
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [ev1, ev2])

        assert decision.new_status == FindingStatus.CONFIRMED
        assert decision.decision_id.startswith("val-f1")

    def test_confirm_with_verification(self):
        v = IndependentValidator(min_evidence_for_confirm=10, min_verification_for_confirm=1)
        verification = _verification("v1", "f1", VerificationOutcome.DEMONSTRATED)
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [], [verification])
        assert decision.new_status == FindingStatus.CONFIRMED

    def test_reject_with_counterevidence(self):
        v = IndependentValidator(min_evidence_for_confirm=5)
        ev1 = _evidence("e1", "f1", EvidenceStrength.STRONG, "contradicts: prepared statement in place")
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [ev1])
        assert decision.new_status == FindingStatus.REJECTED

    def test_unresolved_with_weak_evidence(self):
        v = IndependentValidator()
        ev1 = _evidence("e1", "f1", EvidenceStrength.WEAK)
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [ev1])
        assert decision.new_status == FindingStatus.UNRESOLVED

    def test_unresolved_with_no_evidence(self):
        v = IndependentValidator()
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [])
        assert decision.new_status == FindingStatus.UNRESOLVED

    def test_previous_status_recorded(self):
        v = IndependentValidator()
        decision = v.validate("f1", FindingStatus.UNPROCESSED, _assessment("f1"), [])
        assert decision.previous_status == FindingStatus.UNPROCESSED
