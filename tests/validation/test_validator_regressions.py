"""FR-50: proposals, blocked procedures and counterevidence cannot confirm findings."""

import pytest

from tests.ai.test_review_wiring import _assessment, _finding
from tests.validation.test_validator import _evidence, _verification
from vulnscan.ai.review import evidence_for
from vulnscan.assessment.validator import IndependentValidator
from vulnscan.contracts import EvidenceKind, EvidenceStrength, FindingStatus, VerificationOutcome


@pytest.mark.parametrize("proposal", ["confirmed", "rejected", "unresolved"])
def test_scanner_and_model_proposal_alone_cannot_make_terminal_decision(proposal):
    assessment = _assessment(proposal, 0.99)
    records = evidence_for(_finding(), assessment, "r1")
    result = IndependentValidator().validate("f1", FindingStatus.UNPROCESSED, assessment, records)
    assert result.new_status == FindingStatus.UNRESOLVED


def trusted(eid, polarity="supporting", strength=EvidenceStrength.STRONG):
    record = _evidence(eid, "f1", strength)
    record.source_location = "Example.java:42"
    record.metadata = {
        "independently_verified": True,
        "polarity": polarity,
        "run_id": "r1",
        "verifier": "fixture-independent-check",
    }
    return record


def test_two_counterevidence_records_reject_instead_of_becoming_support():
    records = [trusted("e1", "contradicting"), trusted("e2", "contradicting")]
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), records
    )
    assert result.new_status == FindingStatus.REJECTED


def test_conflicting_independent_evidence_remains_unresolved():
    records = [trusted("positive-1"), trusted("positive-2"), trusted("negative", "contradicting")]
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), records
    )
    assert result.new_status == FindingStatus.UNRESOLVED


def test_repeated_or_foreign_records_cannot_inflate_confirmation():
    record = trusted("one")
    foreign = trusted("foreign")
    foreign.finding_id = "another-finding"
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), [record, record, foreign]
    )
    assert result.new_status == FindingStatus.UNRESOLVED
    wrong_run = trusted("wrong-run")
    wrong_run.metadata["run_id"] = "another-run"
    assert (
        IndependentValidator()
        .validate("f1", FindingStatus.UNPROCESSED, _assessment(), [record, wrong_run])
        .new_status
        == FindingStatus.UNRESOLVED
    )


@pytest.mark.parametrize(
    "status",
    [
        VerificationOutcome.BLOCKED,
        VerificationOutcome.HARNESSED_FAILED,
        VerificationOutcome.INCONCLUSIVE,
    ],
)
def test_blocked_or_failed_verification_never_confirms(status):
    observation = _verification("v1", "f1", status)
    observation.execution_status = status
    observation.legitimate_functionality_ok = True
    observation.metadata = {
        "independently_verified": True,
        "polarity": "supporting",
        "verifier": "fixture-independent-check",
    }
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), [], [observation]
    )
    assert result.new_status == FindingStatus.UNRESOLVED


def test_fixed_variant_success_does_not_confirm_original_finding():
    observation = _verification("v1", "f1", VerificationOutcome.DEMONSTRATED)
    observation.is_vulnerable_variant = False
    observation.legitimate_functionality_ok = True
    observation.metadata = {
        "independently_verified": True,
        "polarity": "supporting",
        "verifier": "fixture-independent-check",
    }
    assert (
        IndependentValidator()
        .validate("f1", FindingStatus.UNPROCESSED, _assessment(), [], [observation])
        .new_status
        == FindingStatus.UNRESOLVED
    )


def test_model_cannot_claim_independent_evidence_metadata():
    record = trusted("model")
    record.kind = EvidenceKind.MODEL
    assert (
        IndependentValidator(min_evidence_for_confirm=1)
        .validate("f1", FindingStatus.UNPROCESSED, _assessment(), [record])
        .new_status
        == FindingStatus.UNRESOLVED
    )


@pytest.mark.parametrize("minimum", [0, -1])
def test_confirmation_thresholds_must_be_positive(minimum):
    with pytest.raises(ValueError):
        IndependentValidator(min_evidence_for_confirm=minimum)


def test_assessment_for_another_finding_is_rejected():
    with pytest.raises(ValueError):
        IndependentValidator().validate(
            "foreign-finding", FindingStatus.UNPROCESSED, _assessment(), []
        )


def test_multiple_raw_scanner_observations_are_not_independent_proof():
    finding = _finding()
    finding.observations.append(
        finding.observations[0].model_copy(update={"observation_id": "second-scanner"})
    )
    records = evidence_for(finding, _assessment("confirmed", 0.99), "r1")
    assert (
        IndependentValidator()
        .validate("f1", FindingStatus.UNPROCESSED, _assessment(), records)
        .new_status
        == FindingStatus.UNRESOLVED
    )


@pytest.mark.parametrize("legitimate", [None, False])
def test_incomplete_legitimate_functionality_checks_do_not_confirm(legitimate):
    observation = _verification("v1", "f1", VerificationOutcome.DEMONSTRATED)
    observation.legitimate_functionality_ok = legitimate
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), [], [observation]
    )
    assert result.new_status == FindingStatus.UNRESOLVED


def test_conflicting_duplicate_evidence_identity_is_quarantined():
    first = trusted("same-id")
    changed = first.model_copy(deep=True)
    changed.metadata["polarity"] = "contradicting"
    result = IndependentValidator().validate(
        "f1", FindingStatus.UNPROCESSED, _assessment(), [first, changed, trusted("another")]
    )
    assert result.new_status == FindingStatus.UNRESOLVED
    assert result.metadata["conflicting_ids"] == ["same-id"]
