"""Independent status decisions require scoped, explicitly verified evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypeVar

from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.enums import (
    EvidenceKind,
    EvidenceStrength,
    FindingStatus,
    VerificationOutcome,
)
from vulnscan.contracts.validation import EvidenceRecord, ValidationDecision
from vulnscan.contracts.verification import VerificationObservation

_Record = TypeVar("_Record", EvidenceRecord, VerificationObservation)
_INDEPENDENT_KINDS = {
    EvidenceKind.STATIC,
    EvidenceKind.DATAFLOW,
    EvidenceKind.RUNTIME,
    EvidenceKind.POLICY,
}


def _unique(records: list[_Record], field: str) -> tuple[list[_Record], list[str]]:
    by_id: dict[str, _Record] = {}
    conflicts: set[str] = set()
    for record in records:
        key = str(getattr(record, field))
        if key in by_id and by_id[key] != record:
            conflicts.add(key)
        else:
            by_id[key] = record
    return [record for key, record in by_id.items() if key not in conflicts], sorted(conflicts)


def _independent(metadata: dict[str, Any]) -> bool:
    return (
        metadata.get("independently_verified") is True
        and isinstance(metadata.get("verifier"), str)
        and bool(metadata["verifier"].strip())
        and metadata.get("polarity") in ("supporting", "contradicting")
    )


class IndependentValidator:
    """Consume trusted verification results; do not manufacture verification.

    Trusted application producers assert independent metadata after checking the
    relevant source/procedure. Scanner/model adapters do not assert it. This
    decision boundary cannot itself prove a producer's assertions.
    """

    def __init__(
        self, min_evidence_for_confirm: int = 2, min_verification_for_confirm: int = 1
    ) -> None:
        if min_evidence_for_confirm < 1 or min_verification_for_confirm < 1:
            raise ValueError("Confirmation thresholds must be positive")
        self._min_ev, self._min_verif = min_evidence_for_confirm, min_verification_for_confirm

    def validate(
        self,
        finding_id: str,
        previous_status: FindingStatus,
        assessment: Assessment,
        evidence: list[EvidenceRecord],
        verification: list[VerificationObservation] | None = None,
    ) -> ValidationDecision:
        if assessment.finding_id != finding_id:
            raise ValueError("Assessment belongs to a different finding")
        records, conflicts = _unique(evidence, "evidence_id")
        observations, verification_conflicts = _unique(
            verification or [], "verification_observation_id"
        )
        ignored: list[dict[str, str]] = []
        scoped: list[EvidenceRecord] = []
        supporting: list[EvidenceRecord] = []
        contrary: list[EvidenceRecord] = []
        for record in records:
            if record.finding_id != finding_id or record.metadata.get("run_id") not in (
                None,
                assessment.run_id,
            ):
                ignored.append({"id": record.evidence_id, "reason": "different finding or run"})
                continue
            scoped.append(record)
            if (
                record.kind not in _INDEPENDENT_KINDS
                or not _independent(record.metadata)
                or record.metadata.get("run_id") != assessment.run_id
                or not (record.source_location or record.artifact_ref)
                or record.strength not in (EvidenceStrength.STRONG, EvidenceStrength.MODERATE)
            ):
                ignored.append(
                    {
                        "id": record.evidence_id,
                        "reason": "not independently verified supporting/counter evidence",
                    }
                )
                continue
            (supporting if record.metadata["polarity"] == "supporting" else contrary).append(record)

        demonstrations: list[VerificationObservation] = []
        counter_demonstrations: list[VerificationObservation] = []
        scoped_observations: list[VerificationObservation] = []
        for observation in observations:
            if observation.finding_id != finding_id or observation.run_id != assessment.run_id:
                ignored.append(
                    {
                        "id": observation.verification_observation_id,
                        "reason": "different finding or run",
                    }
                )
                continue
            scoped_observations.append(observation)
            if (
                observation.execution_status != VerificationOutcome.DEMONSTRATED
                or not observation.is_vulnerable_variant
                or observation.legitimate_functionality_ok is not True
                or observation.evidence_kind not in _INDEPENDENT_KINDS
                or not _independent(observation.metadata)
                or not observation.procedure_version.strip()
                or observation.verification_level not in {"static", "junit", "sandbox"}
            ):
                ignored.append(
                    {
                        "id": observation.verification_observation_id,
                        "reason": "incomplete, blocked, failed, non-independent or fixed-variant verification",
                    }
                )
                continue
            (
                demonstrations
                if observation.metadata["polarity"] == "supporting"
                else counter_demonstrations
            ).append(observation)

        has_support, has_counter = (
            bool(supporting or demonstrations),
            bool(contrary or counter_demonstrations),
        )
        if conflicts or verification_conflicts or (has_support and has_counter):
            new_status, strength, outcome = (
                FindingStatus.UNRESOLVED,
                EvidenceStrength.WEAK,
                VerificationOutcome.INCONCLUSIVE,
            )
            rationale = "Conflicting independent evidence or conflicting record identities; human review is required."
        elif (
            any(record.strength == EvidenceStrength.STRONG for record in contrary)
            or counter_demonstrations
        ):
            new_status, strength, outcome = (
                FindingStatus.REJECTED,
                EvidenceStrength.STRONG,
                VerificationOutcome.DEMONSTRATED,
            )
            rationale = f"Independent counterevidence: {len(contrary)} records and {len(counter_demonstrations)} completed checks."
        elif len(supporting) >= self._min_ev or len(demonstrations) >= self._min_verif:
            new_status = FindingStatus.CONFIRMED
            strength = EvidenceStrength.STRONG if demonstrations else EvidenceStrength.MODERATE
            outcome = (
                VerificationOutcome.DEMONSTRATED
                if demonstrations
                else VerificationOutcome.NOT_VERIFIED
            )
            rationale = f"Independent supporting evidence: {len(supporting)} records and {len(demonstrations)} completed demonstrations."
        else:
            new_status = FindingStatus.UNRESOLVED
            strength = (
                EvidenceStrength.WEAK if scoped or scoped_observations else EvidenceStrength.NONE
            )
            statuses = {record.execution_status for record in scoped_observations}
            outcome = (
                VerificationOutcome.BLOCKED
                if statuses == {VerificationOutcome.BLOCKED}
                else VerificationOutcome.INCONCLUSIVE
                if scoped or scoped_observations
                else VerificationOutcome.NOT_VERIFIED
            )
            rationale = "Insufficient independent evidence. Scanner detections, model proposals and incomplete procedures do not establish confirmation or rejection."
        return ValidationDecision(
            decision_id=f"val-{finding_id}",
            finding_id=finding_id,
            previous_status=previous_status,
            new_status=new_status,
            outcome=outcome,
            evidence_refs=[record.evidence_id for record in scoped],
            evidence_strength=strength,
            rationale=rationale,
            decided_by="independent-validator",
            decided_at=datetime.now(UTC),
            metadata={
                "policy": "independent-evidence/2",
                "run_id": assessment.run_id,
                "assessment_id": assessment.assessment_id,
                "supporting_evidence": [record.evidence_id for record in supporting],
                "counterevidence": [record.evidence_id for record in contrary],
                "supporting_verification": [
                    record.verification_observation_id for record in demonstrations
                ],
                "counter_verification": [
                    record.verification_observation_id for record in counter_demonstrations
                ],
                "conflicting_ids": conflicts + verification_conflicts,
                "verification_outcomes": {
                    record.verification_observation_id: record.execution_status.value
                    for record in scoped_observations
                },
                "ignored": ignored,
                "model_proposal_used_for_status": False,
            },
        )
