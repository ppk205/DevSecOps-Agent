"""Independent validator — consumes evidence and emits ValidationDecision.

Ownership boundary: only this module may move a finding into confirmed or
rejected status.  AI assessments are proposals only and cannot directly
mutate finding status.
"""

from __future__ import annotations

from datetime import datetime, timezone

from vulnscan.contracts.validation import EvidenceRecord, ValidationDecision
from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.verification import VerificationObservation
from vulnscan.contracts.enums import (
    EvidenceKind,
    EvidenceStrength,
    FindingStatus,
    VerificationOutcome,
)


class IndependentValidator:
    """Decide a finding's status from evidence and verification observations.

    Parameters
    ----------
    min_evidence_for_confirm:
        Minimum number of evidence records with ``strong`` or ``moderate``
        strength required to confirm a finding.
    min_verification_for_confirm:
        Minimum verification observations with ``demonstrated`` outcome
        required for confirm-by-verification.
    """

    def __init__(
        self,
        min_evidence_for_confirm: int = 2,
        min_verification_for_confirm: int = 1,
    ) -> None:
        self._min_ev = min_evidence_for_confirm
        self._min_verif = min_verification_for_confirm

    def validate(
        self,
        finding_id: str,
        previous_status: FindingStatus,
        assessment: Assessment,
        evidence: list[EvidenceRecord],
        verification: list[VerificationObservation] | None = None,
    ) -> ValidationDecision:
        """Evaluate a finding and emit a validation decision.

        Decision logic:
        - **Confirmed**: sufficient strong/moderate evidence AND/OR
          demonstrated verification outcome.
        - **Rejected**: strong counterevidence with explanation.
        - **Unresolved**: insufficient or ambiguous evidence.
        """
        verification = verification or []

        # Count evidence strengths
        strong_evidence = sum(
            1 for e in evidence
            if e.strength in (EvidenceStrength.STRONG, EvidenceStrength.MODERATE)
        )
        weak_evidence = sum(
            1 for e in evidence
            if e.strength in (EvidenceStrength.WEAK,)
        )

        # Count verification outcomes
        demonstrated = sum(
            1 for v in verification
            if v.execution_status in (
                VerificationOutcome.DEMONSTRATED,
                VerificationOutcome.BLOCKED,
            )
        )
        inconclusive = sum(
            1 for v in verification
            if v.execution_status in (
                VerificationOutcome.INCONCLUSIVE,
                VerificationOutcome.HARNESSED_FAILED,
                VerificationOutcome.BLOCKED,
            )
        )

        # Identify counterevidence
        rejected_counterevidence = [
            e for e in evidence
            if e.strength == EvidenceStrength.STRONG
            and "contradicts" in (e.source_description or "").lower()
        ]

        now = datetime.now(timezone.utc)

        # Decision tree
        if rejected_counterevidence and strong_evidence < self._min_ev:
            new_status = FindingStatus.REJECTED
            strength = EvidenceStrength.STRONG
            outcome = VerificationOutcome.DEMONSTRATED
            rationale = (
                f"Rejected based on {len(rejected_counterevidence)} strong "
                f"counterevidence records."
            )
            if assessment.proposed_status == "confirmed":
                rationale += (
                    " AI assessment proposed 'confirmed' but was overridden "
                    "by independent counterevidence."
                )
        elif strong_evidence >= self._min_ev or demonstrated >= self._min_verif:
            new_status = FindingStatus.CONFIRMED
            strength = EvidenceStrength.STRONG if demonstrated else EvidenceStrength.MODERATE
            outcome = VerificationOutcome.DEMONSTRATED if demonstrated else VerificationOutcome.NOT_VERIFIED
            rationale = (
                f"Confirmed with {strong_evidence} supporting evidence "
                f"({demonstrated} verification demonstrations)."
            )
        elif weak_evidence > 0 or inconclusive > 0:
            new_status = FindingStatus.UNRESOLVED
            strength = EvidenceStrength.WEAK
            outcome = VerificationOutcome.INCONCLUSIVE
            rationale = (
                f"Insufficient evidence for confirmation: "
                f"{strong_evidence} strong, {weak_evidence} weak evidence; "
                f"{demonstrated} demonstrations, {inconclusive} inconclusive."
            )
        else:
            new_status = FindingStatus.UNRESOLVED
            strength = EvidenceStrength.NONE
            outcome = VerificationOutcome.NOT_VERIFIED
            rationale = "No evidence available for assessment."

        return ValidationDecision(
            decision_id=f"val-{finding_id}",
            finding_id=finding_id,
            previous_status=previous_status,
            new_status=new_status,
            outcome=outcome,
            evidence_refs=[e.evidence_id for e in evidence],
            evidence_strength=strength,
            rationale=rationale,
            decided_by="independent-validator",
            decided_at=now,
        )
