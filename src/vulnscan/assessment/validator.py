"""Bộ xác thực độc lập — tiếp nhận bằng chứng và phát ra ValidationDecision.

Ranh giới quyền sở hữu: chỉ module này mới có quyền chuyển một finding sang trạng thái
confirmed hoặc rejected. Các đánh giá AI chỉ là đề xuất và không thể trực tiếp
thay đổi trạng thái của finding.
"""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.enums import (
    EvidenceStrength,
    FindingStatus,
    VerificationOutcome,
)
from vulnscan.contracts.validation import EvidenceRecord, ValidationDecision
from vulnscan.contracts.verification import VerificationObservation


class IndependentValidator:
    """Quyết định trạng thái của finding từ bằng chứng và các quan sát xác minh.

    Parameters
    ----------
    min_evidence_for_confirm:
        Số lượng bản ghi bằng chứng tối thiểu có độ mạnh ``strong`` hoặc ``moderate``
        cần thiết để xác nhận một finding.
    min_verification_for_confirm:
        Số lượng quan sát xác minh tối thiểu có kết quả ``demonstrated``
        cần thiết để xác nhận thông qua xác minh.
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
        """Đánh giá một finding và phát ra quyết định xác thực.

        Logic quyết định:
        - **Confirmed**: có đủ bằng chứng strong/moderate VÀ/HOẶC
          kết quả xác minh kiểu demonstrated.
        - **Rejected**: có bằng chứng phản bác mạnh kèm giải thích.
        - **Unresolved**: bằng chứng không đủ hoặc mơ hồ.
        """
        verification = verification or []

        # Đếm độ mạnh của bằng chứng
        strong_evidence = sum(
            1
            for e in evidence
            if e.strength in (EvidenceStrength.STRONG, EvidenceStrength.MODERATE)
        )
        weak_evidence = sum(1 for e in evidence if e.strength in (EvidenceStrength.WEAK,))

        # Đếm kết quả xác minh
        demonstrated = sum(
            1
            for v in verification
            if v.execution_status
            in (
                VerificationOutcome.DEMONSTRATED,
                VerificationOutcome.BLOCKED,
            )
        )
        inconclusive = sum(
            1
            for v in verification
            if v.execution_status
            in (
                VerificationOutcome.INCONCLUSIVE,
                VerificationOutcome.HARNESSED_FAILED,
                VerificationOutcome.BLOCKED,
            )
        )

        # Xác định bằng chứng phản bác
        rejected_counterevidence = [
            e
            for e in evidence
            if e.strength == EvidenceStrength.STRONG
            and "contradicts" in (e.source_description or "").lower()
        ]

        now = datetime.now(UTC)

        # Cây quyết định
        if rejected_counterevidence and strong_evidence < self._min_ev:
            new_status = FindingStatus.REJECTED
            strength = EvidenceStrength.STRONG
            outcome = VerificationOutcome.DEMONSTRATED
            rationale = (
                f"Rejected based on {len(rejected_counterevidence)} strong counterevidence records."
            )
            if assessment.proposed_status == "confirmed":
                rationale += (
                    " AI assessment proposed 'confirmed' but was overridden "
                    "by independent counterevidence."
                )
        elif strong_evidence >= self._min_ev or demonstrated >= self._min_verif:
            new_status = FindingStatus.CONFIRMED
            strength = EvidenceStrength.STRONG if demonstrated else EvidenceStrength.MODERATE
            outcome = (
                VerificationOutcome.DEMONSTRATED
                if demonstrated
                else VerificationOutcome.NOT_VERIFIED
            )
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
