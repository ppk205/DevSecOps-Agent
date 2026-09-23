"""T07 gate: evaluation metrics — precision, recall, F1, verification coverage."""

from datetime import datetime, timezone

from vulnscan.contracts.enums import (
    CWECategory,
    Severity,
    FindingStatus,
    SplitMembership,
    VariantRelationship,
)
from vulnscan.contracts.evaluation import EvaluationCase, MatchingCriteria
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.contracts.validation import ValidationDecision
from vulnscan.contracts.enums import EvidenceStrength, VerificationOutcome
from vulnscan.evaluation.metrics import (
    compute_metrics,
    match_findings_to_cases,
    AggregateResults,
    CWEResults,
)
from vulnscan.evaluation.cases import create_sample_cases


def _finding(fid: str, cwe: CWECategory, file_path: str = "src/LoginServlet.java") -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        finding_id=fid,
        run_id="r1",
        fingerprint=f"fp-{fid}",
        title=f"Test finding {fid}",
        description="test",
        cwe_category=cwe,
        severity=Severity.HIGH,
        status=FindingStatus.UNPROCESSED,
        observations=[
            Observation(
                observation_id=f"obs-{fid}",
                detected_at=now,
                run_id="r1",
                tool=__import__("vulnscan.contracts.enums", fromlist=["ToolName"]).ToolName.SEMGREP,
                tool_version="1.0",
                rule_id=f"rule-{fid}",
                cwe_category=cwe,
                severity=Severity.HIGH,
                message="test",
                confidence=0.9,
                location=SourceCoordinate(file_path=file_path, line_start=10),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _decision(fid: str, status: FindingStatus) -> ValidationDecision:
    return ValidationDecision(
        decision_id=f"val-{fid}",
        finding_id=fid,
        previous_status=FindingStatus.UNPROCESSED,
        new_status=status,
        outcome=VerificationOutcome.DEMONSTRATED,
        evidence_refs=[],
        evidence_strength=EvidenceStrength.STRONG,
        rationale="test",
        decided_by="test",
        decided_at=datetime.now(timezone.utc),
    )


class TestMetrics:
    def test_perfect_detection(self):
        """All vulnerable cases found, no false positives."""
        cases = create_sample_cases()
        # Create one finding per vulnerable case
        from vulnscan.contracts.enums import ToolName
        findings = []
        now = datetime.now(timezone.utc)
        for c in cases:
            if c.variant_relationship == VariantRelationship.VULNERABLE and c.expected_cwe_category:
                findings.append(Finding(
                    finding_id=f"fp-{c.case_id}",
                    run_id="r1",
                    fingerprint=f"fp-{c.case_id}",
                    title=f"Finding for {c.case_id}",
                    description="test",
                    cwe_category=c.expected_cwe_category,
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    observations=[
                        Observation(
                            observation_id=f"obs-{c.case_id}",
                            detected_at=now,
                            run_id="r1",
                            tool=ToolName.SEMGREP,
                            tool_version="1.0",
                            rule_id="test-rule",
                            cwe_category=c.expected_cwe_category,
                            severity=Severity.HIGH,
                            message="test",
                            confidence=0.9,
                            location=SourceCoordinate(file_path=c.variant_path, line_start=10),
                        )
                    ],
                    created_at=now,
                    updated_at=now,
                ))

        decisions = [_decision(f.finding_id, FindingStatus.CONFIRMED) for f in findings]
        results = compute_metrics(cases, findings, decisions)
        assert results.total_tp == 6  # 3 dev + 3 held-out vulnerable
        assert results.total_fp == 0
        assert results.total_fn == 0
        assert results.recall == 1.0
        assert results.precision == 1.0

    def test_missed_detection(self):
        """Some findings missed -> lower recall."""
        cases = create_sample_cases()
        # Only create one finding for one vulnerable case
        from vulnscan.contracts.enums import ToolName
        now = datetime.now(timezone.utc)
        vuln_cases = [c for c in cases if c.variant_relationship == VariantRelationship.VULNERABLE]
        first_case = vuln_cases[0]
        findings = [
            Finding(
                finding_id=f"fp-{first_case.case_id}",
                run_id="r1",
                fingerprint=f"fp-{first_case.case_id}",
                title="Partial finding",
                description="test",
                cwe_category=first_case.expected_cwe_category,
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                observations=[
                    Observation(
                        observation_id=f"obs-partial",
                        detected_at=now,
                        run_id="r1",
                        tool=ToolName.SEMGREP,
                        tool_version="1.0",
                        rule_id="test-rule",
                        cwe_category=first_case.expected_cwe_category,
                        severity=Severity.HIGH,
                        message="test",
                        confidence=0.9,
                        location=SourceCoordinate(file_path=first_case.variant_path, line_start=10),
                    )
                ],
                created_at=now,
                updated_at=now,
            )
        ]
        results = compute_metrics(cases, findings)
        assert results.total_tp >= 1
        assert results.total_fn >= 5  # 6 total vulnerable - at least 1 found
        assert results.recall < 1.0

    def test_zero_denominator(self):
        """Empty cases -> 0.0 precision/recall, no divide-by-zero."""
        results = compute_metrics([], [])
        assert results.precision == 0.0
        assert results.recall == 0.0
        assert results.f1 == 0.0
