"""Contract smoke tests (T00 gate).

These verify the shared contracts are usable and that the invariants from
docs/SRS.md section 4.2 (evaluation-case isolation) and section 8 (ACC
negative paths) hold. Downstream modules depend on these passing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make src importable when the package is not installed.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from vulnscan.contracts import (  # noqa: E402
    ArtifactReference,
    Assessment,
    EvaluationCase,
    Finding,
    Observation,
    ScanSpecification,
    ToolConfig,
)

JVA_COMMIT = "dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5"
JVA_URL = "https://github.com/Moseyuh333/JVA-bookstore"


def _make_spec() -> ScanSpecification:
    return ScanSpecification(
        target_repository_url=JVA_URL,
        target_commit_sha=JVA_COMMIT,
        tools=[ToolConfig(tool="semgrep"), ToolConfig(tool="spotbugs")],
    )


class TestScanSpecification:
    def test_round_trip(self) -> None:
        spec = _make_spec()
        restored = ScanSpecification.model_validate_json(spec.model_dump_json())
        assert restored.target_commit_sha == JVA_COMMIT
        assert restored.target_repository_url == JVA_URL

    def test_created_at_defaults_to_utc_now(self) -> None:
        spec = _make_spec()
        assert spec.created_at is not None
        # A fresh spec must be constructible without supplying created_at.
        assert ScanSpecification.model_validate_json(spec.model_dump_json())

    def test_head_is_not_a_valid_pin(self) -> None:
        with pytest.raises(ValueError):
            ScanSpecification(
                target_repository_url=JVA_URL,
                target_commit_sha="HEAD",
                tools=[ToolConfig(tool="semgrep")],
            )


class TestNegativePaths:
    def test_invalid_cwe_rejected(self) -> None:
        with pytest.raises(ValueError):
            Observation(
                rule_id="x",
                severity="high",
                cwe="NOT-A-CWE",
                location_path="A.java",
                location_line=10,
            )

    def test_malformed_cvss_rejected(self) -> None:
        with pytest.raises(ValueError):
            Assessment(
                finding_id="f1",
                cvss_vector="CVSS:4.0/AV:N",
                proposed_conclusion="confirmed",
            )

    def test_bad_checksum_rejected(self) -> None:
        with pytest.raises(ValueError):
            ArtifactReference(
                path="raw/semgrep.json",
                checksum_sha256="tooshort",
                mime_type="application/json",
            )

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValueError):
            Observation.model_validate(
                {
                    "rule_id": "x",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "location_path": "A.java",
                    "location_line": 10,
                    "unexpected_extra": "leak",
                }
            )


class TestEvaluationIsolation:
    """SRS 4.2: evaluator-only fields must not appear on inference-facing models."""

    @pytest.mark.parametrize(
        "model",
        [Finding, Observation, Assessment],
    )
    def test_no_evaluator_only_fields(self, model) -> None:
        fields = set(model.model_fields.keys())
        assert "expected_label" not in fields, "evaluator label leaked into inference model"
        assert "fixed_variant_ref" not in fields, "fixed-variant ref leaked into inference model"
        assert "review_judgment" not in fields, "review judgment leaked into inference model"

    def test_evaluation_case_carries_the_labels(self) -> None:
        # The evaluator-only model is where these belong.
        fields = set(EvaluationCase.model_fields.keys())
        assert "expected_labels" in fields or "expected_finding_identity" in fields
