"""T07 gate: evaluation cases — loading, validation, split summary."""

from pathlib import Path

from vulnscan.contracts.enums import (
    SplitMembership,
    VariantRelationship,
)
from vulnscan.evaluation.cases import (
    case_families,
    create_sample_cases,
    load_cases,
    save_cases,
    split_summary,
    validate_cases,
)


class TestCaseManagement:
    def test_sample_cases_created(self):
        cases = create_sample_cases()
        assert len(cases) == 9  # 3 CWE groups x 3 cases each

    def test_sample_families(self):
        cases = create_sample_cases()
        families = case_families(cases)
        assert len(families) == 3
        assert all(len(v) == 3 for v in families.values())

    def test_sample_split_summary(self):
        cases = create_sample_cases()
        summary = split_summary(cases)
        assert summary["total_cases"] == 9
        assert summary["families"] == 3
        assert summary["by_split"]["development"] == 3
        assert summary["by_split"]["held_out"] == 6

    def test_no_duplicate_ids(self):
        cases = create_sample_cases()
        errors = validate_cases(cases)
        assert errors == []

    def test_invalid_regression_held_out(self):
        """Regression variant cannot be held-out (must match parent split)."""
        from vulnscan.contracts.evaluation import EvaluationCase, MatchingCriteria

        cases = create_sample_cases()
        bad = EvaluationCase(
            case_id="bad-case",
            case_family="family-1",
            split=SplitMembership.HELD_OUT,
            variant_relationship=VariantRelationship.REGRESSION,
            matching_criteria=MatchingCriteria(),
            source_commit_sha="aaa111",
            variant_path="harness/JVA-bookstore-regression",
            created_at="2026-01-01T00:00:00Z",
        )
        errors = validate_cases(cases + [bad])
        assert any("regression" in e.lower() for e in errors)

    def test_save_and_load(self, tmp_path: Path):
        cases = create_sample_cases()
        save_path = tmp_path / "cases.json"
        save_cases(cases, save_path)
        loaded = load_cases(save_path)
        assert len(loaded) == 9
        assert loaded[0].case_id == cases[0].case_id
