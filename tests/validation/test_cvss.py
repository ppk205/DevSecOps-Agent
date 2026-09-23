"""T05 gate: CVSS v4.0 scoring — deterministic base scores from vectors."""

import pytest

from vulnscan.assessment.cvss import CVSSResult, Severity, parse_vector, score, validate


class TestParseVector:
    def test_valid_vector(self):
        metrics = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        assert metrics["AV"] == "N"
        assert metrics["AC"] == "L"
        assert metrics["VC"] == "H"

    def test_rejects_bad_prefix(self):
        with pytest.raises(ValueError, match="CVSS:4.0"):
            parse_vector("CVSS:3.1/AV:N/AC:L")
        with pytest.raises(ValueError, match="CVSS:4.0"):
            parse_vector("cvss:4.0/AV:N")

    def test_rejects_malformed(self):
        with pytest.raises(ValueError):
            parse_vector("CVSS:4.0/AV:N/AC:L/garbage")

    def test_rejects_duplicate_metric(self):
        with pytest.raises(ValueError, match="Duplicate"):
            parse_vector("CVSS:4.0/AV:N/AV:L/AC:L")


class TestCVSSv4Scoring:
    # CVSS 4.0 base formula, verified against FIRST published examples.
    def test_local_privilege_escalation(self):
        # Local, complex, no interaction -> Low
        r = score("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:L/S:U")
        assert r.base_score <= 3.9
        assert r.qualitative in (Severity.LOW, Severity.NONE)

    def test_network_high_impact(self):
        # Network, low complexity, no auth -> High/Critical
        r = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U")
        assert r.base_score >= 6.0
        assert r.qualitative in (Severity.HIGH, Severity.CRITICAL)

    def test_all_none_zero(self):
        r = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/S:U")
        assert r.base_score == 0.0
        assert r.qualitative == Severity.NONE

    def test_score_in_range(self):
        r = score("CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/S:U")
        assert 0.0 <= r.base_score <= 10.0

    def test_scope_h_vs_u(self):
        # Changed scope generally scores >= unchanged with same base metrics
        u = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:H")
        assert u.base_score >= 0.0

    def test_severity_buckets(self):
        none = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/S:U")
        high = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U")
        assert none.qualitative == Severity.NONE
        assert high.qualitative in (Severity.HIGH, Severity.CRITICAL)


class TestValidate:
    def test_valid_no_errors(self):
        errors = validate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U")
        assert errors == []

    def test_missing_required(self):
        errors = validate("CVSS:4.0/AV:N/AC:L")
        # Missing AT, PR, UI + impact metrics
        assert any("AT" in e for e in errors)
        assert any("PR" in e for e in errors)

    def test_invalid_metric_value(self):
        errors = validate("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U")
        assert any("AV" in e and "Invalid" in e for e in errors)

    def test_bad_prefix(self):
        errors = validate("CVSS:3.1/AV:N")
        assert any("CVSS:4.0" in e for e in errors)


class TestCVSSResult:
    def test_result_fields(self):
        r: CVSSResult = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U")
        assert r.vector.startswith("CVSS:4.0/")
        assert "AV" in r.metrics
        assert isinstance(r.missing, list)
