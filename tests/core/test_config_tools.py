"""ScanConfig.tools override: subset of scanners without changing profile."""

from vulnscan.contracts import ToolName
from vulnscan.core.config import ScanConfig


def test_default_tools_come_from_profile() -> None:
    spec = ScanConfig(profile="fast").specification(".", "abc", "local")
    assert {c.tool for c in spec.tools} == {
        ToolName.SEMGREP,
        ToolName.NATIVE_HUNT,
        ToolName.GITLEAKS,
    }


def test_tools_override_subset() -> None:
    spec = ScanConfig(profile="fast", tools=["semgrep"]).specification(".", "abc", "local")
    assert [c.tool for c in spec.tools] == [ToolName.SEMGREP]


def test_tools_override_rejects_unknown() -> None:
    try:
        ScanConfig(profile="fast", tools=["nope"]).specification(".", "abc", "local")
    except ValueError as exc:
        assert "Unknown scanner tool" in str(exc)
    else:
        raise AssertionError("expected ValueError")
