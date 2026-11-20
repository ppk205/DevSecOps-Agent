"""ScanConfig.tools override: subset of scanners without changing profile."""

from vulnscan.contracts import ToolName
from vulnscan.core.config import ScanConfig


def test_default_tools_come_from_profile() -> None:
    fast = ScanConfig(profile="fast").specification(".", "abc", "local")
    full = ScanConfig(profile="full").specification(".", "abc", "local")
    fast_tools = [ToolName.SEMGREP, ToolName.NATIVE_HUNT, ToolName.GITLEAKS]
    assert [config.tool for config in fast.tools] == fast_tools
    assert [config.tool for config in full.tools] == [
        *fast_tools,
        ToolName.SPOTBUGS,
        ToolName.OWASP_DEPENDENCY_CHECK,
    ]


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
