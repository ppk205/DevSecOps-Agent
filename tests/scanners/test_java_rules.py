"""The Java ruleset must cover common webapp vulnerability classes.

Every rule is exercised against a real Semgrep run, in both directions: it must
fire on the vulnerable fixture and stay silent on the safe one. A rule that
never fires is worse than no rule, because the scanner reports a clean repo.

The whole fixture directory is scanned in ONE Semgrep invocation. Per-fixture
isolation does not change what a rule matches (each fixture is a standalone
compilable file), but it costs ~6s of process start per case — 24 cases became
147s, while the batched run sees the same rules fire in ~6s.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "src" / "vulnscan" / "scanners" / "rules" / "java.yml"
SEMGREP = ROOT / ".venv" / "Scripts" / "semgrep.exe"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "java"

# rule id -> (vulnerable fixture, safe fixture)
CASES = {
    "java-xss-response-writer": ("VulnXss", "SafeXss"),
    "java-path-traversal-file": ("VulnPath", "SafePath"),
    "java-weak-cipher": ("VulnCipher", "SafeCipher"),
    "java-insecure-random": ("VulnRandom", "SafeRandom"),
    "java-unsafe-deserialization": ("VulnDeserialize", "SafeDeserialize"),
    "java-xxe-document-builder": ("VulnXxe", "SafeXxe"),
    "java-weak-cipher-secret-key": ("VulnKey", "SafeKey"),
    "java-trust-all-certificates": ("VulnTls", "SafeTls"),
    "java-unsafe-deserialization-objectmapper": ("VulnMapper", "SafeMapper"),
    "java-permissive-cors": ("VulnCors", "SafeCors"),
}

# Fixtures outside CASES that pin the XSS rule's boundaries.
SILENT_FIXTURES = {
    "LogConsole": set(),
    "StaticJson": set(),
    "SanitizedXss": set(),
    "ComputedXss": {"java-xss-response-writer"},
}


@pytest.fixture(scope="module")
def findings_by_file() -> dict[str, set[str]]:
    """Scan every fixture once and group the matched rule ids by file name."""
    staged = ROOT / ".pytest_cache" / "java-rule-scan"
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)
    for source in FIXTURES.glob("*.java"):
        shutil.copy(source, staged / source.name)

    # A missing scanner must fail loudly. Skipping here used to make the whole
    # ruleset look green in a venv without the `scanners` extra, which is the
    # one state where these tests cannot say anything about the rules.
    if not SEMGREP.is_file():
        pytest.fail(
            f"semgrep not installed at {SEMGREP}; run `uv sync --extra scanners` "
            "(or reinstall the scanner extras) before running the Java ruleset tests"
        )

    result = subprocess.run(
        [
            str(SEMGREP),
            "scan",
            "--config",
            str(RULES),
            "--metrics=off",
            "--no-git-ignore",
            "--json",
            str(staged),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, f"semgrep failed: {result.stderr[-2000:]}"
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert payload.get("errors") == [], payload["errors"]

    grouped: dict[str, set[str]] = {}
    for item in payload.get("results", []):
        name = item["path"].replace("\\", "/").rsplit("/", 1)[-1]
        grouped.setdefault(name, set()).add(item["check_id"].split(".")[-1])
    return grouped


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_fires_on_vulnerable_code(
    rule_id: str, fixtures: tuple, findings_by_file: dict
) -> None:
    assert findings_by_file.get(f"{fixtures[0]}.java", set()) == {rule_id}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_stays_quiet_on_safe_code(
    rule_id: str, fixtures: tuple, findings_by_file: dict
) -> None:
    assert findings_by_file.get(f"{fixtures[1]}.java", set()) == set()


@pytest.mark.parametrize("fixture,expected", SILENT_FIXTURES.items())
def test_xss_rule_boundaries(fixture: str, expected: set, findings_by_file: dict) -> None:
    """Console logging, static JSON and escaped output stay quiet; request data
    serialised then written is the real signal and must survive."""
    assert findings_by_file.get(f"{fixture}.java", set()) == expected
