"""The Python ruleset must cover common webapp vulnerability classes.

Every rule is exercised against a real Semgrep run, in both directions: it must
fire on the vulnerable fixture and stay silent on the safe one. A rule that
never fires is worse than no rule, because the scanner reports a clean repo.

The whole fixture directory is scanned in ONE Semgrep invocation. Per-fixture
isolation does not change what a rule matches (each fixture is a standalone
file), but it costs ~6s of process start per case — batching keeps the run
to a single process start.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "src" / "vulnscan" / "scanners" / "rules" / "python.yml"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "python"

# rule id -> (vulnerable fixture, safe fixture)
CASES = {
    "py-sql-injection": ("VulnSql", "SafeSql"),
    "py-xss-markup-bypass": ("VulnXss", "SafeXss"),
    "py-command-injection": ("VulnCommand", "SafeCommand"),
    "py-path-traversal-open": ("VulnPath", "SafePath"),
    "py-ssrf-requests": ("VulnSsrf", "SafeSsrf"),
    "py-ssti-jinja2": ("VulnSsti", "SafeSsti"),
    "py-unsafe-deserialization": ("VulnDeser", "SafeDeser"),
    "py-hardcoded-secret": ("VulnSecret", "SafeSecret"),
    "py-weak-random-token": ("VulnRandom", "SafeRandom"),
    "py-code-injection-eval": ("VulnEval", "SafeEval"),
}

# Fixtures outside CASES that pin sanitizer/taint boundaries.
SILENT_FIXTURES = {
    "SanitizedCommand": set(),
    "SanitizedXss": set(),
}


@pytest.fixture(scope="session")
def semgrep() -> str:
    """QR-20/23: find the provisioned scanner on any supported platform.

    A missing scanner must fail loudly. Skipping here used to make the whole
    ruleset look green in a venv without the `scanners` extra, which is the
    one state where these tests cannot say anything about the rules.
    """
    executable = shutil.which("semgrep")
    if executable:
        return executable
    script = Path(sysconfig.get_path("scripts")) / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if not script.is_file():
        pytest.fail(
            "semgrep is required: run `uv sync --extra scanners` before running "
            "the Python ruleset tests"
        )
    return str(script)


@pytest.fixture(scope="module")
def findings_by_file(semgrep: str, tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[str]]:
    """Scan every fixture once and group the matched rule ids by file name."""
    staged = tmp_path_factory.mktemp("python-rule-scan")
    for source in FIXTURES.glob("*.py"):
        shutil.copy(source, staged / source.name)

    result = subprocess.run(
        [
            semgrep,
            "scan",
            "--config",
            str(RULES),
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            str(staged),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, f"semgrep failed: {result.stderr[-2000:]}"
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert not payload.get("errors"), payload["errors"]

    grouped: dict[str, set[str]] = {}
    for item in payload.get("results", []):
        name = item["path"].replace("\\", "/").rsplit("/", 1)[-1]
        grouped.setdefault(name, set()).add(item["check_id"].split(".")[-1])
    return grouped


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_fires_on_vulnerable_code(
    rule_id: str, fixtures: tuple, findings_by_file: dict
) -> None:
    assert findings_by_file.get(f"{fixtures[0]}.py", set()) == {rule_id}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_stays_quiet_on_safe_code(
    rule_id: str, fixtures: tuple, findings_by_file: dict
) -> None:
    assert findings_by_file.get(f"{fixtures[1]}.py", set()) == set()


@pytest.mark.parametrize("fixture,expected", SILENT_FIXTURES.items())
def test_sanitized_code_stays_quiet(fixture: str, expected: set, findings_by_file: dict) -> None:
    """shlex.quote() and escape() neutralize the taint flow, so no rule fires."""
    assert findings_by_file.get(f"{fixture}.py", set()) == expected
