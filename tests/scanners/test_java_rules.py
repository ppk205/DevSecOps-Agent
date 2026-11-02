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
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "src" / "vulnscan" / "scanners" / "rules" / "java.yml"
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
    "java-ldap-injection": ("VulnLdap", "SafeLdap"),
    "java-xpath-injection": ("VulnXpath", "SafeXpath"),
    "java-ssrf-url-connection": ("VulnSsrf", "SafeSsrf"),
    "java-command-injection-processbuilder": ("VulnProc", "SafeProc"),
    "java-open-redirect": ("VulnRedirect", "SafeRedirect"),
    "java-unsafe-reflection": ("VulnReflect", "SafeReflect"),
    "java-log-injection": ("VulnLog", "SafeLog"),
    "java-insecure-cookie": ("VulnCookie", "SafeCookie"),
    "java-hardcoded-credentials": ("VulnSecret", "SafeSecret"),
    "java-stack-trace-exposure": ("VulnStack", "SafeStack"),
    "java-xxe-sax-parser": ("VulnSax", "SafeSax"),
    "java-path-traversal-nio": ("VulnNio", "SafeNio"),
}

# Fixtures outside CASES that pin rule boundaries: console logging, static
# JSON and escaped output stay quiet; request data serialised then written
# is the real signal and must survive. The same idea applies to the new
# rules: an encoded LDAP filter and a Secure-only cookie stay quiet.
SILENT_FIXTURES = {
    "LogConsole": set(),
    "StaticJson": set(),
    "SanitizedXss": set(),
    "ComputedXss": {"java-xss-response-writer"},
    "SanitizedLdap": set(),
    "PartialCookie": set(),
}

# FR-23: every TLS verification bypass shape, and validating/unrelated look-alikes.
TLS_BYPASSES = [
    "VulnTrustManager",
    "VulnNamedTrustManager",
    "VulnHostnameVerifier",
    "VulnNamedHostnameVerifier",
    "VulnInstanceHostnameVerifier",
]
TLS_LOOKALIKES = ["SafeTrustManager", "SafeHostnameVerifier", "UnrelatedInit"]


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
            "the Java ruleset tests"
        )
    return str(script)


@pytest.fixture(scope="module")
def findings_by_file(semgrep: str, tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[str]]:
    """Scan every fixture once and group the matched rule ids by file name."""
    staged = tmp_path_factory.mktemp("java-rule-scan")
    for source in FIXTURES.glob("*.java"):
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


@pytest.mark.parametrize("fixture", TLS_BYPASSES)
def test_fr23_tls_verification_bypasses_are_detected(fixture: str, findings_by_file: dict) -> None:
    assert findings_by_file.get(f"{fixture}.java", set()) == {"java-trust-all-certificates"}


@pytest.mark.parametrize("fixture", TLS_LOOKALIKES)
def test_fr23_validating_tls_and_unrelated_methods_are_not_flagged(
    fixture: str, findings_by_file: dict
) -> None:
    assert findings_by_file.get(f"{fixture}.java", set()) == set()
