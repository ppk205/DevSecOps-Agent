"""SonarCloud analyses the mixed-language repository rather than skipping Maven."""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCAN_ACTION = "SonarSource/sonarqube-scan-action@4d1dc0c91ee400dcf8a6dddf2f705ac36542e304"


def properties() -> dict[str, str]:
    text = (ROOT / "sonar-project.properties").read_text(encoding="utf-8")
    return dict(
        line.split("=", 1)
        for line in text.replace("\\\n", "").splitlines()
        if line.strip() and not line.startswith("#")
    )


def matches(path: str, patterns: str) -> bool:
    return any(fnmatch.fnmatchcase(path, item.strip()) for item in patterns.split(","))


def test_sonarcloud_runs_standard_scan_with_repository_configuration():
    data = yaml.load(
        (ROOT / ".github/workflows/sonarcloud.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(data["on"]["push"]["branches"]) >= {"main", "dev"}
    assert "pull_request" in data["on"] and "workflow_dispatch" in data["on"]
    job = data["jobs"]["sonarcloud"]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == "0"
    assert checkout["with"]["persist-credentials"] == "false"
    scan = next(s for s in job["steps"] if s.get("uses") == SCAN_ACTION)
    assert scan["env"]["SONAR_TOKEN"] == "${{ secrets.SONAR_TOKEN }}"
    assert "${{ vars.SONAR_ORGANIZATION }}" in scan["with"]["args"]
    assert "${{ vars.SONAR_PROJECT_KEY }}" in scan["with"]["args"]
    assert "if" not in scan and not scan.get("continue-on-error")
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "mvn" not in commands and "pom.xml" not in str(job)
    for name in ("SONAR_TOKEN", "SONAR_ORGANIZATION", "SONAR_PROJECT_KEY"):
        assert f"${{{name}:?" in commands


def test_sonarcloud_includes_all_first_party_languages_without_test_overlap():
    config = properties()
    assert config["sonar.sources"] == config["sonar.tests"] == "."
    assert "sonar.language" not in config
    for path in (
        "src/vulnscan/harness/session.py",
        "internal/chat/model.go",
        "cmd/devsecops-agent/main.go",
        "web-ui/src/App.tsx",
        "web-ui/src/styles.css",
        "web-ui/index.html",
        "ci/scanners.Dockerfile",
        ".github/workflows/checks.yml",
        "scripts/check.py",
        "action.yml",
    ):
        assert not matches(path, config["sonar.exclusions"]), path
        assert not matches(path, config["sonar.test.inclusions"]), path
    for path in (
        "tests/harness/test_gates.py",
        "internal/chat/model_test.go",
        "cmd/devsecops-agent/main_test.go",
        "web-ui/src/api/remote.test.ts",
        "web-ui/src/pages/RemoteSessionPage.test.tsx",
        "web-ui/src/test-setup.ts",
    ):
        assert matches(path, config["sonar.test.inclusions"]), path
        assert matches(path, config["sonar.exclusions"]), path
        assert not matches(path, config["sonar.test.exclusions"]), path


def test_sonarcloud_excludes_generated_external_and_credential_files():
    config = properties()
    for path in (
        "evidence/run/result.json",
        "artifacts/scanner/A.java",
        "essay/report.docx",
        "web-ui/node_modules/library/index.js",
        "web-ui/dist/assets/index.js",
        "tests/fixtures/java/vulnerable/A.java",
        ".tools/check.py",
        ".venv/lib/a.py",
        ".devsec/sessions/log.jsonl",
        ".env",
        "config/.env.local",
        ".secrets",
        ".hermes/session.json",
        ".planning/state.md",
        "src/__pycache__/a.pyc",
    ):
        assert matches(path, config["sonar.exclusions"]), path
        assert matches(path, config["sonar.test.exclusions"]), path
    assert config["sonar.qualitygate.wait"] == "true"
    assert config["sonar.sourceEncoding"] == "UTF-8"
