"""OSV.dev adapter: manifest parsing, CVE mapping, offline-degraded result."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from vulnscan.contracts import RunStatus, ScanSpecification, Severity, ToolName
from vulnscan.contracts.scan_spec import ToolConfig
from vulnscan.scanners.osv_adapter import (
    OSVAdapter,
    OsvPackage,
    collect_packages,
    map_osv_response,
    parse_package_lock,
    parse_pom_xml,
    parse_requirements_txt,
)

POM_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>noversion</artifactId>
    </dependency>
  </dependencies>
</project>
"""

LOCK_V7 = {
    "packages": {
        "": {"name": "shop", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/left-pad": {"version": ""},
    }
}

LOCK_LEGACY = {"dependencies": {"express": {"version": "4.17.1"}}}

REQUIREMENTS_SAMPLE = """\
# web deps
Django==4.2.7  # pinned
requests==2.31.0; python_version > "3.8"
flask>=2.0  # unpinned, must be skipped
-r other.txt
https://example.com/pkg.tar.gz
"""


def _spec(**overrides) -> ScanSpecification:
    tools = overrides.pop("tools", [ToolConfig(tool=ToolName.OWASP_DEPENDENCY_CHECK, enabled=True)])
    return ScanSpecification(
        run_id="r-osv",
        target_repository_url="https://example.com/repo.git",
        target_commit_sha="a" * 40,
        tools=tools,
        **overrides,
    )


class TestManifestParsing:
    def test_pom_dependencies(self) -> None:
        packages = parse_pom_xml(POM_SAMPLE, manifest="pom.xml")
        assert [(p.name, p.version) for p in packages] == [
            ("org.apache.logging.log4j:log4j-core", "2.14.0")
        ]
        assert all(p.ecosystem == "Maven" for p in packages)

    def test_pom_rejects_entity_declarations(self) -> None:
        evil = '<!DOCTYPE x [<!ENTITY a "b">]><project></project>'
        assert parse_pom_xml(evil, manifest="pom.xml") == []

    def test_package_lock_v7_and_legacy(self) -> None:
        v7 = parse_package_lock(LOCK_V7, manifest="package-lock.json")
        assert [(p.name, p.version) for p in v7] == [("lodash", "4.17.20")]
        assert all(p.ecosystem == "npm" for p in v7)
        legacy = parse_package_lock(LOCK_LEGACY, manifest="package-lock.json")
        assert [(p.name, p.version) for p in legacy] == [("express", "4.17.1")]

    def test_requirements_txt_pins_only(self) -> None:
        packages = parse_requirements_txt(REQUIREMENTS_SAMPLE, manifest="requirements.txt")
        assert [(p.name, p.version) for p in packages] == [
            ("Django", "4.2.7"),
            ("requests", "2.31.0"),
        ]
        assert all(p.ecosystem == "PyPI" for p in packages)

    def test_collect_packages_from_checkout(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("Django==4.2.7\n", encoding="utf-8")
        sub = tmp_path / "web"
        sub.mkdir()
        (sub / "package-lock.json").write_text(
            '{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}',
            encoding="utf-8",
        )
        packages, manifests = collect_packages(tmp_path)
        assert manifests == ["requirements.txt", "web/package-lock.json"]
        assert {(p.ecosystem, p.name) for p in packages} == {
            ("PyPI", "Django"),
            ("npm", "lodash"),
        }


class TestCveMapping:
    def _queries(self) -> list[OsvPackage]:
        return [
            OsvPackage(
                ecosystem="PyPI", name="Django", version="4.2.7", manifest="requirements.txt"
            )
        ]

    def test_cvss_score_maps_to_severity(self) -> None:
        response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "CVE-2024-1234",
                            "summary": "Example vuln",
                            "severity": [{"type": "CVSS_V3", "score": 9.8}],
                            "aliases": ["GHSA-xxxx-yyyy"],
                        }
                    ]
                }
            ]
        }
        (obs,) = map_osv_response(
            self._queries(),
            response,
            run_id="r-osv",
            tool_version="osv.dev",
            source_snapshot="abc",
        )
        assert obs.rule_id == "osv-CVE-2024-1234"
        assert obs.severity == Severity.CRITICAL
        assert obs.tool == ToolName.OWASP_DEPENDENCY_CHECK
        assert obs.tool_version == "osv.dev"
        assert obs.dependency_identity == "PyPI/Django@4.2.7"

    def test_missing_cvss_defaults_to_high(self) -> None:
        response = {"results": [{"vulns": [{"id": "CVE-2024-9999", "summary": "No score"}]}]}
        (obs,) = map_osv_response(
            self._queries(),
            response,
            run_id="r-osv",
            tool_version="osv.dev",
            source_snapshot="abc",
        )
        assert obs.rule_id == "osv-CVE-2024-9999"
        assert obs.severity == Severity.HIGH


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class TestRunBehaviour:
    def test_offline_returns_skipped_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "requirements.txt").write_text("Django==4.2.7\n", encoding="utf-8")

        def _offline(*args, **kwargs) -> object:
            raise httpx.ConnectError("offline")

        monkeypatch.setattr(httpx, "post", _offline)
        result = OSVAdapter().run(_spec(), workdir=str(tmp_path))
        assert result.status == RunStatus.SKIPPED
        assert result.tool_version == "osv.dev"
        assert result.observations == []
        assert any("osv.dev" in err for err in result.errors)

    def test_success_maps_cves(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "requirements.txt").write_text("Django==4.2.7\n", encoding="utf-8")
        payload = {
            "results": [
                {"vulns": [{"id": "CVE-2024-1234", "severity": [{"score": 5.5}]}]},
            ]
        }
        monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse(payload))
        result = OSVAdapter().run(_spec(), workdir=str(tmp_path))
        assert result.status == RunStatus.COMPLETED
        assert result.tool == ToolName.OWASP_DEPENDENCY_CHECK
        assert result.tool_version == "osv.dev"
        assert [o.rule_id for o in result.observations] == ["osv-CVE-2024-1234"]
        assert result.observations[0].severity == Severity.MEDIUM

    def test_disabled_tool_returns_skipped(self, tmp_path: Path) -> None:
        spec = _spec(tools=[ToolConfig(tool=ToolName.OWASP_DEPENDENCY_CHECK, enabled=False)])
        result = OSVAdapter().run(spec, workdir=str(tmp_path))
        assert result.status == RunStatus.SKIPPED
