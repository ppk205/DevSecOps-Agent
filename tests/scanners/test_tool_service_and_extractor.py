"""Tests for ScannerToolService, ResultExtractor, and 7-language OSV manifests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from vulnscan.contracts import (
    CWECategory,
    Observation,
    RunStatus,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.scanners.extractor import (
    explain_scanner_rule,
    extract_scanner_result,
    normalize_cwe_filter,
)
from vulnscan.scanners.osv_adapter import collect_packages
from vulnscan.scanners.tool_service import (
    SUPPORTED_LANGUAGE_FAMILIES,
    ScannerToolService,
    detect_snapshot_languages,
)


def _obs(
    obs_id: str,
    tool: ToolName,
    rule_id: str,
    file_path: str,
    line: int,
    *,
    cwe: CWECategory = CWECategory.SQL_INJECTION,
    severity: Severity = Severity.HIGH,
    cvss: float | None = None,
) -> Observation:
    meta = {"cvss": cvss} if cvss is not None else {}
    return Observation(
        observation_id=obs_id,
        run_id="r1",
        tool=tool,
        tool_version="1.0",
        rule_id=rule_id,
        cwe_category=cwe,
        severity=severity,
        message=f"Finding {rule_id}",
        location=SourceCoordinate(file_path=file_path, line_start=line, line_end=line),
        detected_at=datetime.now(UTC),
        metadata=meta,
    )


def _fake_result(tool: ToolName, observations: list[Observation]) -> ScannerResult:
    now = datetime.now(UTC)
    return ScannerResult(
        run_id="r1",
        tool=tool,
        tool_version="test-1.0",
        adapter_version="0.1.0",
        status=RunStatus.COMPLETED,
        started_at=now,
        finished_at=now,
        observations=observations,
        coverage_records=[],
        eligible_units=len(observations),
        analyzed_units=len(observations),
    )


class TestSevenLanguageSupport:
    def test_detect_all_seven_language_families(self, tmp_path: Path) -> None:
        files = [
            "src/App.java",
            "web/index.ts",
            "api/app.py",
            "legacy/login.php",
            "cmd/server.go",
            "native/parser.cpp",
            "dotnet/Service.cs",
        ]
        for rel in files:
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("// stub\n", encoding="utf-8")

        detected = detect_snapshot_languages(tmp_path)
        assert tuple(detected) == SUPPORTED_LANGUAGE_FAMILIES

    def test_osv_collect_packages_all_seven_ecosystems(self, tmp_path: Path) -> None:
        (tmp_path / "pom.xml").write_text(
            "<project><dependencies><dependency>"
            "<groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId><version>2.14.1</version>"
            "</dependency></dependencies></project>",
            encoding="utf-8",
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.15"}}}),
            encoding="utf-8",
        )
        (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
        (tmp_path / "composer.lock").write_text(
            json.dumps({"packages": [{"name": "symfony/http-kernel", "version": "v5.4.0"}]}),
            encoding="utf-8",
        )
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n",
            encoding="utf-8",
        )
        (tmp_path / "conanfile.txt").write_text(
            "[requires]\nopenssl/1.1.1k\n",
            encoding="utf-8",
        )
        (tmp_path / "App.csproj").write_text(
            '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>',
            encoding="utf-8",
        )

        packages, manifests = collect_packages(tmp_path)
        ecosystems = {p.ecosystem for p in packages}
        assert ecosystems == {"Maven", "npm", "PyPI", "Packagist", "Go", "ConanCenter", "NuGet"}
        assert len(manifests) == 7

        # Targeted single manifest filter
        go_pkgs, go_manifests = collect_packages(tmp_path, manifest_path="go.mod")
        assert len(go_pkgs) == 1
        assert go_pkgs[0].ecosystem == "Go"
        assert go_manifests == ["go.mod"]


class TestResultExtractor:
    def test_prioritizes_severity_filters_cwe_and_caps_items(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("line1\nline2\neval(user_input)\nline4\n", encoding="utf-8")
        obs = [
            _obs("o1", ToolName.SEMGREP, "r-low", "a.py", 1, cwe=CWECategory.XSS, severity=Severity.LOW),
            _obs("o2", ToolName.SEMGREP, "r-crit", "a.py", 3, cwe=CWECategory.SQL_INJECTION, severity=Severity.CRITICAL),
            _obs("o3", ToolName.SEMGREP, "r-high", "a.py", 2, cwe=CWECategory.SQL_INJECTION, severity=Severity.HIGH),
        ]
        res = _fake_result(ToolName.SEMGREP, obs)
        extracted = extract_scanner_result(res, snapshot_root=tmp_path, cwe="89", max_items=1)
        assert normalize_cwe_filter("89") == "CWE-89"
        assert extracted["total_observations"] == 3
        assert extracted["matched_observations"] == 2
        assert extracted["returned"] == 1
        assert extracted["truncated"] is True
        assert extracted["findings"][0]["severity"] == "critical"
        assert "eval(user_input)" in extracted["findings"][0]["snippet"]

    def test_explain_scanner_rule_bundled_and_fallback(self) -> None:
        # Fallback inference for generic rule IDs
        sqli = explain_scanner_rule("java.lang.security.audit.sqli", tool="semgrep")
        assert "CWE-89" in sqli["cwe"]
        assert "parameterized" in sqli["remediation"].lower()

        trivy = explain_scanner_rule("AVD-DS-0002", tool="trivy")
        assert "CWE-16" in trivy["cwe"]


class TestScannerToolService:
    def test_path_traversal_escape_blocked(self, tmp_path: Path) -> None:
        svc = ScannerToolService(tmp_path)
        assert svc.run_semgrep(target_path="../etc/passwd")["status"] == "error"
        assert svc.run_codeql(target_path="../../secret")["status"] == "error"
        assert svc.run_owasp(manifest_path="../pom.xml")["status"] == "error"
        assert svc.run_secret_scan(target_path="../outside")["status"] == "error"
        assert svc.run_config_audit(target_path="../outside")["status"] == "error"

    def test_all_five_tools_and_session_query_cache(self, tmp_path: Path) -> None:
        (tmp_path / "App.java").write_text("class App {}\n", encoding="utf-8")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")

        mock_sg = MagicMock()
        mock_sg.run.return_value = _fake_result(
            ToolName.SEMGREP,
            [_obs("sg-1", ToolName.SEMGREP, "java.sqli", "App.java", 1, cwe=CWECategory.SQL_INJECTION, severity=Severity.HIGH)],
        )
        mock_cql = MagicMock()
        mock_cql.run.return_value = _fake_result(
            ToolName.CODEQL,
            [_obs("cql-1", ToolName.CODEQL, "java/sql-injection", "App.java", 1, cwe=CWECategory.SQL_INJECTION, severity=Severity.CRITICAL)],
        )
        mock_owasp = MagicMock()
        mock_owasp.run.return_value = _fake_result(
            ToolName.OWASP_DEPENDENCY_CHECK,
            [_obs("odc-1", ToolName.OWASP_DEPENDENCY_CHECK, "CVE-2021-44228", "pom.xml", 1, cwe=CWECategory.DEPENDENCY_VULNERABILITY, severity=Severity.CRITICAL, cvss=10.0)],
        )
        mock_gl = MagicMock()
        mock_gl.run.return_value = _fake_result(
            ToolName.GITLEAKS,
            [_obs("gl-1", ToolName.GITLEAKS, "generic-api-key", "App.java", 1, cwe=CWECategory.HARD_CODED_SECRET, severity=Severity.HIGH)],
        )
        mock_trivy = MagicMock()
        mock_trivy.run.return_value = _fake_result(
            ToolName.TRIVY,
            [_obs("trv-1", ToolName.TRIVY, "AVD-DS-0002", "Dockerfile", 1, cwe=CWECategory.SECURITY_MISCONFIGURATION, severity=Severity.HIGH)],
        )

        svc = ScannerToolService(
            tmp_path,
            semgrep_adapter=mock_sg,
            codeql_adapter=mock_cql,
            owasp_adapter=mock_owasp,
            gitleaks_adapter=mock_gl,
            trivy_adapter=mock_trivy,
        )

        assert svc.run_semgrep(target_path="App.java")["returned"] == 1
        assert svc.run_codeql(language="java")["returned"] == 1
        assert svc.run_owasp(min_cvss=9.0)["returned"] == 1
        assert svc.run_secret_scan(target_path="App.java")["returned"] == 1
        assert svc.run_config_audit(target_path="Dockerfile", check_type="iac_config")["returned"] == 1

        # PHP CodeQL gracefully skips with actionable Semgrep hint
        php_cql = svc.run_codeql(language="php")
        assert php_cql["status"] == "skipped"
        assert "semgrep" in php_cql["errors"][0].lower()

        # Consolidated query returns all 5 cached observations without rerunning tools
        all_q = svc.query_findings(tool="all")
        assert all_q["total_matched"] == 5
        cql_q = svc.query_findings(tool="codeql", cwe="CWE-89")
        assert cql_q["total_matched"] == 1
        assert cql_q["results"][0]["rule_id"] == "java/sql-injection"

    def test_live_semgrep_scan_through_tool_service(self, tmp_path: Path) -> None:
        """Integration test invoking the real Semgrep binary installed in the venv."""
        vuln = tmp_path / "vuln.py"
        vuln.write_text(
            "import subprocess\n"
            "def run(user_cmd):\n"
            "    subprocess.Popen(user_cmd, shell=True)\n",
            encoding="utf-8",
        )
        svc = ScannerToolService(tmp_path)
        res = svc.run_semgrep(target_path="vuln.py", language="python")
        assert res["status"] == "completed"
        assert res["returned"] >= 1
        assert any("vuln.py" in f["file"] for f in res["findings"])

    def test_semgrep_registry_pack_falls_back_to_bundled_offline(self, tmp_path: Path) -> None:
        """Explicit p/ ruleset combines with bundled pack and falls back cleanly if offline."""
        (tmp_path / "App.java").write_text("class App {}", encoding="utf-8")
        seen_specs: list[list[str]] = []

        def _fake_run(spec, *, workdir):
            rule_paths = list(spec.tools[0].rule_paths)
            seen_specs.append(rule_paths)
            if any(p.startswith("p/") for p in rule_paths):
                return ScannerResult(
                    run_id=spec.run_id or "r",
                    tool=ToolName.SEMGREP,
                    tool_version="1.178.0",
                    adapter_version="0.2.0",
                    status=RunStatus.FAILED,
                    started_at=datetime.now(UTC),
                    finished_at=datetime.now(UTC),
                    errors=["offline registry unreachable"],
                )
            return _fake_result(
                ToolName.SEMGREP, [_obs("obs-sg-1", ToolName.SEMGREP, "java-sqli", "App.java", 1)]
            )

        mock_sg = MagicMock()
        mock_sg.run.side_effect = _fake_run
        svc = ScannerToolService(tmp_path, semgrep_adapter=mock_sg)

        out = svc.run_semgrep(target_path="App.java", ruleset="p/owasp-top-ten", language="java")
        assert out["status"] == "completed"
        assert out["returned"] == 1
        assert len(seen_specs) == 2
        assert "p/owasp-top-ten" in seen_specs[0]
        assert all(not p.startswith("p/") for p in seen_specs[1])

    def test_parse_pom_xml_interpolates_properties_and_parent(self) -> None:
        """parse_pom_xml resolves ${property} versions and includes <parent> BOM."""
        from vulnscan.scanners.osv_adapter import parse_pom_xml

        pom = """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <parent>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-parent</artifactId>
            <version>3.2.5</version>
          </parent>
          <properties>
            <hsqldb.version>2.7.2</hsqldb.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.hsqldb</groupId>
              <artifactId>hsqldb</artifactId>
              <version>${hsqldb.version}</version>
            </dependency>
          </dependencies>
        </project>
        """
        pkgs = parse_pom_xml(pom, manifest="pom.xml")
        coords = {(p.name, p.version) for p in pkgs}
        assert ("org.springframework.boot:spring-boot-starter-parent", "3.2.5") in coords
        assert ("org.hsqldb:hsqldb", "2.7.2") in coords
