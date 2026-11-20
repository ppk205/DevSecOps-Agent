"""Unified Scanner Tool Service — on-demand scanner hub for AI Agents and CLI.

Decouples targeted scanner invocations from the monolithic full-scan pipeline so
both the AI Agent (via OpenAI function calling) and CLI commands can invoke any
of the 5 security tools across all 7 language families, cache observations in
session, and return token-optimized JSON payloads.

Supported 5 Tool Groups:
1. Semgrep CE (SAST / AST pattern matching)
2. CodeQL (deep inter-procedural dataflow & taint tracking)
3. OWASP Dependency-Check / OSV.dev (SCA dependency vulnerabilities)
4. Gitleaks (secret & credential detection)
5. SpotBugs + FindSecBugs / Trivy (Java bytecode & IaC/Container config audit)

Supported 7 Language Families:
1. Java / JVM (Java, Kotlin, JSP)
2. JavaScript / TypeScript / Node.js
3. Python
4. PHP
5. Go
6. C / C++
7. C# / .NET
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    Finding,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    ToolConfig,
    ToolName,
)

from .base import AdapterRegistry, ScannerAdapter
from .codeql_adapter import CodeQLAdapter
from .dependency_check_adapter import DependencyCheckAdapter
from .extractor import (
    explain_scanner_rule,
    extract_findings_query,
    extract_scanner_result,
)
from .gitleaks_adapter import GitleaksAdapter
from .semgrep_adapter import SemgrepAdapter
from .spotbugs_adapter import SpotBugsAdapter
from .trivy_adapter import TrivyAdapter

SUPPORTED_LANGUAGE_FAMILIES: tuple[str, ...] = (
    "java",
    "javascript",
    "python",
    "php",
    "go",
    "cpp",
    "csharp",
)

#: Maps language family -> bundled Semgrep YAML rule pack filename (if present).
_BUNDLED_SEMGREP_RULES: dict[str, str] = {
    "java": "java.yml",
    "javascript": "javascript.yml",
    "python": "python.yml",
    "php": "php.yml",
}

#: Default community/registry Semgrep pack names for families without bundled YAML.
_SEMGREP_COMMUNITY_PACKS: dict[str, str] = {
    "go": "p/golang",
    "cpp": "p/c",
    "csharp": "p/csharp",
}

#: File extensions mapped to one of the 7 language families.
_EXT_TO_FAMILY: dict[str, str] = {
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".jsp": "java",
    ".jspx": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "javascript",
    ".py": "python",
    ".php": "php",
    ".phtml": "php",
    ".go": "go",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
}

_LANGUAGE_NORMALIZE: dict[str, str] = {
    "java": "java",
    "jvm": "java",
    "kotlin": "java",
    "jsp": "java",
    "javascript": "javascript",
    "typescript": "javascript",
    "js": "javascript",
    "ts": "javascript",
    "node": "javascript",
    "python": "python",
    "py": "python",
    "php": "php",
    "go": "go",
    "golang": "go",
    "c": "cpp",
    "cpp": "cpp",
    "c++": "cpp",
    "c/c++": "cpp",
    "csharp": "csharp",
    "c#": "csharp",
    "dotnet": "csharp",
    ".net": "csharp",
}

#: Dummy 40-char commit SHA used for ad-hoc local/snapshot tool invocations.
_ADHOC_COMMIT_SHA = "0" * 40


def normalize_language_family(raw: str | None) -> str | None:
    """Normalize a user/LLM language string into one of the 7 canonical families."""
    if not raw:
        return None
    return _LANGUAGE_NORMALIZE.get(str(raw).strip().lower())


def detect_snapshot_languages(snapshot_root: Path, max_files: int = 2000) -> list[str]:
    """Detect which of the 7 language families exist inside *snapshot_root*."""
    found: set[str] = set()
    count = 0
    try:
        for path in snapshot_root.rglob("*"):
            if not path.is_file():
                continue
            parts = path.parts
            if any(
                p in {".git", ".venv", "node_modules", "target", "dist", "build"} for p in parts
            ):
                continue
            fam = _EXT_TO_FAMILY.get(path.suffix.lower())
            if fam:
                found.add(fam)
            count += 1
            if count >= max_files:
                break
    except OSError:
        pass
    return [f for f in SUPPORTED_LANGUAGE_FAMILIES if f in found]


class ScannerToolService:
    """Facade executing on-demand security scans jailed to *snapshot_root*."""

    def __init__(
        self,
        snapshot_root: str | Path,
        *,
        findings: Sequence[Finding] = (),
        run_id: str = "agent-adhoc",
        commit_sha: str = _ADHOC_COMMIT_SHA,
        semgrep_adapter: ScannerAdapter | None = None,
        codeql_adapter: ScannerAdapter | None = None,
        owasp_adapter: ScannerAdapter | None = None,
        gitleaks_adapter: ScannerAdapter | None = None,
        spotbugs_adapter: ScannerAdapter | None = None,
        trivy_adapter: ScannerAdapter | None = None,
    ) -> None:
        self.snapshot_root = Path(snapshot_root).resolve()
        self.findings = list(findings)
        self.run_id = run_id
        self.commit_sha = (
            commit_sha
            if len(commit_sha) >= 7 and commit_sha.upper() != "HEAD"
            else _ADHOC_COMMIT_SHA
        )
        self.semgrep: ScannerAdapter = semgrep_adapter or SemgrepAdapter()
        self.codeql: ScannerAdapter = codeql_adapter or CodeQLAdapter()
        self.codeql.default_timeout = 75.0
        self.owasp: ScannerAdapter = owasp_adapter or DependencyCheckAdapter()
        self.gitleaks: ScannerAdapter = gitleaks_adapter or GitleaksAdapter()
        self.spotbugs: ScannerAdapter = spotbugs_adapter or SpotBugsAdapter()
        self.trivy: ScannerAdapter = trivy_adapter or TrivyAdapter()
        self._cached_results: dict[str, ScannerResult] = {}
        self._cached_observations: list[Observation] = []

    @classmethod
    def from_registry(
        cls,
        snapshot_root: str | Path,
        registry: AdapterRegistry,
        *,
        findings: Sequence[Finding] = (),
        run_id: str = "agent-adhoc",
        commit_sha: str = _ADHOC_COMMIT_SHA,
    ) -> ScannerToolService:
        """Create a service wired to adapters from an existing :class:`AdapterRegistry`."""
        return cls(
            snapshot_root,
            findings=findings,
            run_id=run_id,
            commit_sha=commit_sha,
            semgrep_adapter=registry.get(ToolName.SEMGREP),
            codeql_adapter=registry.get(ToolName.CODEQL),
            owasp_adapter=registry.get(ToolName.OWASP_DEPENDENCY_CHECK),
            gitleaks_adapter=registry.get(ToolName.GITLEAKS),
            spotbugs_adapter=registry.get(ToolName.SPOTBUGS),
            trivy_adapter=registry.get(ToolName.TRIVY),
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _jail_path(self, rel_path: str | None) -> tuple[str | None, str | None]:
        """Resolve *rel_path* inside ``snapshot_root``.

        Returns ``(posix_rel, None)`` on success or ``(None, error_message)``
        when the path escapes the snapshot or does not exist.
        """
        raw = (rel_path or ".").strip() or "."
        try:
            resolved = (self.snapshot_root / raw).resolve()
            rel = resolved.relative_to(self.snapshot_root).as_posix()
        except (OSError, ValueError):
            return None, f"path escapes the scan snapshot: {raw[:200]}"
        if not resolved.exists():
            return None, f"path does not exist inside snapshot: {raw[:200]}"
        return (rel or "."), None

    def _build_spec(
        self,
        tool: ToolName,
        *,
        language: str = "java",
        rule_paths: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> ScanSpecification:
        return ScanSpecification(
            run_id=self.run_id,
            target_repository_url=f"local://{self.snapshot_root.name}",
            target_commit_sha=self.commit_sha,
            language=language,
            tools=[
                ToolConfig(
                    tool=tool,
                    enabled=True,
                    rule_paths=rule_paths or [],
                    options=options or {},
                )
            ],
        )

    def _record_result(self, cache_key: str, result: ScannerResult) -> None:
        if (
            result.status == RunStatus.FAILED
            and result.errors
            and all(
                any(tok in err.lower() for tok in ("not found", "unavailable", "no such file"))
                for err in result.errors
            )
        ):
            result = result.model_copy(
                update={
                    "status": RunStatus.SKIPPED,
                    "warnings": [*result.warnings, *result.errors],
                    "errors": [],
                }
            )
        self._cached_results[cache_key] = result
        existing_ids = {o.observation_id for o in self._cached_observations}
        for obs in result.observations:
            if obs.observation_id not in existing_ids:
                self._cached_observations.append(obs)
                existing_ids.add(obs.observation_id)

    def _resolve_semgrep_rule_paths(
        self,
        ruleset: str | None,
        language: str | None,
    ) -> list[str]:
        rules_dir = Path(__file__).with_name("rules")
        if ruleset and ruleset.strip():
            raw = ruleset.strip()
            local_pack = rules_dir / (raw if raw.endswith(".yml") else f"{raw}.yml")
            if local_pack.is_file():
                return [str(local_pack)]
            raw_fam = normalize_language_family(raw)
            if raw_fam and _BUNDLED_SEMGREP_RULES.get(raw_fam):
                fam_pack = rules_dir / _BUNDLED_SEMGREP_RULES[raw_fam]
                if fam_pack.is_file():
                    return [str(fam_pack)]
            candidate_path = Path(raw)
            if candidate_path.is_file():
                return [str(candidate_path)]
            # Non-existent symbolic ruleset names invented by LLMs (e.g.
            # "security-audit", "default", "owasp") fall through to the
            # language-matched bundled rule pack below so offline Semgrep
            # never fails with exit code 7.

        fam = normalize_language_family(language)
        if fam:
            bundled = _BUNDLED_SEMGREP_RULES.get(fam)
            if bundled and (rules_dir / bundled).is_file():
                return [str(rules_dir / bundled)]
            community = _SEMGREP_COMMUNITY_PACKS.get(fam)
            if community:
                return [community]
        return []

    # ------------------------------------------------------------------ #
    # Public Tool Operations (5 Scanner Groups + Query + Explain)
    # ------------------------------------------------------------------ #

    def capabilities(self) -> dict[str, Any]:
        """Report installed availability and version of all 5 security tools."""
        adapters = {
            "semgrep": self.semgrep.capabilities(),
            "codeql": self.codeql.capabilities(),
            "owasp": self.owasp.capabilities(),
            "gitleaks": self.gitleaks.capabilities(),
            "spotbugs": self.spotbugs.capabilities(),
            "trivy": self.trivy.capabilities(),
        }
        tools_map: dict[str, dict[str, Any]] = {}
        for name, cap in adapters.items():
            if name == "owasp" and not cap.available:
                tools_map[name] = {
                    "tool": cap.tool.value,
                    "binary": cap.binary,
                    "available": True,
                    "version": "osv.dev-fallback",
                    "reason": "using built-in OSV.dev multi-ecosystem SCA fallback",
                }
            else:
                tools_map[name] = {
                    "tool": cap.tool.value,
                    "binary": cap.binary,
                    "available": cap.available,
                    "version": cap.version,
                    "reason": cap.reason,
                }
        return {
            "snapshot_root": str(self.snapshot_root),
            "detected_languages": detect_snapshot_languages(self.snapshot_root),
            "supported_language_families": list(SUPPORTED_LANGUAGE_FAMILIES),
            "tools": tools_map,
        }

    def run_semgrep(
        self,
        *,
        target_path: str = ".",
        ruleset: str | None = None,
        cwe: str | None = None,
        language: str | None = None,
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Run Semgrep AST/pattern scan on a jailed file or directory."""
        rel, err = self._jail_path(target_path)
        if err or rel is None:
            return {"tool": "semgrep", "status": "error", "error": err}

        fam = normalize_language_family(language)
        if fam is None and rel != ".":
            fam = _EXT_TO_FAMILY.get(Path(rel).suffix.lower())
        rule_paths = self._resolve_semgrep_rule_paths(ruleset, fam)

        spec = self._build_spec(
            ToolName.SEMGREP,
            language=fam or "java",
            rule_paths=rule_paths,
            options={"target_path": rel},
        )
        result = self.semgrep.run(spec, workdir=str(self.snapshot_root))
        self._record_result(f"semgrep:{rel}:{ruleset or fam or 'default'}", result)
        payload = extract_scanner_result(
            result,
            snapshot_root=self.snapshot_root,
            cwe=cwe,
            max_items=max_items,
        )
        payload["target_path"] = rel
        if fam:
            payload["language"] = fam
        return payload

    def run_codeql(
        self,
        *,
        target_path: str = ".",
        query_suite: str | None = None,
        cwe: str | None = None,
        language: str | None = None,
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Run CodeQL inter-procedural dataflow/taint analysis across supported families."""
        rel, err = self._jail_path(target_path)
        if err or rel is None:
            return {"tool": "codeql", "status": "error", "error": err}

        fam = normalize_language_family(language)
        if fam is None:
            detected = detect_snapshot_languages(self.snapshot_root)
            fam = detected[0] if detected else "java"

        if fam == "php":
            return {
                "tool": "codeql",
                "status": "skipped",
                "language": "php",
                "target_path": rel,
                "errors": [
                    (
                        "CodeQL does not natively support PHP dataflow; use run_semgrep_scan "
                        "with language='php' for PHP AST/taint rules."
                    )
                ],
                "findings": [],
            }

        import hashlib as _hashlib
        import tempfile as _tempfile

        target_fs = self.snapshot_root / rel
        codeql_workdir = str(target_fs if target_fs.is_dir() else self.snapshot_root)
        rel_hash = _hashlib.sha1(f"{self.snapshot_root}:{rel}".encode()).hexdigest()[:10]
        db_cache_dir = (
            Path(_tempfile.gettempdir())
            / "vulnscan-codeql-db"
            / f"{self.commit_sha[:12]}-{rel_hash}"
        )
        options: dict[str, Any] = {
            "language": fam,
            "database_dir": str(db_cache_dir),
        }
        if query_suite and query_suite.strip():
            options["suite"] = query_suite.strip()

        spec = self._build_spec(ToolName.CODEQL, language=fam, options=options)
        result = self.codeql.run(spec, workdir=codeql_workdir)
        if rel != "." and target_fs.is_dir():
            prefix = f"{rel.rstrip('/')}/"
            for obs in result.observations:
                fp = obs.location.file_path
                if not fp.startswith(prefix) and not Path(fp).is_absolute():
                    obs.location.file_path = f"{prefix}{fp}"
        self._record_result(f"codeql:{rel}:{fam}", result)

        file_filter = None if (rel == "." or target_fs.is_dir()) else rel
        payload = extract_scanner_result(
            result,
            snapshot_root=self.snapshot_root,
            cwe=cwe,
            file_path=file_filter,
            max_items=max_items,
        )
        payload["target_path"] = rel
        payload["language"] = fam
        return payload

    def run_owasp(
        self,
        *,
        manifest_path: str | None = None,
        min_cvss: float | None = None,
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Run OWASP Dependency-Check (or OSV.dev fallback) across 7 language manifests."""
        rel_manifest: str | None = None
        if manifest_path and manifest_path.strip():
            rel, err = self._jail_path(manifest_path)
            if err or rel is None:
                return {"tool": "owasp-dependency-check", "status": "error", "error": err}
            rel_manifest = rel

        options: dict[str, Any] = {}
        if rel_manifest:
            options["manifest_path"] = rel_manifest

        spec = self._build_spec(ToolName.OWASP_DEPENDENCY_CHECK, options=options)
        result = self.owasp.run(spec, workdir=str(self.snapshot_root))
        self._record_result(f"owasp:{rel_manifest or 'all'}", result)

        payload = extract_scanner_result(
            result,
            snapshot_root=self.snapshot_root,
            min_cvss=min_cvss,
            file_path=rel_manifest,
            max_items=max_items,
        )
        if rel_manifest:
            payload["manifest_path"] = rel_manifest
        if isinstance(result.metadata, dict):
            if "manifests" in result.metadata:
                payload["manifests"] = result.metadata["manifests"]
            if "advisory_data_source" in result.metadata:
                payload["advisory_data_source"] = result.metadata["advisory_data_source"]
        return payload

    def run_secret_scan(
        self,
        *,
        target_path: str = ".",
        scan_git_history: bool = False,
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Run Gitleaks secret detection on source files or git history."""
        rel, err = self._jail_path(target_path)
        if err or rel is None:
            return {"tool": "gitleaks", "status": "error", "error": err}

        spec = self._build_spec(
            ToolName.GITLEAKS,
            options={
                "target_path": rel,
                "scan_git_history": bool(scan_git_history),
            },
        )
        result = self.gitleaks.run(spec, workdir=str(self.snapshot_root))
        self._record_result(f"gitleaks:{rel}:{scan_git_history}", result)
        payload = extract_scanner_result(
            result,
            snapshot_root=self.snapshot_root,
            max_items=max_items,
        )
        payload["target_path"] = rel
        payload["scan_git_history"] = bool(scan_git_history)
        return payload

    def run_config_audit(
        self,
        *,
        target_path: str = ".",
        check_type: str = "auto",
        max_items: int = 15,
    ) -> dict[str, Any]:
        """Run SpotBugs (Java bytecode) or Trivy (IaC/Dockerfile/K8s config audit)."""
        rel, err = self._jail_path(target_path)
        if err or rel is None:
            return {"tool": "config_audit", "status": "error", "error": err}

        mode = (check_type or "auto").strip().lower()

        if mode == "bytecode":
            spec = self._build_spec(ToolName.SPOTBUGS, language="java")
            result = self.spotbugs.run(spec, workdir=str(self.snapshot_root))
            self._record_result(f"spotbugs:{rel}", result)
        else:
            spec = self._build_spec(ToolName.TRIVY, options={"target_path": rel})
            result = self.trivy.run(spec, workdir=str(self.snapshot_root))
            self._record_result(f"trivy:{rel}", result)

        payload = extract_scanner_result(
            result,
            snapshot_root=self.snapshot_root,
            file_path=None if rel == "." else rel,
            max_items=max_items,
        )
        payload["check_type"] = mode
        payload["target_path"] = rel
        return payload

    def query_findings(
        self,
        *,
        tool: str = "all",
        cwe: str | None = None,
        file_path: str | None = None,
        min_severity: str | None = None,
        max_items: int = 20,
    ) -> dict[str, Any]:
        """Query consolidated findings and cached ad-hoc scanner observations."""
        return extract_findings_query(
            self.findings,
            self._cached_observations,
            snapshot_root=self.snapshot_root,
            tool=tool,
            cwe=cwe,
            file_path=file_path,
            min_severity=min_severity,
            max_items=max_items,
        )

    def explain_rule(self, *, rule_id: str, tool: str | None = None) -> dict[str, Any]:
        """Explain a scanner rule ID with CWE metadata and remediation guidance."""
        return explain_scanner_rule(rule_id, tool=tool)

    def executed_tools(self) -> list[ToolName]:
        """Return the distinct scanner tools actually invoked during this session."""
        seen: list[ToolName] = []
        for result in self._cached_results.values():
            if result.tool not in seen:
                seen.append(result.tool)
        return seen

    def executed_results(self) -> list[ScannerResult]:
        """Return merged :class:`ScannerResult` objects produced during this session.

        When the AI invokes the same scanner multiple times (e.g. different
        languages or subdirectories), observations and coverage records are
        merged per :class:`ToolName` so downstream reporting and policy gates
        reuse the exact evidence without re-running scanners.
        """
        grouped: dict[ToolName, list[ScannerResult]] = {}
        for result in self._cached_results.values():
            grouped.setdefault(result.tool, []).append(result)

        status_rank = {
            RunStatus.COMPLETED: 4,
            RunStatus.COMPLETED_WITH_ERRORS: 3,
            RunStatus.SKIPPED: 2,
            RunStatus.FAILED: 1,
        }
        merged: list[ScannerResult] = []
        for batch in grouped.values():
            if len(batch) == 1:
                merged.append(batch[0])
                continue
            primary = max(batch, key=lambda r: status_rank.get(r.status, 0))
            obs_seen: set[str] = set()
            all_obs: list[Observation] = []
            cov_seen: set[tuple[str, str]] = set()
            all_cov = []
            all_errors: list[str] = []
            all_warnings: list[str] = []
            for item in batch:
                for obs in item.observations:
                    if obs.observation_id not in obs_seen:
                        obs_seen.add(obs.observation_id)
                        all_obs.append(obs)
                for cov in item.coverage_records:
                    key = (cov.unit_language.value, cov.unit_path)
                    if key not in cov_seen:
                        cov_seen.add(key)
                        all_cov.append(cov)
                for err in item.errors:
                    if err not in all_errors:
                        all_errors.append(err)
                for warn in item.warnings:
                    if warn not in all_warnings:
                        all_warnings.append(warn)
            merged.append(
                primary.model_copy(
                    update={
                        "observations": all_obs,
                        "coverage_records": all_cov,
                        "errors": all_errors,
                        "warnings": all_warnings,
                    }
                )
            )
        return merged


__all__ = [
    "SUPPORTED_LANGUAGE_FAMILIES",
    "ScannerToolService",
    "detect_snapshot_languages",
    "normalize_language_family",
]
