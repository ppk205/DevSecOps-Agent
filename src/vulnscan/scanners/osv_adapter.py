"""OSV.dev adapter — dependency CVE lookup replacing flaky NVD downloads.

Parses dependency manifests from the checkout (``pom.xml``, ``package-lock.json``,
``requirements.txt``), batches them into ``POST https://api.osv.dev/v1/querybatch``
(timeout 30s), and maps CVEs to observations (``rule_id`` ``osv-<id>``).

Network failure is an *offline-degraded* condition, never an exception: the
adapter returns a ``skipped`` :class:`ScannerResult` with the reason recorded.
No local binary is required, so :meth:`capabilities` always reports available
(the scan spec can still disable the tool).

The adapter reuses the :attr:`ToolName.OWASP_DEPENDENCY_CHECK` tool slot (there
is no OSV member in the contract enum) and sets ``tool_version='osv.dev'``.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    ExtractionMode,
    LanguageKind,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    Severity,
    SourceCoordinate,
    ToolName,
)

from .base import AdapterCapability, ScannerAdapter

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 30.0
TOOL_VERSION = "osv.dev"
BATCH_SIZE = 100

_REQUIREMENT_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*==\s*([^;\s#]+)")


@dataclass(frozen=True)
class OsvPackage:
    """One pinned dependency resolved from a manifest file."""

    ecosystem: str
    name: str
    version: str
    manifest: str  # checkout-relative POSIX path of the manifest file


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_pom_xml(text: str, *, manifest: str) -> list[OsvPackage]:
    """Parse Maven ``pom.xml`` dependencies into OSV packages (ecosystem Maven)."""
    # stdlib ElementTree does not fetch external entities, but internal
    # ``<!ENTITY`` expansions (billion laughs) come from the scanned repo
    # itself, so refuse entity declarations outright before parsing.
    if "<!ENTITY" in text.upper():
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    packages: list[OsvPackage] = []
    for node in root.iter():
        if _local(node.tag) != "dependency":
            continue
        fields: dict[str, str] = {}
        for child in node:
            fields[_local(child.tag)] = (child.text or "").strip()
        artifact = fields.get("artifactId", "")
        version = fields.get("version", "")
        if not artifact or not version or "$" in version:
            continue
        group = fields.get("groupId", "")
        name = f"{group}:{artifact}" if group else artifact
        packages.append(
            OsvPackage(ecosystem="Maven", name=name, version=version, manifest=manifest)
        )
    return packages


def _package_lock_name(key: str) -> str:
    # npm v7+ keys look like "node_modules/a" (nested: "node_modules/a/node_modules/b").
    return key.split("node_modules/")[-1] if "node_modules/" in key else key


def parse_package_lock(data: dict[str, Any], *, manifest: str) -> list[OsvPackage]:
    """Parse ``package-lock.json`` (v7+ ``packages`` or legacy ``dependencies``)."""
    packages: list[OsvPackage] = []
    nested = data.get("packages")
    if isinstance(nested, dict):
        for key, info in nested.items():
            if not key:
                continue
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "").strip()
            if not version:
                continue
            name = _package_lock_name(key)
            if not name:
                continue
            packages.append(
                OsvPackage(ecosystem="npm", name=name, version=version, manifest=manifest)
            )
        return packages
    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        for name, info in legacy.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "").strip()
            if not version:
                continue
            packages.append(
                OsvPackage(ecosystem="npm", name=name, version=version, manifest=manifest)
            )
    return packages


def parse_requirements_txt(text: str, *, manifest: str) -> list[OsvPackage]:
    """Parse ``requirements.txt`` ``name==version`` pins (ecosystem PyPI)."""
    packages: list[OsvPackage] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip().strip("\"'")
        if not line or line.startswith(("-", ".", "http:", "https:", "file:")):
            continue
        if "://" in line:
            continue
        match = _REQUIREMENT_PIN.match(line)
        if not match:
            continue
        name = match.group(1).split("[", 1)[0].strip()
        version = match.group(2).strip().lstrip("=").strip().rstrip(",").strip()
        if not name or not version or "*" in version or " " in version:
            continue
        packages.append(OsvPackage(ecosystem="PyPI", name=name, version=version, manifest=manifest))
    return packages


def collect_packages(workdir: str | Path) -> tuple[list[OsvPackage], list[str]]:
    """Collect pinned packages from every manifest under *workdir*.

    Returns ``(packages, manifests)`` where ``manifests`` are the
    checkout-relative POSIX paths of manifest files found (even unparsable
    ones). Packages are deduplicated and sorted for deterministic queries.
    """
    root = Path(workdir)
    packages: list[OsvPackage] = []
    manifests: list[str] = []
    try:
        pom_files = sorted(root.rglob("pom.xml"))
        lock_files = sorted(root.rglob("package-lock.json"))
        req_files = sorted(root.rglob("requirements.txt"))
    except OSError:
        return [], []
    for path in pom_files + lock_files + req_files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        manifests.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.name == "pom.xml":
            packages.extend(parse_pom_xml(text, manifest=rel))
        elif path.name == "package-lock.json":
            import json as _json

            try:
                data = _json.loads(text)
            except ValueError:
                continue
            if isinstance(data, dict):
                packages.extend(parse_package_lock(data, manifest=rel))
        else:
            packages.extend(parse_requirements_txt(text, manifest=rel))
    seen: dict[tuple[str, str, str], OsvPackage] = {}
    for pkg in packages:
        seen.setdefault((pkg.ecosystem, pkg.name, pkg.version), pkg)
    return sorted(seen.values(), key=lambda p: (p.ecosystem, p.name, p.version)), sorted(
        set(manifests)
    )


_SEVERITY_BY_NAME: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _cvss_to_severity(score: float | None) -> Severity | None:
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _severity_from_vuln(vuln: dict[str, Any]) -> tuple[Severity, str | None]:
    """Map an OSV vuln entry to contract Severity (default HIGH when no CVSS)."""
    best: float | None = None
    named: Severity | None = None

    def _consider(value: Any) -> None:
        nonlocal best, named
        if isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            score = float(value)
            if best is None or score > best:
                best = score
            return
        if isinstance(value, str):
            text = value.strip()
            if not text or text.upper().startswith("CVSS:"):
                return
            try:
                score = float(text)
            except ValueError:
                named = named or _SEVERITY_BY_NAME.get(text.lower())
            else:
                if best is None or score > best:
                    best = score

    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict):
            _consider(entry.get("score"))
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        for key in ("cvss_score", "cvss", "cvssScore", "cvss_score_v3"):
            value = db_specific.get(key)
            if isinstance(value, dict):
                _consider(value.get("score", value.get("baseScore")))
            elif value is not None:
                _consider(value)
        _consider(db_specific.get("severity"))
    mapped = _cvss_to_severity(best) or named
    native = f"cvss={best}" if best is not None else None
    return mapped or Severity.HIGH, native


def _observation_id(ecosystem: str, name: str, version: str, vuln_id: str) -> str:
    blob = f"{ecosystem}|{name}|{version}|{vuln_id}"
    return "obs-" + hashlib.sha256(blob.encode()).hexdigest()[:16]


def map_osv_response(
    queries: list[OsvPackage],
    response: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> list[Observation]:
    """Map an OSV ``querybatch`` response to observations aligned with *queries*."""
    del source_snapshot  # manifest path is the location; snapshot lives on coverage.
    now = datetime.now(UTC)
    observations: list[Observation] = []
    results = response.get("results", [])
    for pkg, entry in zip(queries, results):
        if not isinstance(entry, dict):
            continue
        for vuln in entry.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id") or (vuln.get("aliases") or ["unknown"])[0])
            severity, native_severity = _severity_from_vuln(vuln)
            summary = str(vuln.get("summary") or vuln.get("details") or "")[:1000]
            observations.append(
                Observation(
                    observation_id=_observation_id(pkg.ecosystem, pkg.name, pkg.version, vuln_id),
                    run_id=run_id,
                    tool=ToolName.OWASP_DEPENDENCY_CHECK,
                    tool_version=tool_version,
                    rule_id=f"osv-{vuln_id}",
                    cwe_category=CWECategory.DEPENDENCY_VULNERABILITY,
                    severity=severity,
                    native_severity=native_severity,
                    message=f"{vuln_id} affects {pkg.name}@{pkg.version}: {summary}",
                    location=SourceCoordinate(
                        file_path=pkg.manifest,
                        language=LanguageKind.OTHER,
                        line_start=1,
                    ),
                    dependency_identity=f"{pkg.ecosystem}/{pkg.name}@{pkg.version}",
                    detected_at=now,
                    metadata={
                        "ecosystem": pkg.ecosystem,
                        "package": pkg.name,
                        "version": pkg.version,
                        "osv_id": vuln_id,
                        "aliases": vuln.get("aliases") or [],
                        "published": vuln.get("published"),
                        "modified": vuln.get("modified"),
                    },
                )
            )
    return observations


def query_osv(
    packages: list[OsvPackage],
    *,
    timeout: float = REQUEST_TIMEOUT,
    batch_size: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """POST *packages* to OSV ``querybatch``; returns per-query result entries."""
    entries: list[dict[str, Any]] = []
    for start in range(0, len(packages), batch_size):
        chunk = packages[start : start + batch_size]
        payload = {
            "queries": [
                {
                    "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
                    "version": pkg.version,
                }
                for pkg in chunk
            ]
        }
        response = httpx.post(OSV_QUERYBATCH_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        results = data.get("results", []) if isinstance(data, dict) else []
        entries.extend(r if isinstance(r, dict) else {} for r in results)
        while len(entries) < len(packages[: start + batch_size]):
            entries.append({})
    return entries[: len(packages)]


def _coverage_for_manifests(
    manifests: list[str],
    *,
    run_id: str,
    source_snapshot: str,
    analyzed_at: datetime,
) -> list[CoverageRecord]:
    now = analyzed_at
    return [
        CoverageRecord(
            run_id=run_id,
            tool=ToolName.OWASP_DEPENDENCY_CHECK,
            tool_version=TOOL_VERSION,
            source_snapshot=source_snapshot,
            unit_path=manifest,
            unit_language=LanguageKind.OTHER,
            eligible=True,
            status=CoverageUnitStatus.ANALYZED,
            extraction_mode=ExtractionMode.DEPENDENCY_GRAPH,
            diagnostics=[],
            unresolved_calls=[],
            cwe_capabilities=[CWECategory.DEPENDENCY_VULNERABILITY],
            cwe_limitations=[],
            analyzed_at=now,
        )
        for manifest in manifests
    ]


class OSVAdapter(ScannerAdapter):
    """OSV.dev dependency-CVE lookup (dependency track, no local binary)."""

    tool = ToolName.OWASP_DEPENDENCY_CHECK
    binary_name = "osv.dev"

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=TOOL_VERSION,
            available=True,
            reason=None,
        )

    def _skipped_offline(self, spec: ScanSpecification, started: Any, reason: str) -> Any:
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version=TOOL_VERSION,
            adapter_version=self.adapter_version,
            status=RunStatus.SKIPPED,
            started_at=started,
            finished_at=started,
            errors=[reason],
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        packages, manifests = collect_packages(workdir)
        if not packages:
            finished = datetime.now(UTC)
            return ScannerResult(
                run_id=spec.run_id or "unassigned",
                tool=self.tool,
                tool_version=TOOL_VERSION,
                adapter_version=self.adapter_version,
                status=RunStatus.COMPLETED,
                started_at=started,
                finished_at=finished,
                observations=[],
                coverage_records=_coverage_for_manifests(
                    manifests,
                    run_id=spec.run_id or "unassigned",
                    source_snapshot=spec.target_commit_sha,
                    analyzed_at=finished,
                ),
                raw_output_refs=[],
                eligible_units=len(manifests),
                analyzed_units=len(manifests),
                skipped_units=0,
                failed_units=0,
                errors=[],
                warnings=["no pinned dependency manifests found"] if not manifests else [],
                duration_ms=int((finished - started).total_seconds() * 1000),
                metadata={
                    "advisory_data_source": "osv.dev",
                    "packages_queried": 0,
                    "manifests": manifests,
                },
            )

        try:
            entries = query_osv(packages)
        except (httpx.HTTPError, OSError, TimeoutError, ValueError) as exc:
            # offline or API failure -> degraded, never raise
            return self._skipped_offline(spec, started, f"osv.dev unreachable: {exc}")

        finished = datetime.now(UTC)
        response: dict[str, Any] = {"results": entries}
        observations = map_osv_response(
            packages,
            response,
            run_id=spec.run_id or "unassigned",
            tool_version=TOOL_VERSION,
            source_snapshot=spec.target_commit_sha,
        )
        coverage_records = _coverage_for_manifests(
            manifests,
            run_id=spec.run_id or "unassigned",
            source_snapshot=spec.target_commit_sha,
            analyzed_at=finished,
        )
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version=TOOL_VERSION,
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            observations=observations,
            coverage_records=coverage_records,
            raw_output_refs=[],
            eligible_units=len(coverage_records),
            analyzed_units=len(coverage_records),
            skipped_units=0,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=int((finished - started).total_seconds() * 1000),
            metadata={
                "advisory_data_source": "osv.dev",
                "packages_queried": len(packages),
                "manifests": manifests,
            },
        )


__all__ = [
    "BATCH_SIZE",
    "OSV_QUERYBATCH_URL",
    "REQUEST_TIMEOUT",
    "TOOL_VERSION",
    "OSVAdapter",
    "OsvPackage",
    "collect_packages",
    "map_osv_response",
    "parse_package_lock",
    "parse_pom_xml",
    "parse_requirements_txt",
    "query_osv",
]
