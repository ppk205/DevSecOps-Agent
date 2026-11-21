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
    """Parse Maven ``pom.xml`` dependencies into OSV packages (ecosystem Maven).

    Resolves ``${property}`` placeholders from ``<properties>`` (plus
    ``project.version`` / ``project.parent.version``) and includes the
    ``<parent>`` BOM coordinate when pinned so pre-build SCA works without
    running Maven.
    """
    # stdlib ElementTree does not fetch external entities, but internal
    # ``<!ENTITY`` expansions (billion laughs) come from the scanned repo
    # itself, so refuse entity declarations outright before parsing.
    if "<!ENTITY" in text.upper():
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    props: dict[str, str] = {}
    parent_fields: dict[str, str] = {}
    for child in root:
        tag = _local(child.tag)
        if tag == "version" and (child.text or "").strip():
            props["project.version"] = (child.text or "").strip()
        elif tag == "parent":
            for pchild in child:
                parent_fields[_local(pchild.tag)] = (pchild.text or "").strip()
            if parent_fields.get("version"):
                props["project.parent.version"] = parent_fields["version"]
                props.setdefault("project.version", parent_fields["version"])
        elif tag == "properties":
            for prop in child:
                val = (prop.text or "").strip()
                if val:
                    props[_local(prop.tag)] = val

    def _resolve_props(raw: str) -> str:
        val = raw.strip()
        for _ in range(3):
            if "${" not in val:
                break
            updated = re.sub(
                r"\$\{([^}]+)\}",
                lambda m: props.get(m.group(1).strip(), m.group(0)),
                val,
            )
            if updated == val:
                break
            val = updated
        return val

    packages: list[OsvPackage] = []
    seen: set[tuple[str, str]] = set()

    if parent_fields.get("artifactId") and parent_fields.get("version"):
        p_ver = _resolve_props(parent_fields["version"])
        if p_ver and "$" not in p_ver:
            p_group = parent_fields.get("groupId", "")
            p_name = f"{p_group}:{parent_fields['artifactId']}" if p_group else parent_fields["artifactId"]
            seen.add((p_name, p_ver))
            packages.append(
                OsvPackage(ecosystem="Maven", name=p_name, version=p_ver, manifest=manifest)
            )

    for node in root.iter():
        if _local(node.tag) != "dependency":
            continue
        fields: dict[str, str] = {}
        for child in node:
            fields[_local(child.tag)] = (child.text or "").strip()
        artifact = fields.get("artifactId", "")
        version = _resolve_props(fields.get("version", ""))
        if not artifact or not version or "$" in version:
            continue
        group = fields.get("groupId", "")
        name = f"{group}:{artifact}" if group else artifact
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
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


def parse_go_mod(text: str, *, manifest: str) -> list[OsvPackage]:
    """Parse ``go.mod`` require directives (ecosystem Go)."""
    packages: list[OsvPackage] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require (") or line == "require(":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        entry = line[len("require ") :].strip() if line.startswith("require ") else (line if in_block else "")
        if not entry:
            continue
        parts = entry.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1].lstrip("v")
            if name and version and version[0].isdigit():
                packages.append(
                    OsvPackage(ecosystem="Go", name=name, version=f"v{version}", manifest=manifest)
                )
    return packages


def parse_composer_lock(data: dict[str, Any], *, manifest: str) -> list[OsvPackage]:
    """Parse PHP ``composer.lock`` packages (ecosystem Packagist)."""
    packages: list[OsvPackage] = []
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip().lstrip("v")
            if name and version:
                packages.append(
                    OsvPackage(ecosystem="Packagist", name=name, version=version, manifest=manifest)
                )
    return packages


def parse_composer_json(data: dict[str, Any], *, manifest: str) -> list[OsvPackage]:
    """Parse pinned entries from PHP ``composer.json`` (ecosystem Packagist)."""
    packages: list[OsvPackage] = []
    for section in ("require", "require-dev"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, raw_ver in entries.items():
            if not isinstance(name, str) or "/" not in name:
                continue
            ver = str(raw_ver or "").strip().lstrip("^~>=<v ")
            if ver and ver[0].isdigit() and "*" not in ver and " " not in ver:
                packages.append(
                    OsvPackage(ecosystem="Packagist", name=name, version=ver, manifest=manifest)
                )
    return packages


def parse_csproj(text: str, *, manifest: str) -> list[OsvPackage]:
    """Parse .NET ``*.csproj`` PackageReference entries (ecosystem NuGet)."""
    if "<!ENTITY" in text.upper():
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    packages: list[OsvPackage] = []
    for node in root.iter():
        if _local(node.tag) != "PackageReference":
            continue
        name = (node.attrib.get("Include") or node.attrib.get("Update") or "").strip()
        version = (node.attrib.get("Version") or "").strip()
        if not version:
            for child in node:
                if _local(child.tag) == "Version" and child.text:
                    version = child.text.strip()
                    break
        if name and version and "$" not in version and "*" not in version:
            packages.append(
                OsvPackage(ecosystem="NuGet", name=name, version=version, manifest=manifest)
            )
    return packages


def parse_conanfile_txt(text: str, *, manifest: str) -> list[OsvPackage]:
    """Parse C/C++ ``conanfile.txt`` [requires] entries (ecosystem ConanCenter)."""
    packages: list[OsvPackage] = []
    in_requires = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_requires = line.lower() == "[requires]"
            continue
        if not in_requires or "/" not in line:
            continue
        pkg_spec = line.split("@", 1)[0]
        parts = pkg_spec.split("/", 1)
        if len(parts) == 2:
            name, version = parts[0].strip(), parts[1].strip()
            if name and version and "[" not in version:
                packages.append(
                    OsvPackage(
                        ecosystem="ConanCenter", name=name, version=version, manifest=manifest
                    )
                )
    return packages


def parse_vcpkg_json(data: dict[str, Any], *, manifest: str) -> list[OsvPackage]:
    """Parse C/C++ ``vcpkg.json`` overrides/dependencies with explicit versions."""
    packages: list[OsvPackage] = []
    for section in ("overrides", "dependencies"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            version = str(
                item.get("version") or item.get("version>=") or item.get("version-semver") or ""
            ).strip()
            if name and version:
                packages.append(
                    OsvPackage(ecosystem="OSS-Fuzz", name=name, version=version, manifest=manifest)
                )
    return packages


def _parse_manifest_file(path: Path, rel: str) -> list[OsvPackage]:
    import json as _json

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    name = path.name.lower()
    if name == "pom.xml":
        return parse_pom_xml(text, manifest=rel)
    if name == "package-lock.json":
        try:
            data = _json.loads(text)
        except ValueError:
            return []
        return parse_package_lock(data, manifest=rel) if isinstance(data, dict) else []
    if name == "requirements.txt":
        return parse_requirements_txt(text, manifest=rel)
    if name == "go.mod":
        return parse_go_mod(text, manifest=rel)
    if name == "composer.lock":
        try:
            data = _json.loads(text)
        except ValueError:
            return []
        return parse_composer_lock(data, manifest=rel) if isinstance(data, dict) else []
    if name == "composer.json":
        try:
            data = _json.loads(text)
        except ValueError:
            return []
        return parse_composer_json(data, manifest=rel) if isinstance(data, dict) else []
    if name.endswith(".csproj"):
        return parse_csproj(text, manifest=rel)
    if name == "conanfile.txt":
        return parse_conanfile_txt(text, manifest=rel)
    if name == "vcpkg.json":
        try:
            data = _json.loads(text)
        except ValueError:
            return []
        return parse_vcpkg_json(data, manifest=rel) if isinstance(data, dict) else []
    return []


def collect_packages(
    workdir: str | Path,
    *,
    manifest_path: str | None = None,
) -> tuple[list[OsvPackage], list[str]]:
    """Collect pinned packages from every manifest under *workdir*.

    Supports all 7 language families: Maven (``pom.xml``), npm
    (``package-lock.json``), PyPI (``requirements.txt``), Go (``go.mod``),
    PHP (``composer.lock``/``composer.json``), .NET (``*.csproj``), and
    C/C++ (``conanfile.txt``/``vcpkg.json``).

    Returns ``(packages, manifests)`` where ``manifests`` are the
    checkout-relative POSIX paths of manifest files found (even unparsable
    ones). Packages are deduplicated and sorted for deterministic queries.
    """
    root = Path(workdir)
    packages: list[OsvPackage] = []
    manifests: list[str] = []

    if manifest_path:
        candidate = (root / manifest_path).resolve()
        try:
            rel = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            return [], []
        if not candidate.is_file():
            return [], []
        manifests.append(rel)
        packages.extend(_parse_manifest_file(candidate, rel))
    else:
        patterns = (
            "pom.xml",
            "package-lock.json",
            "requirements.txt",
            "go.mod",
            "composer.lock",
            "composer.json",
            "*.csproj",
            "conanfile.txt",
            "vcpkg.json",
        )
        found_paths: list[Path] = []
        try:
            for pattern in patterns:
                found_paths.extend(sorted(root.rglob(pattern)))
        except OSError:
            return [], []
        for path in found_paths:
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            manifests.append(rel)
            packages.extend(_parse_manifest_file(path, rel))

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
        try:
            response = httpx.post(OSV_QUERYBATCH_URL, json=payload, timeout=timeout)
        except httpx.InvalidURL:
            from vulnscan.providers.client import _make_http_client

            with _make_http_client(timeout) as client:
                response = client.post(OSV_QUERYBATCH_URL, json=payload)
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

    def _skipped_offline(
        self, spec: ScanSpecification, started: Any, reason: str
    ) -> ScannerResult:
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

        manifest_path: str | None = None
        if tool_cfg and isinstance(tool_cfg.options, dict):
            raw_mp = tool_cfg.options.get("manifest_path")
            if isinstance(raw_mp, str) and raw_mp.strip():
                manifest_path = raw_mp.strip()

        packages, manifests = collect_packages(workdir, manifest_path=manifest_path)
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
