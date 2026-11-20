"""Token-optimized scanner result extractor and rule explainer for AI agents.

Raw SARIF and vendor JSON payloads easily exceed an LLM's context window.
This module distills :class:`ScannerResult`, :class:`Observation`, and
:class:`Finding` objects into compact, high-signal JSON payloads containing:

- rule_id, cwe, severity, tool
- file path and line range
- short code snippet (bounded to a few lines of surrounding context)
- capped result lists prioritized by severity so the model sees critical
  vulnerabilities first without overflowing context.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from vulnscan.contracts import Finding, Observation, ScannerResult, Severity, ToolName

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "undetermined": 5,
}

#: Concise remediation guidance keyed by canonical CWE identifier.
_CWE_GUIDANCE: dict[str, dict[str, str]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "remediation": (
            "Use parameterized queries / prepared statements (e.g. PreparedStatement, "
            "SQLAlchemy bind params, PDO prepare, Go database/sql placeholders). "
            "Never concatenate user input into SQL strings."
        ),
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "remediation": (
            "Avoid invoking a shell (shell=False / exec.Command with arg array / "
            "ProcessBuilder). Strictly validate arguments against an allowlist."
        ),
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "remediation": (
            "Apply context-aware output encoding (HTML, JS, URL, CSS) and use "
            "auto-escaping templates. Avoid innerHTML, document.write, and raw markup."
        ),
    },
    "CWE-22": {
        "name": "Path Traversal",
        "remediation": (
            "Canonicalize paths (resolve()) and verify the target stays strictly "
            "inside the allowed base directory before reading or writing."
        ),
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "remediation": (
            "Avoid native binary deserialization (ObjectInputStream, pickle.loads, "
            "unserialize, BinaryFormatter) on untrusted data; use JSON with strict schema."
        ),
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "remediation": (
            "Disable DOCTYPE declarations and external entity resolution in the XML parser."
        ),
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "remediation": (
            "Validate outbound URLs against an explicit host/scheme allowlist and block "
            "loopback, link-local, and RFC1918 private IP ranges after DNS resolution."
        ),
    },
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "remediation": (
            "Remove secrets from source code and git history; rotate exposed credentials "
            "and load secrets from environment variables or a secret manager."
        ),
    },
    "CWE-327": {
        "name": "Broken or Risky Cryptographic Algorithm",
        "remediation": (
            "Replace weak ciphers/hashes (MD5, SHA1, DES, RC4, ECB mode) with modern "
            "primitives (AES-GCM, ChaCha20-Poly1305, SHA-256+, Argon2/bcrypt for passwords)."
        ),
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "remediation": (
            "Enforce server-side authorization checks on every sensitive endpoint and "
            "verify object ownership (prevent IDOR / CWE-639)."
        ),
    },
    "CWE-119": {
        "name": "Buffer Overflow / Memory Safety",
        "remediation": (
            "Use bounded buffer APIs (snprintf, strncpy_s, std::string/std::vector) "
            "and validate buffer lengths prior to copy/indexing."
        ),
    },
    "CWE-16": {
        "name": "Security Misconfiguration",
        "remediation": (
            "Harden container/IaC configuration: run as non-root, drop unnecessary "
            "capabilities, pin versions, and disable debug/privileged modes."
        ),
    },
    "CWE-1395": {
        "name": "Vulnerable Third-Party Dependency",
        "remediation": (
            "Upgrade the affected dependency to a patched version and re-run SCA verification."
        ),
    },
}


def normalize_cwe_filter(raw: str | None) -> str | None:
    """Normalize inputs like ``'89'``, ``'cwe-89'``, or ``'CWE-89'`` to ``'CWE-89'``."""
    if not raw:
        return None
    text = str(raw).strip().upper()
    if not text:
        return None
    match = re.search(r"(\d+)", text)
    if not match:
        return text
    return f"CWE-{match.group(1)}"


def severity_meets_minimum(severity: Severity | str, min_severity: str | None) -> bool:
    """Return True if *severity* is at least as severe as *min_severity*."""
    if not min_severity:
        return True
    sev_val = severity.value if isinstance(severity, Severity) else str(severity).lower()
    min_val = str(min_severity).strip().lower()
    if min_val not in _SEVERITY_RANK:
        return True
    return _SEVERITY_RANK.get(sev_val, 5) <= _SEVERITY_RANK[min_val]


def read_code_snippet(
    snapshot_root: str | Path | None,
    file_path: str | None,
    line_start: int | None,
    line_end: int | None = None,
    *,
    context_lines: int = 2,
    max_lines: int = 10,
) -> str | None:
    """Read a bounded code excerpt jailed inside *snapshot_root*."""
    if not snapshot_root or not file_path or not line_start or line_start < 1:
        return None
    root = Path(snapshot_root).resolve()
    try:
        target = (root / file_path).resolve()
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    if not target.is_file():
        return None
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(1, line_start - context_lines)
    end = min(len(lines), max(line_end or line_start, line_start) + context_lines)
    if end - start + 1 > max_lines:
        end = start + max_lines - 1
    excerpt = [f"{idx}: {lines[idx - 1][:240]}" for idx in range(start, end + 1)]
    return "\n".join(excerpt)


def extract_observation(
    obs: Observation,
    *,
    snapshot_root: str | Path | None = None,
    include_snippet: bool = True,
) -> dict[str, Any]:
    """Distill one :class:`Observation` into a compact LLM-friendly dict."""
    file_path = obs.location.file_path if obs.location else None
    line_start = obs.location.line_start if obs.location else None
    line_end = obs.location.line_end if obs.location else None

    snippet: str | None = None
    if include_snippet and obs.tool != ToolName.GITLEAKS:
        if obs.location and obs.location.snippet:
            snippet = obs.location.snippet.strip()[:600]
        else:
            snippet = read_code_snippet(snapshot_root, file_path, line_start, line_end)

    entry: dict[str, Any] = {
        "observation_id": obs.observation_id,
        "tool": obs.tool.value,
        "rule_id": obs.rule_id,
        "cwe": obs.cwe_category.value if obs.cwe_category else "unknown",
        "severity": obs.severity.value,
        "file": file_path or "",
        "line_start": line_start,
        "line_end": line_end,
        "message": (obs.message or "")[:400],
    }
    if snippet:
        entry["snippet"] = snippet
    if obs.dependency_identity:
        entry["dependency"] = obs.dependency_identity
    cvss = obs.metadata.get("cvss") if isinstance(obs.metadata, dict) else None
    if cvss is not None:
        entry["cvss"] = cvss
    return entry


def extract_scanner_result(
    result: ScannerResult,
    *,
    snapshot_root: str | Path | None = None,
    cwe: str | None = None,
    min_severity: str | None = None,
    min_cvss: float | None = None,
    file_path: str | None = None,
    max_items: int = 15,
) -> dict[str, Any]:
    """Filter, prioritize, and compact a :class:`ScannerResult` for LLM consumption."""
    cwe_norm = normalize_cwe_filter(cwe)
    file_norm = file_path.replace("\\", "/").strip().lower() if file_path else None
    cap = max(1, min(50, int(max_items)))

    filtered: list[Observation] = []
    for obs in result.observations:
        if cwe_norm:
            obs_cwe = obs.cwe_category.value.upper() if obs.cwe_category else ""
            if obs_cwe != cwe_norm:
                continue
        if not severity_meets_minimum(obs.severity, min_severity):
            continue
        if min_cvss is not None:
            raw_cvss = obs.metadata.get("cvss") if isinstance(obs.metadata, dict) else None
            if raw_cvss is not None:
                try:
                    if float(raw_cvss) < float(min_cvss):
                        continue
                except (TypeError, ValueError):
                    pass
            elif not severity_meets_minimum(
                obs.severity,
                "critical" if min_cvss >= 9.0 else ("high" if min_cvss >= 7.0 else "medium"),
            ):
                continue
        if file_norm:
            obs_file = (obs.location.file_path if obs.location else "").replace("\\", "/").lower()
            if file_norm not in obs_file:
                continue
        filtered.append(obs)

    filtered.sort(
        key=lambda o: (
            _SEVERITY_RANK.get(o.severity.value, 5),
            o.location.file_path if o.location else "",
            o.location.line_start or 0 if o.location else 0,
        )
    )

    items = [extract_observation(obs, snapshot_root=snapshot_root) for obs in filtered[:cap]]

    return {
        "tool": result.tool.value,
        "tool_version": result.tool_version,
        "status": result.status.value,
        "total_observations": len(result.observations),
        "matched_observations": len(filtered),
        "returned": len(items),
        "truncated": len(filtered) > cap,
        "errors": list(result.errors)[:5],
        "warnings": list(result.warnings)[:5],
        "findings": items,
        "coverage": {
            "eligible_units": result.eligible_units,
            "analyzed_units": result.analyzed_units,
            "skipped_units": result.skipped_units,
        },
    }


def extract_findings_query(
    findings: Sequence[Finding],
    extra_observations: Sequence[Observation] = (),
    *,
    snapshot_root: str | Path | None = None,
    tool: str | None = None,
    cwe: str | None = None,
    file_path: str | None = None,
    min_severity: str | None = None,
    max_items: int = 20,
) -> dict[str, Any]:
    """Query pre-existing findings and cached ad-hoc observations in one compact view."""
    tool_norm = (tool or "all").strip().lower()
    cwe_norm = normalize_cwe_filter(cwe)
    file_norm = file_path.replace("\\", "/").strip().lower() if file_path else None
    cap = max(1, min(50, int(max_items)))

    records: list[dict[str, Any]] = []
    seen_obs: set[str] = set()

    for finding in findings:
        for obs in finding.observations:
            seen_obs.add(obs.observation_id)
            if tool_norm not in ("", "all") and tool_norm not in obs.tool.value.lower():
                continue
            if cwe_norm:
                f_cwe = (
                    obs.cwe_category.value
                    if obs.cwe_category
                    else (finding.cwe_category.value if finding.cwe_category else "")
                ).upper()
                if f_cwe != cwe_norm:
                    continue
            if not severity_meets_minimum(obs.severity, min_severity):
                continue
            if file_norm:
                obs_file = (
                    (obs.location.file_path if obs.location else "").replace("\\", "/").lower()
                )
                if file_norm not in obs_file:
                    continue
            item = extract_observation(obs, snapshot_root=snapshot_root)
            item["finding_id"] = finding.finding_id
            item["status"] = finding.status.value
            records.append(item)

    for obs in extra_observations:
        if obs.observation_id in seen_obs:
            continue
        seen_obs.add(obs.observation_id)
        if tool_norm not in ("", "all") and tool_norm not in obs.tool.value.lower():
            continue
        if cwe_norm:
            obs_cwe = obs.cwe_category.value.upper() if obs.cwe_category else ""
            if obs_cwe != cwe_norm:
                continue
        if not severity_meets_minimum(obs.severity, min_severity):
            continue
        if file_norm:
            obs_file = (obs.location.file_path if obs.location else "").replace("\\", "/").lower()
            if file_norm not in obs_file:
                continue
        records.append(extract_observation(obs, snapshot_root=snapshot_root))

    records.sort(
        key=lambda r: (
            _SEVERITY_RANK.get(str(r.get("severity", "undetermined")), 5),
            str(r.get("file", "")),
            int(r.get("line_start") or 0),
        )
    )

    return {
        "filters": {
            "tool": tool_norm or "all",
            "cwe": cwe_norm,
            "file_path": file_path,
            "min_severity": min_severity,
        },
        "total_matched": len(records),
        "returned": min(len(records), cap),
        "truncated": len(records) > cap,
        "results": records[:cap],
    }


def explain_scanner_rule(rule_id: str, tool: str | None = None) -> dict[str, Any]:
    """Return rule metadata, CWE classification, and remediation guidance.

    Searches bundled Semgrep YAML packs first, then falls back to CWE-based
    guidance inferred from the rule identifier.
    """
    clean_id = (rule_id or "").strip()
    if not clean_id:
        return {"error": "missing required argument: rule_id"}

    rules_dir = Path(__file__).with_name("rules")
    if rules_dir.is_dir():
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            yaml = None
        if yaml is not None:
            import logging

            _log = logging.getLogger(__name__)
            for yml_path in sorted(rules_dir.glob("*.yml")):
                try:
                    doc = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
                except Exception as exc:  # noqa: BLE001
                    _log.debug("Failed reading bundled rule pack %s: %s", yml_path, exc)
                    continue
                for rule in (doc or {}).get("rules") or []:
                    if not isinstance(rule, dict):
                        continue
                    rid = str(rule.get("id") or "")
                    if (
                        rid == clean_id
                        or clean_id.endswith(f".{rid}")
                        or rid.endswith(f".{clean_id}")
                    ):
                        meta = rule.get("metadata") or {}
                        raw_cwe = meta.get("cwe")
                        cwe_list = [raw_cwe] if isinstance(raw_cwe, str) else list(raw_cwe or [])
                        first_cwe = normalize_cwe_filter(cwe_list[0]) if cwe_list else None
                        guide = _CWE_GUIDANCE.get(first_cwe or "", {})
                        return {
                            "rule_id": rid,
                            "tool": tool or "semgrep",
                            "source_pack": yml_path.name,
                            "languages": rule.get("languages") or [],
                            "severity": rule.get("severity") or "WARNING",
                            "message": str(rule.get("message") or "").strip(),
                            "cwe": cwe_list,
                            "owasp": meta.get("owasp") or [],
                            "remediation": guide.get(
                                "remediation",
                                "Validate and sanitize untrusted inputs before reaching sensitive sinks.",
                            ),
                        }

    # Infer CWE from rule_id string when not found in bundled YAML packs
    cwe_norm = normalize_cwe_filter(clean_id) if "cwe" in clean_id.lower() else None
    if not cwe_norm:
        low = clean_id.lower()
        if "sql" in low:
            cwe_norm = "CWE-89"
        elif "xss" in low:
            cwe_norm = "CWE-79"
        elif any(k in low for k in ("cmd", "command", "exec", "subprocess", "shell")):
            cwe_norm = "CWE-78"
        elif "path" in low or "traversal" in low:
            cwe_norm = "CWE-22"
        elif "xxe" in low:
            cwe_norm = "CWE-611"
        elif "ssrf" in low:
            cwe_norm = "CWE-918"
        elif "deserial" in low or "pickle" in low:
            cwe_norm = "CWE-502"
        elif "secret" in low or "key" in low or "token" in low or "password" in low:
            cwe_norm = "CWE-798"
        elif "cve-" in low or "ghsa-" in low or "osv-" in low:
            cwe_norm = "CWE-1395"
        elif "avd-" in low or "docker" in low or "ksv" in low or "trivy" in low:
            cwe_norm = "CWE-16"

    guide = _CWE_GUIDANCE.get(cwe_norm or "", {})
    return {
        "rule_id": clean_id,
        "tool": tool or "unknown",
        "cwe": [cwe_norm] if cwe_norm else [],
        "category": guide.get("name", "Security Rule"),
        "remediation": guide.get(
            "remediation",
            "Review the flagged sink, verify attacker reachability, and apply input validation or safe APIs.",
        ),
    }


__all__ = [
    "explain_scanner_rule",
    "extract_findings_query",
    "extract_observation",
    "extract_scanner_result",
    "normalize_cwe_filter",
    "read_code_snippet",
    "severity_meets_minimum",
]
