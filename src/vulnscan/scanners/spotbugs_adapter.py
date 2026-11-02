"""SpotBugs adapter — bytecode-based static analysis for Java.

SpotBugs requires a compiled classpath.  When the ``classes`` directory
is not found, the adapter documents the absence in ``errors`` and returns
a ``failed`` result rather than raising.

Native XML output is parsed by :func:`parse_spotbugs_xml`; the ``run`` method
shells out via ``_invoke``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
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
from .platform import which
from .tool_versions import probe_version

# --- Severity map --------------------------------------------------------- #

_BUG_PRIORITY_MAP = {
    1: Severity.HIGH,
    2: Severity.MEDIUM,
    3: Severity.LOW,
}

_CATEGORIES_MAP = {
    "malicious_code": Severity.HIGH,
    "correctness": Severity.MEDIUM,
    "correctness:likely": Severity.MEDIUM,
    "bad-practice": Severity.LOW,
    "style": Severity.INFO,
    "performance": Severity.LOW,
    "info": Severity.INFO,
    "internationalization": Severity.INFO,
    "multithreading": Severity.LOW,
}


def _determine_severity(category: str, priority: int) -> Severity:
    """Map SpotBugs category + priority to a contract Severity."""
    cat = _CATEGORIES_MAP.get(category.lower(), Severity.UNDETERMINED)
    pri = _BUG_PRIORITY_MAP.get(priority, Severity.UNDETERMINED)
    # Highest of category and priority
    order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.UNDETERMINED,
    ]
    ci, pi = order.index(cat), order.index(pri)
    return order[min(ci, pi)]


def _parse_line_number(source_lines: Any) -> int | None:
    """Extract a single line number from SpotBugs ``SourceLine`` or ``Method``."""
    if source_lines is None:
        return None
    start = source_lines.get("start")
    if start is not None:
        try:
            return int(start)
        except (ValueError, TypeError):
            pass
    return None


def parse_spotbugs_xml(
    xml_text: str,
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse SpotBugs XML into Observations and CoverageRecords."""
    from lxml import etree as lxml_etree

    root = lxml_etree.fromstring(
        xml_text.encode(), parser=lxml_etree.XMLParser(resolve_entities=False, no_network=True)
    )

    if root.tag != "BugCollection":
        raise ValueError("expected a SpotBugs BugCollection report")
    errors_element = root.find("Errors")
    if errors_element is not None and (
        int(errors_element.get("errors", "0")) or int(errors_element.get("missingClasses", "0"))
    ):
        raise ValueError("SpotBugs reported analysis errors or missing classes")
    now = datetime.now(UTC)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    for bug_instance in root.findall("BugInstance"):
        bug_id = bug_instance.get("type", "unknown")
        priority = int(bug_instance.get("priority", 3))
        category = bug_instance.get("category", "unknown")
        short_msg = bug_instance.get("shortMessage", bug_id)
        long_msg_el = bug_instance.find("LongMessage")
        long_msg = long_msg_el.text if long_msg_el is not None else short_msg

        # Location extraction: prefer Method > Class > SourceLine
        source_line_el = bug_instance.find("SourceLine")
        method_el = bug_instance.find("Method")
        class_el = bug_instance.find("Class")

        file_path = ""
        if source_line_el is not None:
            file_path = source_line_el.get("sourcepath", "")
        line_start = _parse_line_number(source_line_el)
        symbol = None
        if method_el is not None:
            symbol = method_el.get("name")
        elif class_el is not None:
            symbol = class_el.get("classname", "").split(".")[-1]

        if not file_path and class_el is not None:
            # Convert classname to path
            cn = class_el.get("classname", "")
            file_path = cn.replace(".", "/") + ".java"

        if not line_start:
            line_start = 1

        sev = _determine_severity(category, priority)

        observations.append(
            Observation(
                run_id=run_id,
                tool=ToolName.SPOTBUGS,
                tool_version=tool_version,
                rule_id=bug_id,
                cwe_category=None,
                severity=sev,
                native_severity=f"priority={priority}, category={category}",
                message=long_msg[:1000] if long_msg else short_msg[:1000],
                location=SourceCoordinate(
                    file_path=file_path,
                    language=LanguageKind.JAVA,
                    line_start=line_start,
                    symbol=symbol,
                ),
                detected_at=now,
                metadata={
                    "category": category,
                    "priority": priority,
                },
                observation_id=f"spotbugs-{bug_id}-{file_path}-{line_start}",
            )
        )

    # Coverage: collect all files referenced by BugInstance sourcepath
    seen_files: set[str] = set()
    for bi in root.findall("BugInstance"):
        sl = bi.find("SourceLine")
        if sl is not None:
            sp = sl.get("sourcepath", "")
            if sp and sp not in seen_files:
                seen_files.add(sp)
                coverage.append(
                    CoverageRecord(
                        run_id=run_id,
                        tool=ToolName.SPOTBUGS,
                        tool_version=tool_version,
                        source_snapshot=source_snapshot,
                        unit_path=sp,
                        unit_language=LanguageKind.JAVA,
                        eligible=True,
                        status=CoverageUnitStatus.ANALYZED,
                        extraction_mode=ExtractionMode.BYTECODE,
                        diagnostics=[],
                        unresolved_calls=[],
                        cwe_capabilities=[],
                        cwe_limitations=[],
                        analyzed_at=now,
                    )
                )

    return observations, coverage


class SpotBugsAdapter(ScannerAdapter):
    """SpotBugs bytecode adapter with XML parsing."""

    tool = ToolName.SPOTBUGS
    binary_name = "spotbugs"

    def capabilities(self) -> AdapterCapability:
        resolved = which(self.binary_name)
        version = probe_version(self.binary_name) if resolved else None
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=version,
            available=resolved is not None,
            reason=None if resolved else f"{self.binary_name} not found on PATH",
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        from datetime import datetime

        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        # Disabled in spec?
        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        # SpotBugs needs compiled classes
        classes_dir = tool_cfg.options.get("classes_dir") if tool_cfg else None
        if classes_dir:
            classes_path = Path(workdir) / classes_dir
        else:
            # Try Maven default target/classes
            classes_path = Path(workdir) / "target" / "classes"
        if not classes_path.exists():
            return self._fatal(
                spec,
                started,
                datetime.now(UTC),
                type(
                    "FakeResult",
                    (),
                    {
                        "timed_out": False,
                        "succeeded": False,
                        "returncode": 1,
                        "stdout": "",
                        "stderr": "",
                        "duration_ms": 0,
                    },
                )(),
                note=f"classes directory not found: {classes_path} (run 'mvn compile' first)",
            )

        # Build command
        argv = [
            self.binary_name,
            "-xml:withMessages",
            "-exitcode",
            "-pluginList",
            "/opt/findsecbugs.jar",
            "-output",
            str(Path(workdir) / "target" / "spotbugs-report.xml"),
            str(classes_path),
        ]

        import os

        dependency_jars = sorted((Path(workdir) / "target/dependency").glob("*.jar"))
        if dependency_jars:
            # 243+ jars exceed the Windows command-line limit: pass them via
            # a file instead of inline -auxclasspath.
            auxclasspath_file = Path(workdir) / "target" / "auxclasspath.txt"
            auxclasspath_file.write_text(
                os.linesep.join(str(p) for p in dependency_jars), encoding="utf-8"
            )
            argv[-1:-1] = ["-auxclasspathFromFile", str(auxclasspath_file)]
        output_file = Path(workdir) / "target" / "spotbugs-report.xml"
        output_file.unlink(missing_ok=True)

        # FindSpotBugs needs JAVA_HOME or a JRE on PATH
        import os

        env = {}
        if "JAVA_HOME" in os.environ:
            env["JAVA_HOME"] = os.environ["JAVA_HOME"]

        result = self._invoke(argv, cwd=workdir, env=env)
        finished = datetime.now(UTC)

        if result.timed_out or result.returncode not in (0, 1):
            return self._fatal(spec, started, finished, result, note="SpotBugs execution failed")

        output_file = Path(workdir) / "target" / "spotbugs-report.xml"
        if not output_file.exists():
            return self._fatal(
                spec, started, finished, result, note="SpotBugs did not produce XML output"
            )

        try:
            xml_text = output_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return self._fatal(
                spec, started, finished, result, note=f"failed to read SpotBugs output: {exc}"
            )

        try:
            observations, coverage_records = parse_spotbugs_xml(
                xml_text,
                run_id=spec.run_id or "unassigned",
                tool_version=cap.version or "unknown",
                source_snapshot=spec.target_commit_sha,
            )
        except (ET.ParseError, SyntaxError, TypeError, ValueError) as exc:
            return self._fatal(
                spec, started, finished, result, note=f"failed to parse SpotBugs XML: {exc}"
            )

        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version=cap.version or "unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            observations=observations,
            coverage_records=coverage_records,
            raw_output_refs=[],
            eligible_units=len(coverage_records),
            analyzed_units=sum(
                1 for c in coverage_records if c.status == CoverageUnitStatus.ANALYZED
            ),
            skipped_units=0,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={},
        )


__all__ = ["SpotBugsAdapter", "parse_spotbugs_xml"]
