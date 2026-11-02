"""SpotBugs coverage completion: clean compiled files count as analyzed.

BugInstance entries only reference files WITH bugs. Without completion,
reconcile() would flag every clean file as "missing coverage" and flood
run errors (and the HTML chip) with hundreds of false lines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageUnitStatus,
    ScanSpecification,
    ToolConfig,
    ToolName,
)
from vulnscan.scanners.process import CommandResult
from vulnscan.scanners.spotbugs_adapter import SpotBugsAdapter

_BUGGY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
  <BugInstance type="EI_EXPOSE_REP" priority="2" category="BAD_PRACTICE" shortMessage="expose">
    <LongMessage>exposes internal representation</LongMessage>
    <Class classname="org.example.Holder"/>
    <Method name="&lt;init&gt;"/>
    <SourceLine classname="org.example.Holder" sourcepath="src/main/java/org/example/Holder.java" start="10"/>
  </BugInstance>
  <BugInstance type="DM_DEFAULT_ENCODING" priority="3" category="I18N" shortMessage="encoding">
    <LongMessage>relies on default encoding</LongMessage>
    <Class classname="org.example.Holder"/>
    <SourceLine classname="org.example.Holder" sourcepath="src/main/java/org/example/Holder.java" start="20"/>
  </BugInstance>
</BugCollection>
"""


def _spec(tmp_path: Path) -> ScanSpecification:
    metadata: dict[str, Any] = {
        "configuration": {"output_dir": str(tmp_path / "artifacts")},
        "manifest": {
            "inventory": [
                "src/main/java/org/example/Holder.java",
                "src/main/java/org/example/Clean.java",
                "src/main/java/org/example/NeverCompiled.java",
                "src/main/resources/app.js",
            ]
        },
    }
    return ScanSpecification(
        run_id="run-spotbugs-cov",
        target_repository_url="https://example.invalid/repo.git",
        target_commit_sha="abc123def456",
        repository_checkout_path=str(tmp_path),
        language="java",
        tools=[ToolConfig(tool=ToolName.SPOTBUGS, enabled=True)],
        metadata=metadata,
    )


def _ok_xml() -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout="",
        stderr="",
        duration_ms=10,
        timed_out=False,
    )


def test_clean_compiled_files_marked_analyzed(tmp_path: Path, monkeypatch) -> None:
    classes = tmp_path / "target" / "classes" / "org" / "example"
    classes.mkdir(parents=True)
    (classes / "Holder.class").write_bytes(b"\xca\xfe\xba\xbe")
    (classes / "Clean.class").write_bytes(b"\xca\xfe\xba\xbe")
    (tmp_path / "target" / "spotbugs-report.xml").write_text(
        _BUGGY_XML, encoding="utf-8"
    )
    adapter = SpotBugsAdapter()

    def fake_invoke(argv, **kw):
        (tmp_path / "target" / "spotbugs-report.xml").write_text(_BUGGY_XML, encoding="utf-8")
        return _ok_xml()

    monkeypatch.setattr(adapter, "_invoke", fake_invoke)
    result = adapter.run(_spec(tmp_path), workdir=str(tmp_path))
    assert result.status.value == "completed"
    by_path = {c.unit_path: c.status for c in result.coverage_records}
    assert by_path.get("src/main/java/org/example/Holder.java") == CoverageUnitStatus.ANALYZED
    assert by_path.get("src/main/java/org/example/Clean.java") == CoverageUnitStatus.ANALYZED
    # No compiled counterpart -> unsupported with reason, never "missing".
    assert by_path.get("src/main/java/org/example/NeverCompiled.java") == CoverageUnitStatus.UNSUPPORTED
    # Non-Java units are out of scope, recorded not missing.
    assert by_path.get("src/main/resources/app.js") == CoverageUnitStatus.UNSUPPORTED


def test_spotbugs_cwe_mapping() -> None:
    from vulnscan.contracts import CWECategory
    from vulnscan.scanners.spotbugs_adapter import _spotbugs_cwe

    assert _spotbugs_cwe("SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE", "SQL") == CWECategory.SQL_INJECTION
    assert _spotbugs_cwe("EI_EXPOSE_REP2", "BAD_PRACTICE") == CWECategory.SENSITIVE_DATA_EXPOSURE
    assert _spotbugs_cwe("DMI_RANDOM_USED_ONLY_ONCE", "BAD_PRACTICE") == CWECategory.INSECURE_RANDOMNESS
    assert _spotbugs_cwe("RV_RETURN_VALUE_IGNORED", "BAD_PRACTICE") == CWECategory.UNCHECKED_RETURN_VALUE
    assert _spotbugs_cwe("URF_UNREAD_FIELD", "STYLE") == CWECategory.UNUSED_ASSIGNMENT
    assert _spotbugs_cwe("OBL_UNSATISFIED_OBLIGATION", "BAD_PRACTICE") == CWECategory.IMPROPER_RESOURCE_SHUTDOWN
    assert _spotbugs_cwe("REC_CATCH_EXCEPTION", "BAD_PRACTICE") == CWECategory.GENERIC_EXCEPTION_CAUGHT
    assert _spotbugs_cwe("DM_DEFAULT_ENCODING", "I18N") == CWECategory.UNICODE_ENCODING_ERROR
    assert _spotbugs_cwe("DE_MIGHT_IGNORE", "BAD_PRACTICE") == CWECategory.IMPROPER_EXCEPTION_CHECK
    assert _spotbugs_cwe("VA_FORMAT_STRING_USES_NEWLINE", "I18N") == CWECategory.EXTERNALLY_CONTROLLED_FORMAT_STRING
    assert _spotbugs_cwe("MS_PKGPROTECT", "MALICIOUS_CODE") is None
    assert _spotbugs_cwe("SOMETHING_ELSE", "CORRECTNESS") is None
