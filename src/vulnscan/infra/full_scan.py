"""Full scans isolate target builds from credentials and the persistent advisory cache."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from filelock import FileLock, Timeout

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    LanguageKind,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    ToolName,
    language_from_extension,
)
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.process import CommandResult, ScanCancelled, _cancel_check, run_command

IMAGE = "devsecops-agent-scanners:0.2.0"
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz"
KEV_FEED = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
)


def _container(mounts: list[str], command: list[str], timeout: float) -> CommandResult:
    name = "vulnscan-" + uuid.uuid4().hex
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--user",
        f"{getattr(os, 'getuid', lambda: 1000)()}:{getattr(os, 'getgid', lambda: 1000)()}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=4g",
        "--cpus=2",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,exec,size=3g",
    ]
    for mount in mounts:
        argv.extend(["--mount", mount])
    try:
        return run_command([*argv, IMAGE, *command], timeout=max(0.0, timeout))
    finally:
        token = _cancel_check.set(lambda: False)
        try:
            run_command(["docker", "rm", "-f", name], timeout=10)
        finally:
            _cancel_check.reset(token)


@contextmanager
def _advisories(spec: ScanSpecification, timeout: float) -> Iterator[Path]:
    # The updater has no target mount. Untrusted Maven builds never receive write
    # access to this shared database, so one target cannot poison a later scan.
    root = Path(spec.metadata.get("configuration", {}).get("output_dir", "artifacts")).resolve()
    cache = root / ".scanner-data" / "dependency-check-13.0.0"
    if not cache.resolve().is_relative_to(root):
        raise RuntimeError("advisory cache path escapes the artifact directory")
    cache.mkdir(parents=True, exist_ok=True)
    lock = FileLock(str(cache) + ".lock", timeout=0)
    started = time.monotonic()
    while True:
        if _cancel_check.get()():
            raise ScanCancelled()
        if time.monotonic() - started >= timeout:
            raise RuntimeError("timed out waiting for the advisory cache")
        try:
            lock.acquire()
            break
        except Timeout:
            time.sleep(0.1)
    try:
        ready = cache / "ready.json"
        force_update = not ready.is_file()
        ready.unlink(missing_ok=True)
        command = [
            "dependency-check",
            "--updateonly",
            "--data",
            "/data",
            "--nvdDatafeed",
            NVD_FEED,
            "--kevURL",
            KEV_FEED,
        ]
        if force_update:
            command += ["--nvdValidForHours", "0"]
        result = _container(
            [f"type=bind,source={cache},target=/data"],
            command,
            timeout - (time.monotonic() - started),
        )
        if not result.succeeded or not (cache / "odc.mv.db").is_file():
            raise RuntimeError(
                f"Advisory initialization failed (exit {result.returncode}, timeout={result.timed_out}): "
                + (result.stderr or result.stdout)[-2000:]
            )
        ready.write_text(
            json.dumps({"version": "13.0.0", "updated_at": datetime.now(UTC).isoformat()}),
            encoding="utf-8",
        )
        yield cache
    finally:
        lock.release()


def ensure_maven_build(workdir: str, timeout: float) -> str | None:
    """Compile a Maven checkout in place so bytecode scanners can run.

    Returns None on success (or when there is nothing to build), otherwise
    a short reason. Never raises. Only builds when ``pom.xml`` exists and
    ``target/classes`` or ``target/dependency`` is missing.
    """
    from pathlib import Path

    from vulnscan.scanners.platform import which
    from vulnscan.scanners.process import run_command

    root = Path(workdir)
    if not (root / "pom.xml").is_file():
        return None
    if (root / "target" / "classes").is_dir() and (root / "target" / "dependency").is_dir():
        return None
    maven = which("mvn.cmd") or which("mvn")
    if maven is None:
        return "maven not on PATH — install Maven or pre-build target/classes"
    env: dict[str, str] = {}
    if "JAVA_HOME" in os.environ:
        env["JAVA_HOME"] = os.environ["JAVA_HOME"]
    build = run_command(
        [
            maven,
            "-B",
            "-DskipTests",
            "compile",
            "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies",
        ],
        cwd=str(root),
        timeout=timeout,
        env=env or None,
    )
    if build.succeeded:
        return None
    return "maven build failed: " + (
        (build.stderr or build.stdout).strip()[-500:] or "unknown error"
    )


def run_isolated_tool(tool: ToolName, spec: ScanSpecification, timeout: float) -> ScannerResult:
    started = time.monotonic()
    try:
        with ExitStack() as stack:
            cache = (
                stack.enter_context(_advisories(spec, timeout))
                if tool == ToolName.OWASP_DEPENDENCY_CHECK
                else None
            )
            cache_hash = ""
            execution_spec = spec.model_copy(deep=True)
            temporary = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="vulnscan-container-")
            )
            output = Path(temporary).resolve()
            mounts = [
                f"type=bind,source={Path(spec.repository_checkout_path).resolve()},target=/input,readonly",
                f"type=bind,source={output},target=/output",
            ]
            if cache:
                mounts.append(f"type=bind,source={cache},target=/advisories,readonly")
                execution_spec.metadata["advisory_cache_ready"] = True
                with (cache / "odc.mv.db").open("rb") as stream:
                    cache_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            (output / "spec.json").write_text(execution_spec.model_dump_json(), encoding="utf-8")
            result = _container(
                mounts,
                ["python", "-m", "vulnscan.infra.full_scan", tool.value],
                timeout - (time.monotonic() - started),
            )
            path = output / "result.json"
            if not result.succeeded or not path.exists():
                raise RuntimeError(
                    f"Isolated scan failed (exit {result.returncode}, timeout={result.timed_out}); verify the scanner image and Docker resource limits. "
                    + result.stderr[-2000:]
                )
            parsed = ScannerResult.model_validate_json(path.read_text(encoding="utf-8"))
            if cache_hash:
                parsed.metadata["advisory_database_sha256"] = cache_hash
            return parsed
    except RuntimeError as exc:
        now = datetime.now(UTC)
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=tool,
            tool_version="unknown",
            adapter_version="0.2.0",
            status=RunStatus.FAILED,
            started_at=now,
            finished_at=now,
            errors=[str(exc)],
        )


def main() -> None:
    spec = ScanSpecification.model_validate_json(Path("/output/spec.json").read_text())
    tool = ToolName(sys.argv[1])
    if spec.metadata.get("advisory_cache_ready"):
        shutil.copytree(
            "/advisories",
            "/tmp/dependency-check-data",
            ignore=shutil.ignore_patterns("*.lock", "*.trace.db"),
        )
    work = Path("/tmp/checkout")
    shutil.copytree("/input", work, ignore=shutil.ignore_patterns(".git"))
    spec.repository_checkout_path = str(work)
    now = datetime.now(UTC)
    started = time.monotonic()
    goals = ["compile", "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies"]
    build = run_command(
        ["mvn", "-B", "-Dmaven.repo.local=/tmp/m2", "-Duser.home=/tmp", "-DskipTests", *goals],
        cwd=work,
        timeout=spec.max_wall_seconds,
    )

    # CodeQL database creation traces its own build (and JavaScript targets need
    # no Maven build at all), so a failed pre-build is a warning for the opt-in
    # DEEP step rather than a fatal gate as it is for bytecode scanners.
    build_required = tool != ToolName.CODEQL
    if build_required and not build.succeeded:
        result = ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=tool,
            tool_version="unknown",
            adapter_version="0.2.0",
            status=RunStatus.FAILED,
            started_at=now,
            finished_at=datetime.now(UTC),
            errors=["Maven compilation failed: " + (build.stderr or build.stdout)[-1500:]],
        )
    else:
        adapter = AdapterRegistry.default().get(tool)
        assert adapter is not None
        adapter.default_timeout = max(
            1.0, (spec.max_wall_seconds or 600) - (time.monotonic() - started)
        )
        result = adapter.run(spec, workdir=str(work))
        if tool == ToolName.CODEQL and not build.succeeded and result.is_complete:
            result.warnings.insert(
                0,
                "Maven pre-build failed; CodeQL database creation traces its own build "
                "so analysis continued: " + (build.stderr or build.stdout)[-500:],
            )
        if result.is_complete:
            if tool == ToolName.SPOTBUGS:
                result.metadata["findsecbugs_version"] = "1.14.0"
                # Maven succeeded; SpotBugs's FindBugsSummary lists analyzed source files.
                from lxml import etree

                tree = etree.parse(
                    str(work / "target/spotbugs-report.xml"),
                    parser=etree.XMLParser(resolve_entities=False, no_network=True),
                )
                analyzed = {str(e.get("path")) for e in tree.findall(".//FileStats")}
                for class_stats in tree.findall(".//ClassStats"):
                    source = class_stats.get("sourceFile")
                    class_name = class_stats.get("class", "")
                    if source:
                        package = class_name.rpartition(".")[0].replace(".", "/")
                        analyzed.add(f"{package}/{source}" if package else source)
                for observation in result.observations:
                    matches = [
                        name
                        for name in spec.metadata.get("manifest", {}).get("inventory", [])
                        if name.endswith("/" + observation.location.file_path)
                        or name == observation.location.file_path
                    ]
                    if len(matches) == 1:
                        observation.location.file_path = matches[0]
                result.coverage_records = []
                for name in spec.metadata.get("manifest", {}).get("inventory", []):
                    matched = any(name.endswith("/" + p) or name == p for p in analyzed)
                    unsupported = name.endswith(".jsp")
                    result.coverage_records.append(
                        CoverageRecord(
                            run_id=spec.run_id or "unassigned",
                            tool=tool,
                            tool_version=result.tool_version,
                            source_snapshot=spec.target_commit_sha,
                            unit_path=name,
                            unit_language=LanguageKind.JSP
                            if unsupported
                            else language_from_extension(name),
                            eligible=True,
                            status=CoverageUnitStatus.UNSUPPORTED
                            if unsupported
                            else CoverageUnitStatus.ANALYZED
                            if matched
                            else CoverageUnitStatus.NOT_PROCESSED,
                            limitation_reason="JSP compilation is unavailable"
                            if unsupported
                            else None,
                            analyzed_at=datetime.now(UTC),
                        )
                    )
            elif tool == ToolName.OWASP_DEPENDENCY_CHECK:
                reported = {Path(c.unit_path).name for c in result.coverage_records}
                for artifact in (work / "target/dependency").glob("*.jar"):
                    if artifact.name not in reported:
                        result.coverage_records.append(
                            CoverageRecord(
                                run_id=spec.run_id or "unassigned",
                                tool=tool,
                                tool_version=result.tool_version,
                                source_snapshot=spec.target_commit_sha,
                                unit_path=artifact.name,
                                unit_language=LanguageKind.OTHER,
                                eligible=True,
                                status=CoverageUnitStatus.NOT_PROCESSED,
                                limitation_reason="Resolved Maven artifact is missing from the scanner report",
                                analyzed_at=datetime.now(UTC),
                            )
                        )
                result.coverage_records.append(
                    CoverageRecord(
                        run_id=spec.run_id or "unassigned",
                        tool=tool,
                        tool_version=result.tool_version,
                        source_snapshot=spec.target_commit_sha,
                        unit_path="pom.xml",
                        unit_language=LanguageKind.OTHER,
                        eligible=True,
                        status=CoverageUnitStatus.ANALYZED,
                        analyzed_at=datetime.now(UTC),
                    )
                )
    from vulnscan.core.security import sanitize

    Path("/output/result.json").write_text(
        json.dumps(sanitize(result.model_dump(mode="json"))), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
