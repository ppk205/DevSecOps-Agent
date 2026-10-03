"""Shared persistent scan application service (FR-70..73, DR-09, IR-15)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from sqlalchemy import delete

from vulnscan.contracts import ExportFormat, Finding, ScannerResult, ScanSpecification
from vulnscan.decisions.config import LayaConfig
from vulnscan.pipeline.runner import ScanPipeline
from vulnscan.reporting.reporter import ReportGenerator
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.process import ScanCancelled, _cancel_check, run_command
from vulnscan.storage.database import get_session, init_db
from vulnscan.storage.models import FindingORM, RunORM, StageORM, TargetORM
from vulnscan.version import APP_VERSION

from .config import ScanConfig
from .policy import gate
from .security import sanitize


@dataclass(frozen=True)
class ProgressEvent:
    run_id: str
    stage: str
    status: str
    timestamp: str
    message: str


def checkout_manifest(
    checkout: str, config: ScanConfig, expected: str = "", *, excluded: list[Path] | None = None
) -> dict[str, Any]:
    root = Path(checkout).resolve(strict=True)
    runtime = [p.resolve() for p in (excluded or [])]

    def owned_runtime(name: str) -> bool:
        path = (root / name).resolve()
        return any(path == item or path.is_relative_to(item) for item in runtime)

    result = run_command(["git", "rev-parse", "HEAD"], cwd=root)
    if not result.succeeded:
        raise ValueError("checkout must be a Git repository with a committed revision")
    commit = result.stdout.strip()
    if expected and not commit.startswith(expected):
        raise ValueError("requested commit does not match the checked-out commit")
    status = run_command(["git", "status", "--porcelain", "-z", "--untracked-files=all"], cwd=root)
    if not status.succeeded:
        raise ValueError("cannot verify checkout cleanliness")
    changes = [entry for entry in status.stdout.split("\0") if entry]
    dirty = bool(changes) if config.ci else any(not owned_runtime(entry[3:]) for entry in changes)
    if dirty and (config.ci or not config.allow_dirty):
        raise ValueError(
            "dirty checkout: commit changes or explicitly enable --allow-dirty locally"
        )
    listing = run_command(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    )
    if not listing.succeeded:
        raise ValueError("cannot inventory checkout")
    files: dict[str, str] = {}
    for name in sorted(set(listing.stdout.split("\0")) - {""}):
        if owned_runtime(name):
            continue
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("symlink targets are unsupported; use a self-contained checkout")
        if path.is_dir():
            raise ValueError("Git submodules require a separate scan")
        if path.is_file():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(files) > config.max_files:
            raise ValueError("checkout exceeds configured max_files")
    return {
        "commit": commit,
        "dirty": dirty,
        "runtime_exclusions": [str(p) for p in runtime if p.is_relative_to(root)],
        "files": files,
        "inventory": [n for n in files if n.endswith((".java", ".jsp"))],
    }


def reconcile(results: list[ScannerResult], manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for result in results:
        if result.run_id != (
            result.observations[0].run_id if result.observations else result.run_id
        ):
            errors.append(f"{result.tool.value}: observation run identity mismatch")
        for record in result.coverage_records:
            if record.eligible and record.status.value not in {
                "analyzed",
                "unsupported",
                "not_eligible",
            }:
                errors.append(
                    f"{result.tool.value}: incomplete coverage: {record.unit_path}: {record.status.value}"
                )
        if not result.is_complete:
            continue
        records = {c.unit_path.replace("\\", "/"): c for c in result.coverage_records}
        # Dependency analysis covers dependency artifacts, not Java source units.
        expected = (
            manifest["inventory"] if result.tool.value != "owasp-dependency-check" else ["pom.xml"]
        )
        for name in expected:
            coverage = records.get(name)
            if coverage is None:
                errors.append(f"{result.tool.value}: missing coverage for {name}")
            elif coverage.status.value not in {"analyzed", "unsupported", "not_eligible"}:
                errors.append(f"{result.tool.value}: {name}: {coverage.status.value}")
            elif coverage.status.value == "unsupported" and not coverage.limitation_reason:
                errors.append(f"{result.tool.value}: unsupported coverage needs a reason: {name}")
    return errors


class ScanService:
    def __init__(
        self, db_path: str = "vulnscan.db", registry: AdapterRegistry | None = None
    ) -> None:
        self.db_path = str(Path(db_path).resolve())
        init_db(self.db_path)
        self.lock = FileLock(self.db_path + ".lock", timeout=0)
        self.registry = registry or AdapterRegistry.default()

    def recover(self) -> None:
        try:
            with self.lock:
                self._recover_locked()
        except Timeout:
            pass  # A live process owns the scan; it must not be marked interrupted.

    def _recover_locked(self) -> None:
        with get_session(self.db_path) as session:
            for row in session.query(RunORM).filter(RunORM.status.in_(["running", "queued"])):
                row.status = "interrupted"
                summary = json.loads(row.result_json or "{}")
                summary.update(status="interrupted", exit_code=130, gate="failed")
                row.result_json = json.dumps(summary)
                for stage in row.stages:
                    if stage.status == "running":
                        stage.status = "interrupted"
                        stage.completed_at = datetime.now(UTC)

    def runtime_paths(self, config: ScanConfig) -> list[Path]:
        paths = [
            Path(self.db_path + suffix)
            for suffix in ("", "-wal", "-shm", ".lock", ".migration.lock")
        ]
        paths.append(Path(config.output_dir).resolve() / ".scanner-data")
        with get_session(self.db_path) as session:
            for row in session.query(RunORM).filter(RunORM.public_id.is_not(None)):
                if row.public_id and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", row.public_id):
                    saved = (
                        json.loads(row.scan_spec_json).get("metadata", {}).get("configuration", {})
                    )
                    if saved.get("output_dir"):
                        paths.append(Path(saved["output_dir"]).resolve() / row.public_id)
        return paths

    def history(self) -> list[dict[str, Any]]:
        with get_session(self.db_path) as session:
            return [
                {
                    "id": r.id,
                    "run_id": r.public_id or str(r.id),
                    "status": r.status,
                    "attempt": r.attempt,
                    "created_at": r.created_at.replace(tzinfo=UTC).isoformat(),
                }
                for r in session.query(RunORM).order_by(RunORM.id.desc()).limit(100)
            ]

    def resolve_id(self, identifier: int | str) -> int:
        with get_session(self.db_path) as session:
            row = (
                session.get(RunORM, int(identifier))
                if str(identifier).isdigit()
                else session.query(RunORM).filter_by(public_id=str(identifier)).first()
            )
            if row is None:
                raise ValueError("run not found")
            return row.id

    def detail(self, run_id: int | str) -> dict[str, Any]:
        run_id = self.resolve_id(run_id)
        with get_session(self.db_path) as session:
            row = session.get(RunORM, run_id)
            if row is None:
                raise ValueError("run not found")
            return {
                "id": row.id,
                "run_id": row.public_id or str(row.id),
                "status": row.status,
                "spec": json.loads(row.scan_spec_json),
                "result": json.loads(row.result_json),
                "events": json.loads(row.events_json),
                "findings": [json.loads(f.finding_json) for f in row.findings],
            }

    def cancel(self, run_id: int | str) -> None:
        run_id = self.resolve_id(run_id)
        with get_session(self.db_path) as session:
            row = session.get(RunORM, run_id)
            if row is None:
                raise ValueError("run not found")
            row.cancel_requested = 1

    def retry(
        self,
        run_id: int | str,
        on_event: Callable[[ProgressEvent], None] | None = None,
        cancel_signal: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        run_id = self.resolve_id(run_id)
        prior = self.detail(run_id)
        if prior["status"] in {"queued", "running"}:
            raise ValueError("cannot retry an active scan")
        spec = ScanSpecification.model_validate(prior["spec"])
        config = ScanConfig.model_validate(spec.metadata.get("configuration", {}))
        return self.run(
            spec.repository_checkout_path,
            config,
            repo=spec.target_repository_url,
            expected_commit=spec.target_commit_sha,
            parent_id=run_id,
            on_event=on_event,
            cancel_signal=cancel_signal,
        )

    def export(self, run_id: int | str, fmt: ExportFormat, output: str) -> str:
        detail = self.detail(run_id)
        generator = ReportGenerator(
            detail["run_id"],
            [Finding.model_validate(f) for f in detail["findings"]],
            coverage_summary=detail["result"].get("coverage", {}),
            routing_payloads=detail["result"].get("routing", []),
            run_metadata={
                "status": detail["status"],
                "gate": detail["result"].get("gate"),
                "errors": detail["result"].get("errors", []),
                "commit": detail["spec"].get("target_commit_sha"),
                "configuration": detail["spec"].get("metadata", {}).get("configuration", {}),
            },
        )
        return str(generator.export(fmt, output).artifact_ref.path)

    def run(
        self,
        checkout: str,
        config: ScanConfig,
        *,
        repo: str = "local",
        expected_commit: str = "",
        public_id: str | None = None,
        parent_id: int | None = None,
        on_event: Callable[[ProgressEvent], None] | None = None,
        cancel_signal: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        try:
            self.lock.acquire()
        except Timeout as exc:
            raise ValueError("another scan is active in this database") from exc
        try:
            self._recover_locked()
            return self._run(
                checkout,
                config,
                repo,
                expected_commit,
                public_id,
                parent_id,
                on_event,
                cancel_signal,
            )
        finally:
            self.lock.release()

    def _run(
        self,
        checkout: str,
        config: ScanConfig,
        repo: str,
        expected_commit: str,
        public_id: str | None,
        parent_id: int | None,
        on_event: Callable[[ProgressEvent], None] | None,
        cancel_signal: Callable[[], bool] | None,
    ) -> dict[str, Any]:
        run_id = public_id or "run-" + uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("run ID must contain only letters, digits, underscores and hyphens")
        with get_session(self.db_path) as session:
            if session.query(RunORM).filter_by(public_id=run_id).first() is not None:
                raise ValueError("run ID already exists; choose a new attempt ID")
        output = Path(config.output_dir).resolve() / run_id
        if output.exists() or output.is_symlink():
            raise ValueError("run artifact directory already exists; choose a new run ID")
        output.mkdir(parents=True)
        results: list[ScannerResult] = []
        findings: list[Finding] = []
        events: list[dict[str, Any]] = []
        errors: list[str] = []
        manifest: dict[str, Any] = {"inventory": [], "files": {}}
        spec = config.specification(
            str(Path(checkout).resolve()), expected_commit or "unresolved", sanitize(repo)
        )
        spec.run_id = run_id
        with get_session(self.db_path) as session:
            target = TargetORM(
                repository_url=spec.target_repository_url, commit_sha=spec.target_commit_sha
            )
            session.add(target)
            session.flush()
            parent = session.get(RunORM, parent_id) if parent_id else None
            row = RunORM(
                target_id=target.id,
                public_id=run_id,
                status="running",
                parent_id=parent_id,
                attempt=parent.attempt + 1 if parent else 1,
                scan_spec_json=spec.model_dump_json(),
            )
            session.add(row)
            session.flush()
            pk = row.id
        started = time.monotonic()

        def cancelled() -> bool:
            if cancel_signal and cancel_signal():
                return True
            with get_session(self.db_path) as session:
                row = session.get(RunORM, pk)
                return bool(row and row.cancel_requested)

        def persist(stage: str, status: str, message: str = "") -> None:
            event = ProgressEvent(
                run_id, stage, status, datetime.now(UTC).isoformat(), sanitize(message)
            )
            events.append(asdict(event))
            with get_session(self.db_path) as session:
                row = session.get(RunORM, pk)
                assert row is not None
                row.events_json = json.dumps(events)
                row.scan_spec_json = spec.model_dump_json()
                row.result_json = json.dumps(
                    sanitize(
                        {
                            "scanner_results": [r.model_dump(mode="json") for r in results],
                            "coverage": {
                                r.tool.value: [
                                    c.model_dump(mode="json") for c in r.coverage_records
                                ]
                                for r in results
                            },
                        }
                    )
                )
                row.target.commit_sha = spec.target_commit_sha
                stage_row = session.query(StageORM).filter_by(run_id=pk, name=stage).first()
                if stage_row is None:
                    stage_row = StageORM(
                        run_id=pk, name=stage, ordinal=len(events), started_at=datetime.now(UTC)
                    )
                    session.add(stage_row)
                stage_row.status = status
                stage_row.error_message = event.message
                if status != "running":
                    stage_row.completed_at = datetime.now(UTC)
                session.execute(delete(FindingORM).where(FindingORM.run_id == pk))
                for finding in findings:
                    session.add(FindingORM(run_id=pk, finding_json=finding.model_dump_json()))
            if on_event:
                on_event(event)

        snapshot = tempfile.TemporaryDirectory(prefix="vulnscan-snapshot-")
        token = _cancel_check.set(cancelled)
        was_cancelled = False
        routing: list[dict[str, Any]] = []
        try:
            persist("intake", "running")
            runtime = self.runtime_paths(config) + [output]
            manifest = checkout_manifest(checkout, config, expected_commit, excluded=runtime)
            spec.target_commit_sha = manifest["commit"]
            spec.metadata["manifest"] = manifest
            snapshot_root = Path(snapshot.name).resolve()
            for name, expected_hash in manifest["files"].items():
                source = Path(checkout).resolve() / name
                destination = snapshot_root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_hash:
                    raise ValueError("checkout changed while preparing immutable snapshot")
            execution_spec = spec.model_copy(
                update={"repository_checkout_path": str(snapshot_root)}
            )
            persist("intake", "completed", f"Verified commit {manifest['commit']}")
            from dataclasses import replace

            from vulnscan.decisions.config import load_config

            advisory = (
                load_config(config.laya_config_path) if config.laya_config_path else LayaConfig()
            )
            advisory = replace(advisory, enabled=config.laya and not config.ci)
            spec.metadata["advisory_configuration"] = asdict(advisory)
            pipeline = ScanPipeline(
                spec,
                registry=self.registry,
                laya_config=advisory,
            )
            for cfg in spec.tools:
                if cancelled():
                    raise ScanCancelled()
                remaining = config.timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("scan wall-clock limit exceeded")
                persist(cfg.tool.value, "running")
                adapter = self.registry.get(cfg.tool)
                if adapter is None:
                    errors.append(f"{cfg.tool.value}: adapter unavailable")
                    persist(cfg.tool.value, "failed", errors[-1])
                    continue
                adapter.default_timeout = remaining
                try:
                    if config.profile == "full" and cfg.tool.value in {
                        "spotbugs",
                        "owasp-dependency-check",
                    }:
                        from vulnscan.infra.full_scan import run_isolated_tool

                        result = run_isolated_tool(cfg.tool, execution_spec, remaining)
                    else:
                        result = adapter.run(execution_spec, workdir=str(snapshot_root))
                    for observation in result.observations:
                        coordinate = observation.location
                        source_path = (snapshot_root / coordinate.file_path).resolve()
                        if not source_path.is_relative_to(snapshot_root):
                            raise ValueError("scanner evidence path escapes the source snapshot")
                        coordinate.file_path = source_path.relative_to(snapshot_root).as_posix()
                        if source_path.is_file():
                            if result.tool.value == "gitleaks":
                                coordinate.snippet = "[REDACTED: secret evidence]"
                            else:
                                lines = source_path.read_text(
                                    encoding="utf-8", errors="replace"
                                ).splitlines()
                                coordinate.snippet = "\n".join(
                                    lines[
                                        max(0, coordinate.line_start - 1) : min(
                                            len(lines), coordinate.line_start + 2
                                        )
                                    ]
                                )[:2000]
                    result = ScannerResult.model_validate(sanitize(result.model_dump(mode="json")))
                    if result.run_id != run_id or result.tool != cfg.tool:
                        raise ValueError(
                            "scanner result identity does not match the scan specification"
                        )
                    for observation in result.observations:
                        observation.rule_pack_version = spec.rules_packs_version
                    units = {
                        (c.unit_language.value, c.unit_path): c
                        for c in result.coverage_records
                        if c.eligible
                    }
                    result.eligible_units = len(units)
                    result.analyzed_units = sum(
                        c.status.value == "analyzed" for c in units.values()
                    )
                    result.failed_units = sum(
                        c.status.value in {"failed", "not_processed"} for c in units.values()
                    )
                    result.skipped_units = sum(
                        c.status.value in {"skipped", "unsupported"} for c in units.values()
                    )
                    result.coverage_percent = (
                        100.0 * result.analyzed_units / len(units) if units else 0.0
                    )
                    artifact = output / f"scanner-{cfg.tool.value}.json"
                    for observation in result.observations:
                        observation.raw_output_ref = str(artifact)
                    artifact.write_text(result.model_dump_json(indent=2), encoding="utf-8")
                    from vulnscan.contracts.artifact import ArtifactReference

                    result.raw_output_refs.append(
                        ArtifactReference(
                            path=str(artifact),
                            checksum_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
                            mime_type="application/json",
                            size_bytes=artifact.stat().st_size,
                        )
                    )
                    results.append(result)
                    # A scanner that reports internal errors (a ruleset that
                    # failed to load, a tool that could not run) must not be
                    # allowed to look like a clean repository: Semgrep exits 0
                    # in that case, and the gate would pass on zero findings.
                    for scan_error in result.errors:
                        errors.append(f"{cfg.tool.value}: {scan_error}")
                    findings = pipeline.build_findings(results, run_id)
                    persist(cfg.tool.value, result.status.value, "; ".join(result.errors))
                except Exception as exc:  # noqa: BLE001 ? application boundary preserves partial evidence
                    errors.append(f"{cfg.tool.value}: {type(exc).__name__}: {exc}")
                    persist(cfg.tool.value, "failed", errors[-1])
            if cancelled():
                raise ScanCancelled()
            # Detect modifications during scanning instead of claiming the original revision.
            after = checkout_manifest(checkout, config, expected_commit, excluded=runtime)
            if after["commit"] != manifest["commit"] or after["files"] != manifest["files"]:
                errors.append(
                    "checkout contents changed during scanning; retry from a stable checkout"
                )
            routing, stage = pipeline.run_routing(findings)
            if cancelled():
                raise ScanCancelled()
            persist(stage.name, stage.status, stage.detail)
            persist("targeted_deep_analysis", "unavailable", "Deep analysis is not implemented")
            persist(
                "independent_validation",
                "skipped",
                "No assessment evidence supplied; findings remain unprocessed",
            )
        except (ScanCancelled, KeyboardInterrupt):
            was_cancelled = True
            persist("execution", "cancelled", "Scan cancelled; partial evidence retained")
        except Exception as exc:  # noqa: BLE001 ? application boundary preserves partial evidence
            errors.append(f"{type(exc).__name__}: {exc}")
            persist("execution", "failed", errors[-1])
        finally:
            _cancel_check.reset(token)
            snapshot.cleanup()
        policy = gate(
            findings,
            results,
            [t.tool.value for t in spec.tools],
            config.fail_on,
            reconcile(results, manifest),
            cancelled=was_cancelled,
            errors=errors,
        )
        summary: dict[str, Any] = sanitize(
            {
                "schema_version": 1,
                "application_version": APP_VERSION,
                "id": pk,
                "run_id": run_id,
                "commit": spec.target_commit_sha,
                "manifest": manifest,
                "configuration": config.model_dump(),
                "status": "cancelled"
                if was_cancelled
                else "failed"
                if policy["exit_code"] == 2
                else "completed",
                "findings": len(findings),
                "scanner_results": [r.model_dump(mode="json") for r in results],
                "coverage": {
                    r.tool.value: [c.model_dump(mode="json") for c in r.coverage_records]
                    for r in results
                },
                "stages": events,
                "routing": routing,
                **policy,
                "reports": {},
            }
        )
        generator = ReportGenerator(
            run_id,
            findings,
            coverage_summary=summary["coverage"],
            routing_payloads=routing,
            run_metadata={
                "commit": spec.target_commit_sha,
                "target": spec.target_repository_url,
                "status": summary["status"],
                "gate": summary["gate"],
                "errors": summary["errors"],
                "configuration": config.model_dump(),
            },
        )
        for fmt in ExportFormat:
            try:
                summary["reports"][fmt.value] = str(generator.export(fmt, output).artifact_ref.path)
            except (OSError, ValueError) as exc:
                summary["errors"].append(sanitize(f"{fmt.value} export failed: {exc}"))
                if not was_cancelled:
                    summary.update(status="failed", exit_code=2, gate="failed")
            with get_session(self.db_path) as session:
                saved = session.get(RunORM, pk)
                assert saved is not None
                saved.result_json = json.dumps(summary)
        summary["summary_path"] = str(output / "summary.json")
        try:
            (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        except OSError as exc:
            summary["errors"].append(sanitize(f"summary export failed: {exc}"))
            if not was_cancelled:
                summary.update(status="failed", exit_code=2, gate="failed")
        with get_session(self.db_path) as session:
            saved = session.get(RunORM, pk)
            assert saved is not None
            saved.status = summary["status"]
            for saved_stage in saved.stages:
                if saved_stage.status == "running":
                    saved_stage.status = summary["status"]
                    saved_stage.completed_at = datetime.now(UTC)
            saved.result_json = json.dumps(summary)
        return summary
