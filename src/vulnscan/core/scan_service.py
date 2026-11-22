"""Dịch vụ ứng dụng quét lưu trữ bền vững dùng chung (FR-70..73, DR-09, IR-15)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from filelock import FileLock, Timeout
from sqlalchemy import func, select, update

from vulnscan.contracts import (
    ExportFormat,
    Finding,
    FindingProvenance,
    ScannerResult,
    ScanSpecification,
)
from vulnscan.contracts.enums import WEB_SOURCE_EXTENSIONS
from vulnscan.decisions.config import LayaConfig
from vulnscan.pipeline.runner import ScanPipeline
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.events import model_progress
from vulnscan.reporting.reporter import ReportGenerator
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.process import ScanCancelled, _cancel_check, run_command
from vulnscan.storage.database import get_session, init_db
from vulnscan.storage.models import FindingORM, RunORM, ScanEventORM, StageORM, TargetORM
from vulnscan.version import APP_VERSION

from .config import ScanConfig
from .finding_view import project_finding
from .policy import gate
from .security import sanitize
from .source import NO_REVISION, local_revision


@dataclass(frozen=True)
class ProgressEvent:
    run_id: str
    stage: str
    status: str
    timestamp: str
    message: str
    pk: int | None = None
    sequence: int = 0


_TEST_SEGMENTS = frozenset({"test", "tests", "it", "e2e"})


def _model_usage(calls: list[dict[str, Any]], budget: BudgetManager) -> dict[str, Any]:
    usage: dict[str, Any] = {
        "requests": len(calls),
        "completed_requests": sum(call["status"] == "completed" for call in calls),
        "failed_requests": sum(call["status"] == "failed" for call in calls),
        "usage_reported_requests": sum(bool(call.get("usage")) for call in calls),
        "http_attempts": budget.attempts,
        "max_model_requests": budget.max_requests,
        "cost_usd": None,
    }
    for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
        reported = []
        for call in calls:
            raw = call.get("usage") or {}
            if not isinstance(raw, dict):
                continue
            value = raw.get(name)
            if name == "total_tokens" and value is None:
                prompt, completion = raw.get("prompt_tokens"), raw.get("completion_tokens")
                if type(prompt) is int and type(completion) is int:
                    value = prompt + completion
            if type(value) is int and value >= 0:
                reported.append(value)
        usage[name] = sum(reported) if reported else None
    return usage


_UNVERSIONED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".devsec",
        ".tools",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)


def _credential_path(name: str) -> bool:
    return any(
        part == ".secrets"
        or part == ".env"
        or (part.startswith(".env.") and part != ".env.example")
        for part in name.lower().split("/")
    )


def _unversioned_files(root: Path, owned_runtime: Callable[[str], bool]) -> Iterator[str]:
    def unreadable(error: OSError) -> None:
        raise error

    for directory, directories, filenames in os.walk(root, onerror=unreadable, followlinks=False):
        kept = []
        for name in sorted(directories):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if (
                name in _UNVERSIONED_DIRS
                or name.startswith(".venv")
                or _credential_path(relative)
                or owned_runtime(relative)
            ):
                continue
            if path.is_symlink():
                raise ValueError(
                    "symlink targets are unsupported; use a self-contained source folder"
                )
            kept.append(name)
        directories[:] = kept
        for name in sorted(filenames):
            if name in {".git", ".hg", ".svn"}:
                continue
            yield (Path(directory) / name).relative_to(root).as_posix()


def _live_event_kind(stage: str, status: str) -> str:
    """Ánh xạ một giai đoạn pipeline sang loại scan_events (luồng dữ liệu trực tiếp Giai đoạn 3).

    Các hàng ``stage`` luôn tồn tại; loại sự kiện trực tiếp phản ánh những gì
    người vận hành thấy: tác vụ scanner là ``log``, suy luận AI là ``ai_step``,
    đề xuất là ``ai_proposal``, và kiểm tra là ``verification_result``.
    """
    if stage in {
        "model_hunt",
        "laya_batch_routing",
        "targeted_deep_analysis",
        "model_call",
        "model_tool",
    }:
        return "ai_step"
    if stage in {"laya_verification", "model_scanner_compare", "independent_validation"}:
        return "verification_result" if status in {"completed", "partial"} else "ai_step"
    if stage in {"semgrep", "gitleaks", "spotbugs", "owasp-dependency-check"}:
        return "log"
    if stage == "final_report" and status == "completed":
        return "stage"
    return "stage"


def _is_scanned_source(name: str) -> bool:
    """Mã nguồn sản xuất (production) là bề mặt tấn công; mã nguồn kiểm thử (test) thì không.

    Các file kiểm thử vẫn nằm trong ảnh chụp nhanh bất biến (``files``) — chỉ có danh
    mục quét bị thu hẹp, vì vậy không có gì bị âm thầm loại bỏ khỏi bằng chứng.

    Một repo có thể lồng dự án của nó dưới một thư mục cha (``Comic/src/test/``)
    hoặc sử dụng cấu trúc không phải Maven, vì vậy việc phát hiện dựa trên phân đoạn đường dẫn chứ không phải tiền tố:
    bất kỳ phân đoạn nào là dấu hiệu kiểm thử đều sẽ loại trừ file đó.
    """
    if not name.endswith(tuple(WEB_SOURCE_EXTENSIONS)):
        return False
    return not any(segment in _TEST_SEGMENTS for segment in name.split("/"))


def checkout_manifest(
    checkout: str, config: ScanConfig, expected: str = "", *, excluded: list[Path] | None = None
) -> dict[str, Any]:
    root = Path(checkout).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("scan target must be a local source folder")
    runtime = [p.resolve() for p in (excluded or [])]

    def owned_runtime(name: str) -> bool:
        path = (root / name).resolve()
        return any(path == item or path.is_relative_to(item) for item in runtime)

    commit, revision_reason = local_revision(root, run_command)
    if expected and not commit.lower().startswith(expected.lower()):
        raise ValueError("requested commit does not match the checked-out commit")
    dirty: bool | None = None
    if commit == NO_REVISION:
        if config.ci:
            raise ValueError(
                "CI requires a committed Git revision and verified checkout cleanliness"
            )
        names = _unversioned_files(root, owned_runtime)
    else:
        status = run_command(
            ["git", "status", "--porcelain", "-z", "--untracked-files=all"], cwd=root
        )
        if not status.succeeded:
            raise ValueError("cannot verify checkout cleanliness")
        changes = [entry for entry in status.stdout.split("\0") if entry]
        dirty = (
            bool(changes) if config.ci else any(not owned_runtime(entry[3:]) for entry in changes)
        )
        if dirty and (config.ci or not config.allow_dirty):
            raise ValueError(
                "dirty checkout: commit changes or explicitly enable --allow-dirty locally"
            )
        listing = run_command(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
        )
        if not listing.succeeded:
            raise ValueError("cannot inventory checkout")
        names = iter(sorted(set(listing.stdout.split("\0")) - {""}))
    files: dict[str, str] = {}
    for name in names:
        if _credential_path(name) or owned_runtime(name):
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
        "revision_reason": revision_reason,
        "runtime_exclusions": [str(p) for p in runtime if p.is_relative_to(root)],
        "files": files,
        "inventory": [n for n in files if _is_scanned_source(n)],
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
        # Dependency/IaC/dataflow analyzers cover manifests, config files, or
        # analyzed units rather than every source file in inventory.
        if result.tool.value in {"trivy", "codeql"}:
            expected = [c.unit_path for c in result.coverage_records if c.eligible]
        elif result.tool.value == "owasp-dependency-check":
            expected = ["pom.xml"] if "pom.xml" in manifest.get("files", {}) else []
        else:
            expected = manifest["inventory"]
        for name in expected:
            coverage = records.get(name)
            if coverage is None:
                errors.append(f"{result.tool.value}: missing coverage for {name}")
            elif coverage.status.value not in {"analyzed", "unsupported", "not_eligible"}:
                errors.append(f"{result.tool.value}: {name}: {coverage.status.value}")
            elif coverage.status.value == "unsupported" and not coverage.limitation_reason:
                errors.append(f"{result.tool.value}: unsupported coverage needs a reason: {name}")
    return errors


def _finalize_scanner_result(
    result: ScannerResult,
    *,
    snapshot_root: Path,
    output: Path,
    spec: ScanSpecification,
    run_id: str,
) -> ScannerResult:
    """Normalize paths, snippets, coverage counts, and persist scanner-<tool>.json."""
    from vulnscan.contracts.artifact import ArtifactReference

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
                lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
                coordinate.snippet = "\n".join(
                    lines[
                        max(0, coordinate.line_start - 1) : min(
                            len(lines), coordinate.line_start + 2
                        )
                    ]
                )[:2000]
    result = ScannerResult.model_validate(sanitize(result.model_dump(mode="json")))
    if result.run_id != run_id:
        raise ValueError("scanner result identity does not match the scan specification")
    for observation in result.observations:
        observation.rule_pack_version = spec.rules_packs_version
    units = {(c.unit_language.value, c.unit_path): c for c in result.coverage_records if c.eligible}
    result.eligible_units = len(units)
    result.analyzed_units = sum(c.status.value == "analyzed" for c in units.values())
    result.failed_units = sum(c.status.value in {"failed", "not_processed"} for c in units.values())
    result.skipped_units = sum(c.status.value in {"skipped", "unsupported"} for c in units.values())
    result.coverage_percent = 100.0 * result.analyzed_units / len(units) if units else 0.0
    artifact = output / f"scanner-{result.tool.value}.json"
    for observation in result.observations:
        observation.raw_output_ref = str(artifact)
    artifact.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    result.raw_output_refs.append(
        ArtifactReference(
            path=str(artifact),
            checksum_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            mime_type="application/json",
            size_bytes=artifact.stat().st_size,
        )
    )
    return result


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
            pass  # Một tiến trình đang chạy sở hữu lần quét; nó không được đánh dấu là bị gián đoạn.

    def _recover_locked(self, exclude_public_id: str | None = None) -> None:
        with get_session(self.db_path) as session:
            query = session.query(RunORM).filter(RunORM.status.in_(["running", "queued"]))
            if exclude_public_id:
                query = query.filter(
                    (RunORM.public_id.is_(None)) | (RunORM.public_id != exclude_public_id)
                )
            for row in query:
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
                for r in session.execute(
                    select(
                        RunORM.id,
                        RunORM.public_id,
                        RunORM.status,
                        RunORM.attempt,
                        RunORM.created_at,
                    )
                    .order_by(RunORM.id.desc())
                    .limit(100)
                )
            ]

    def summary(self, identifier: int | str) -> dict[str, Any]:
        pk = self.resolve_id(identifier)
        with get_session(self.db_path) as session:
            row = session.execute(
                select(RunORM.id, RunORM.public_id, RunORM.status, RunORM.findings_revision).where(
                    RunORM.id == pk
                )
            ).one()
            return {
                "id": row.id,
                "run_id": row.public_id or str(row.id),
                "status": row.status,
                "revision": row.findings_revision,
            }

    def finding_page(
        self, identifier: int | str, query: str = "", offset: int = 0, limit: int = 200
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid finding page")
        info = self.summary(identifier)
        clauses: list[Any] = [FindingORM.run_id == info["id"]]
        fields = {
            "severity": "severity",
            "cwe": "cwe_category",
            "status": "status",
            "scanner": "scanner",
        }
        for term in query.lower().split():
            column: Any = FindingORM.search_text
            value = term
            if ":" in term:
                name, value = term.split(":", 1)
                if name not in fields:
                    clauses.append(False)
                    continue
                column = func.lower(func.json_extract(FindingORM.summary_json, "$." + fields[name]))
            pattern = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(column.like("%" + pattern + "%", escape="\\"))
        with get_session(self.db_path) as session:
            total = session.scalar(select(func.count()).select_from(FindingORM).where(*clauses))
            rows = session.scalars(
                select(FindingORM.summary_json)
                .where(*clauses)
                .order_by(FindingORM.id)
                .offset(offset)
                .limit(limit)
            )
            return {
                **info,
                "items": [json.loads(r) for r in rows],
                "total": total or 0,
                "offset": offset,
                "limit": limit,
            }

    def activity(self, identifier: int | str) -> dict[str, Any]:
        """FR-71/DR-09: hoạt động được giữ lại mà không cần tải toàn bộ payload của finding."""
        pk = self.resolve_id(identifier)
        with get_session(self.db_path) as session:
            names = ("gate", "exit_code", "errors", "reports", "summary_path", "ai_usage")
            row = session.execute(
                select(
                    RunORM.public_id,
                    RunORM.status,
                    RunORM.events_json,
                    *(func.json_extract(RunORM.result_json, "$." + name) for name in names),
                ).where(RunORM.id == pk)
            ).one()
            result = dict(zip(names, row[3:], strict=True))
            for name, default in (("errors", []), ("reports", {}), ("ai_usage", {})):
                result[name] = json.loads(result[name]) if result[name] else default
            result.update(
                run_id=row[0] or str(pk),
                status=row[1],
                findings=session.scalar(
                    select(func.count()).select_from(FindingORM).where(FindingORM.run_id == pk)
                )
                or 0,
            )
            return {"id": pk, "events": json.loads(row[2] or "[]"), "result": result}

    def finding(self, identifier: int | str, finding_id: str) -> dict[str, Any]:
        pk = self.resolve_id(identifier)
        with get_session(self.db_path) as session:
            payload = session.scalar(
                select(FindingORM.finding_json)
                .where(FindingORM.run_id == pk, FindingORM.finding_id == finding_id)
                .order_by(FindingORM.id)
                .limit(1)
            )
            if payload is None:
                raise ValueError("finding not found")
            item: dict[str, Any] = json.loads(payload)
            raw_assessments = session.scalar(
                select(func.json_extract(RunORM.result_json, "$.assessments")).where(
                    RunORM.id == pk
                )
            )
            related = [
                assessment
                for assessment in json.loads(raw_assessments or "[]")
                if assessment.get("finding_id") == finding_id
            ]
            if related:
                item.setdefault("metadata", {})["ai_assessments"] = related
            return item

    def progress_since(self, identifier: int | str, cursor: int = 0) -> dict[str, Any]:
        pk = self.resolve_id(identifier)
        with get_session(self.db_path) as session:
            payload = session.scalar(select(RunORM.events_json).where(RunORM.id == pk))
            events = json.loads(payload or "[]")
            end = min(len(events), max(0, cursor) + 200)
            return {"events": events[max(0, cursor) : end], "cursor": end}

    def resolve_id(self, identifier: int | str) -> int:
        with get_session(self.db_path) as session:
            clause = (
                RunORM.id == int(identifier)
                if str(identifier).isdigit()
                else RunORM.public_id == str(identifier)
            )
            pk = session.scalar(select(RunORM.id).where(clause))
            if pk is None:
                raise ValueError("run not found")
            return pk

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
            session.execute(update(RunORM).where(RunORM.id == run_id).values(cancel_requested=1))

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
            self._recover_locked(exclude_public_id=public_id)
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
        if config.ci:
            from .config import resolve_model_config

            config = resolve_model_config(config)
        run_id = public_id or "run-" + uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
            raise ValueError("run ID must contain only letters, digits, underscores and hyphens")
        with get_session(self.db_path) as session:
            adopted = (
                session.query(RunORM).filter_by(public_id=run_id).first() if public_id else None
            )
            if adopted is not None and adopted.status != "queued":
                raise ValueError("run ID already exists; choose a new attempt ID")
        output = Path(config.output_dir).resolve() / run_id
        if output.exists() or output.is_symlink():
            raise ValueError("run artifact directory already exists; choose a new run ID")
        output.mkdir(parents=True)
        results: list[ScannerResult] = []
        findings: list[Finding] = []
        events: list[dict[str, Any]] = []
        model_calls: list[dict[str, Any]] = []
        model_stage = "model_hunt"
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
            adopted = (
                session.query(RunORM).filter_by(public_id=run_id).first() if public_id else None
            )
            if adopted is not None and adopted.status == "queued":
                # Lần chạy xếp hàng qua API: sử dụng hàng giữ chỗ thay vì
                # tạo hàng thứ hai, để việc thăm dò (live polling) tiếp tục hoạt động.
                row = adopted
                row.target_id = target.id
                row.status = "running"
                row.parent_id = parent_id
                row.attempt = parent.attempt + 1 if parent else row.attempt
                row.scan_spec_json = spec.model_dump_json()
            else:
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
        budget = BudgetManager(max_requests=config.max_model_requests)

        def cancelled() -> bool:
            if cancel_signal and cancel_signal():
                return True
            with get_session(self.db_path) as session:
                return bool(session.scalar(select(RunORM.cancel_requested).where(RunORM.id == pk)))

        def persist(stage: str, status: str, message: str = "") -> None:
            event = ProgressEvent(
                run_id,
                stage,
                status,
                datetime.now(UTC).isoformat(),
                sanitize(message),
                pk,
                len(events) + 1,
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
                            "model_calls": model_calls,
                            "ai_usage": _model_usage(model_calls, budget),
                            "assessments": review["assessments"],
                            "validation_decisions": review["decisions"],
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
                if status == "running" and stage_row.started_at is None:
                    stage_row.started_at = datetime.now(UTC)
                elif status != "running":
                    stage_row.completed_at = datetime.now(UTC)
                saved = {
                    f.finding_id: f
                    for f in session.scalars(
                        select(FindingORM)
                        .where(FindingORM.run_id == pk)
                        .order_by(FindingORM.id.desc())
                    )
                }
                changed = False
                for finding in findings:
                    payload = finding.model_dump_json()
                    existing = saved.pop(finding.finding_id, None)
                    if existing is not None and existing.finding_json == payload:
                        continue
                    summary, search_text = project_finding(finding.model_dump(mode="json"))
                    if existing is None:
                        existing = FindingORM(run_id=pk, finding_id=finding.finding_id)
                        session.add(existing)
                    existing.finding_json = payload
                    existing.summary_json = json.dumps(summary)
                    existing.search_text = search_text
                    changed = True
                for removed in saved.values():
                    session.delete(removed)
                    changed = True
                if changed:
                    row.findings_revision += 1
                # ---- Giai đoạn 3: hàng sự kiện trực tiếp chỉ thêm (không bao giờ làm gián đoạn lần quét)
                try:
                    from sqlalchemy import func as _func

                    max_seq = session.scalar(
                        select(_func.max(ScanEventORM.seq)).where(ScanEventORM.run_id == pk)
                    )
                    next_seq = int(max_seq) + 1 if max_seq is not None else 0
                    kind = _live_event_kind(stage, status)
                    session.add(
                        ScanEventORM(
                            run_id=pk,
                            seq=next_seq,
                            kind=kind,
                            stage=stage,
                            message=sanitize(message) or f"{stage} → {status}",
                            payload_json=json.dumps(sanitize({"status": status, "stage": stage})),
                            created_at=datetime.now(UTC),
                        )
                    )
                    # Việc hoàn thành rà soát AI cũng tạo ra một hàng đề xuất để
                    # AI AGENT PANEL có nguồn cấp dữ liệu CVSS/tuyên bố mà không cần phân tích cú pháp.
                    if stage == "targeted_deep_analysis" and status in {
                        "completed",
                        "partial",
                    }:
                        try:
                            proposal_count = len(review["assessments"])
                        except Exception:  # noqa: BLE001
                            proposal_count = 0
                        session.add(
                            ScanEventORM(
                                run_id=pk,
                                seq=next_seq + 1,
                                kind="ai_proposal",
                                stage=stage,
                                message=sanitize(message or f"{proposal_count} AI proposals ready"),
                                payload_json=json.dumps(
                                    sanitize({"status": status, "proposals": proposal_count}),
                                ),
                                created_at=datetime.now(UTC),
                            )
                        )
                except Exception:  # noqa: BLE001, S110
                    pass
            if on_event:
                on_event(event)

        model_event_lock = Lock()

        def model_event(event: dict[str, Any]) -> None:
            if event["kind"] == "call" and event["status"] == "running" and cancelled():
                raise ScanCancelled()
            safe = sanitize(event)
            with model_event_lock:
                if safe["kind"] == "call" and safe["status"] in {"completed", "failed"}:
                    model_calls.append(
                        {
                            "stage": model_stage,
                            "status": safe["status"],
                            "provider": safe.get("provider", ""),
                            "model": safe.get("model", ""),
                            "usage": safe.get("usage", {}),
                        }
                    )
                persist(
                    "model_" + safe["kind"], safe["status"], model_stage + " · " + safe["message"]
                )

        snapshot = tempfile.TemporaryDirectory(prefix="vulnscan-snapshot-")
        token = _cancel_check.set(cancelled)
        model_token = model_progress.set(model_event)
        was_cancelled = False
        routing: list[dict[str, Any]] = []
        review: dict[str, Any] = {
            "enabled": False,
            "stage": "targeted_deep_analysis",
            "status": "skipped",
            "detail": "scan ended before AI review",
            "targets": [],
            "assessments": [],
            "decisions": [],
            "usage": {},
            "model": "",
            "provider": "",
        }
        decisions: list[dict[str, Any]] = []
        final: dict[str, Any] = {
            "stage": "final_report",
            "status": "skipped",
            "detail": "scan ended before final report",
            "model": "",
            "provider": "",
            "markdown": "",
            "ai_written": False,
        }
        orchestration_mode = "deterministic"
        ai_invoked_tools: list[str] = []
        hunt_scanner_service: ScannerToolService | None = None
        try:
            persist("intake", "running")
            # Giá trị mặc định cho từng giai đoạn bên dưới: khối tóm tắt sau khối
            # try/except đọc các giá trị này ngay cả khi intake thất bại sớm, vì vậy chúng
            # phải tồn tại trước bất kỳ lệnh persist() nào có thể gây lỗi.
            hunt_candidates = []
            hunt_out = {}
            hunt_status = "skipped"
            hunt_detail = "scan ended before model hunt"
            ai_scanner_results: list[ScannerResult] = []
            verified = []
            comparison: dict[str, Any] = {
                "agreed": [],
                "model_only": [],
                "scanner_only": [],
                "counts": {"agreed": 0, "model_only": 0, "scanner_only": 0},
            }
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
            # SpotBugs cần bytecode: chuyển tiếp các lớp đã biên dịch khi bản
            # checkout đã có sẵn chúng (kết quả build của cùng mã nguồn).
            checkout_classes = Path(checkout).resolve() / "target" / "classes"
            if checkout_classes.is_dir():
                import shutil as _shutil

                _shutil.copytree(
                    checkout_classes, snapshot_root / "target" / "classes", dirs_exist_ok=True
                )
                manifest["classes_included"] = True
            checkout_deps = Path(checkout).resolve() / "target" / "dependency"
            if checkout_deps.is_dir():
                _shutil.copytree(
                    checkout_deps, snapshot_root / "target" / "dependency", dirs_exist_ok=True
                )
                manifest["dependencies_included"] = True
            intake_message = (
                f"Verified commit {manifest['commit']}"
                if manifest["commit"] != NO_REVISION
                else "Source snapshot hashed; no committed Git revision is available"
            )
            persist("intake", "completed", intake_message)
            hunt_detail = "deterministic mode — enable Hunt + a provider profile to run the model"
            if config.mode != "hunt":
                persist("model_hunt", "skipped", hunt_detail)
            if config.mode == "hunt":
                persist(
                    "model_hunt",
                    "running",
                    "AI orchestrator invoking security scanners and analyzing snapshot",
                )
                if not config.provider_profile:
                    from vulnscan.providers.profile_store import default_profile as _default_profile

                    _auto = _default_profile()
                    if _auto is not None:
                        config.provider_profile = _auto.id
                        if not config.provider_model:
                            config.provider_model = _auto.default_model or None
                        hunt_detail = f"auto provider {_auto.id}"
                        spec.metadata["configuration"] = config.model_dump()
                    else:
                        hunt_detail = "no provider key configured — falling back to static scanners"
                        persist("model_hunt", "skipped", hunt_detail)
                if config.provider_profile:
                    hunt_client: Any = None
                    try:
                        from vulnscan.ai.hunt import detect_families, hunt_all
                        from vulnscan.providers.client import ProviderClient
                        from vulnscan.providers.profile_store import load_profile
                        from vulnscan.scanners.tool_service import ScannerToolService

                        hunt_profile = load_profile(config.provider_profile)
                        hunt_client = ProviderClient(hunt_profile, budget)
                        hunt_scanner_service = ScannerToolService.from_registry(
                            snapshot_root,
                            self.registry,
                            run_id=run_id,
                            commit_sha=manifest["commit"],
                        )
                        hunt_families = detect_families(
                            list(manifest.get("inventory") or [])
                            or list((manifest.get("files") or {}).keys())
                        )
                        hunt_out = hunt_all(
                            snapshot_root=str(snapshot_root),
                            client=hunt_client,
                            model=config.provider_model,
                            families=hunt_families,
                            logic_pass=True,
                            broad_pass=True,
                            micro_passes=True,
                            max_rounds=16,
                            max_findings=200,
                            deep=True,
                            scanner_service=hunt_scanner_service,
                            tool_first=True,
                        )
                        hunt_candidates = [dict(c) for c in hunt_out.get("candidates", [])]
                        hunt_status = str(hunt_out.get("status", "partial"))
                        ai_scanner_results = list(hunt_out.get("scanner_results") or []) or (
                            hunt_scanner_service.executed_results()
                        )
                        ai_invoked_tools = list(hunt_out.get("tools_invoked") or []) or [
                            r.tool.value for r in ai_scanner_results
                        ]
                        tool_counts = dict(hunt_out.get("tool_call_counts") or {})
                        all_called_str = (
                            ", ".join(f"{k}:{v}" for k, v in tool_counts.items())
                            if tool_counts
                            else ",".join(ai_invoked_tools)
                        )
                        tools_note = f"; tools=[{all_called_str}]" if all_called_str else ""
                        hunt_detail = (
                            f"{len(hunt_candidates)} candidates "
                            f"in {hunt_out.get('rounds', 0)} rounds"
                            f"{tools_note} ({hunt_out.get('detail', '')})"
                        )[:400]
                    except Exception as exc:  # noqa: BLE001 — hunt stage never fails a run
                        hunt_status = "failed"
                        hunt_detail = f"{type(exc).__name__}"
                        hunt_candidates = []
                        ai_scanner_results = []
                        ai_invoked_tools = []
                    finally:
                        if hunt_client is not None and hasattr(hunt_client, "cleanup_v0_chats"):
                            hunt_client.cleanup_v0_chats()
                if hunt_status not in {"skipped"}:
                    persist(
                        "model_hunt",
                        hunt_status
                        if hunt_status in {"completed", "partial", "failed"}
                        else "partial",
                        hunt_detail,
                    )
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

            # Unified Phase 1 + Phase 2: when AI orchestrated scanners directly
            # during model_hunt, reuse those exact ScannerResult artifacts
            # without re-running deterministic scanners. Otherwise fall back to
            # running the baseline spec.tools scanners.
            if (
                config.mode == "hunt"
                and hunt_status in {"completed", "partial"}
                and any(r.is_complete for r in ai_scanner_results)
            ):
                orchestration_mode = "ai_orchestrated"
                for raw_result in ai_scanner_results:
                    if cancelled():
                        raise ScanCancelled()
                    tool_label = raw_result.tool.value
                    try:
                        finalized = _finalize_scanner_result(
                            raw_result,
                            snapshot_root=snapshot_root,
                            output=output,
                            spec=spec,
                            run_id=run_id,
                        )
                        results.append(finalized)
                        findings = pipeline.build_findings(results, run_id)
                        tool_detail = (
                            f"AI-orchestrated ({len(finalized.observations)} observations)"
                            if not finalized.errors
                            else f"AI-orchestrated ({len(finalized.observations)} observations; "
                            f"{'; '.join(finalized.errors)[:200]})"
                        )
                        persist(tool_label, finalized.status.value, tool_detail)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{tool_label}: {type(exc).__name__}: {exc}")
                        persist(tool_label, "failed", errors[-1])
                tool_outcomes = [r.status.value for r in results]
                completed_count = sum(1 for r in results if r.is_complete)
                if completed_count == 0 and any(s == "failed" for s in tool_outcomes):
                    for r in results:
                        for scan_error in r.errors:
                            errors.append(f"{r.tool.value}: {scan_error}")
                    persist("scanners", "failed", "; ".join(errors[-len(results) :]))
                elif any(s != "completed" for s in tool_outcomes):
                    persist(
                        "scanners",
                        "partial",
                        f"AI-orchestrated: {completed_count}/{len(results)} scanner(s) completed "
                        f"({', '.join(ai_invoked_tools)})",
                    )
                else:
                    persist(
                        "scanners",
                        "completed",
                        f"AI-orchestrated: {len(results)} scanner(s) invoked ({', '.join(ai_invoked_tools)})",
                    )
            else:
                orchestration_mode = (
                    "deterministic_fallback" if config.mode == "hunt" else "deterministic"
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
                            from vulnscan.scanners.platform import which

                            if which("docker") is None:
                                # No Docker on this host: run the adapter in-process
                                # instead of the isolated container. ODC without an
                                # NVD DB degrades to the OSV.dev fallback inside
                                # its own adapter; nothing fails the scan.
                                if cfg.tool.value == "spotbugs":
                                    from vulnscan.infra.full_scan import ensure_maven_build

                                    build_issue = ensure_maven_build(
                                        str(snapshot_root), min(600.0, remaining)
                                    )
                                    if build_issue is not None:
                                        from vulnscan.contracts import RunStatus

                                        now = datetime.now(UTC)
                                        persist(cfg.tool.value, "skipped", build_issue)
                                        results.append(
                                            ScannerResult(
                                                run_id=run_id,
                                                tool=cfg.tool,
                                                tool_version="unknown",
                                                adapter_version="0.2.0",
                                                status=RunStatus.SKIPPED,
                                                started_at=now,
                                                finished_at=now,
                                                errors=[build_issue],
                                            )
                                        )
                                        continue
                                result = adapter.run(execution_spec, workdir=str(snapshot_root))
                            else:
                                result = run_isolated_tool(cfg.tool, execution_spec, remaining)
                        else:
                            result = adapter.run(execution_spec, workdir=str(snapshot_root))
                        if result.tool != cfg.tool:
                            raise ValueError(
                                "scanner result identity does not match the scan specification"
                            )
                        result = _finalize_scanner_result(
                            result,
                            snapshot_root=snapshot_root,
                            output=output,
                            spec=spec,
                            run_id=run_id,
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
                # Aggregate rail node: web runs pre-create a "scanners" placeholder
                # row, so mark it from the per-tool outcomes instead of leaving it
                # pending forever while semgrep/gitleaks show completed.
                tool_outcomes = [r.status.value for r in results]
                if len(tool_outcomes) < len(spec.tools):
                    tool_outcomes.append("failed")
                if any(s == "failed" for s in tool_outcomes):
                    persist("scanners", "failed", "; ".join(errors[-len(spec.tools) :]))
                elif any(s != "completed" for s in tool_outcomes):
                    persist(
                        "scanners",
                        "partial",
                        f"{len(results)}/{len(spec.tools)} scanners completed",
                    )
                else:
                    persist(
                        "scanners",
                        "completed",
                        f"{len(results)}/{len(spec.tools)} scanners completed",
                    )
            if cancelled():
                raise ScanCancelled()
            # Phát hiện các sửa đổi trong quá trình quét thay vì khẳng định phiên bản gốc.
            after = checkout_manifest(checkout, config, expected_commit, excluded=runtime)
            if after["commit"] != manifest["commit"] or after["files"] != manifest["files"]:
                errors.append(
                    "checkout contents changed during scanning; retry from a stable checkout"
                )
            if config.laya and not config.ci and findings:
                persist(
                    "laya_batch_routing",
                    "running",
                    f"Starting Laya worker ({advisory.device}); {len(findings)} findings queued",
                )
            routing, stage = pipeline.run_routing(
                findings,
                on_progress=lambda message: persist("laya_batch_routing", "running", message),
            )
            if cancelled():
                raise ScanCancelled()
            persist(stage.name, stage.status, stage.detail)
            hunt_active = (
                config.mode == "hunt"
                and hunt_status not in {"skipped", "failed"}
                and bool(hunt_candidates)
            )
            if hunt_active:
                from vulnscan.ai.compare import compare_hunt_vs_scanners
                from vulnscan.ai.laya_verify import laya_verify_candidates

                persist("laya_verification", "running", "Verifying model candidates with Laya")
                verified = laya_verify_candidates(
                    hunt_candidates,
                    snapshot_root=str(snapshot_root),
                    laya_config=advisory,
                )
                n_verified = sum(1 for v in verified if v.get("laya_status") == "completed")
                n_skipped = sum(1 for v in verified if v.get("laya_status") == "skipped")
                persist(
                    "laya_verification",
                    "completed" if verified else "partial",
                    f"{len(verified)} verified: {n_verified} completed, {n_skipped} skipped",
                )
                comparison = compare_hunt_vs_scanners(verified, findings)
                counts = comparison.get("counts", {})
                persist(
                    "model_scanner_compare",
                    "completed",
                    f"agreed={counts.get('agreed', 0)} "
                    f"model-only={counts.get('model_only', 0)} "
                    f"scanner-only={counts.get('scanner_only', 0)}",
                )
            # Chế độ hunt: các finding của scanner được đồng thuận sẽ mang nguồn gốc BOTH,
            # phần còn lại của các finding từ scanner sẽ mang SCANNER, và các ứng viên
            # chỉ từ mô hình (model-only) đã được xác minh với bằng chứng mã nguồn rõ ràng sẽ
            # được nâng cấp thành các finding có nguồn gốc mô hình để cổng kiểm soát, nhánh AI,
            # và các báo cáo có thể thấy chúng. Chế độ non-hunt sẽ gắn nhãn mọi finding từ scanner
            # là SCANNER.
            from vulnscan.ai.promote import promote_model_only

            compared: dict[str, Any] = comparison
            promoted: list[Finding] = []
            raw_scanner_findings_count = len(findings)
            ai_filtered_out_count = 0
            if hunt_active:
                agreed_findings = [pair["finding"] for pair in compared.get("agreed", [])]
                agreed_ids = {id(finding) for finding in agreed_findings}
                for scanner_finding in findings:
                    scanner_finding.provenance = (
                        FindingProvenance.BOTH
                        if id(scanner_finding) in agreed_ids
                        else FindingProvenance.SCANNER
                    )
                promoted = promote_model_only(
                    compared.get("model_only", []),
                    snapshot_root=str(snapshot_root),
                    run_id=run_id,
                )
                ai_curated = [*agreed_findings, *promoted]
                if orchestration_mode == "ai_orchestrated" and ai_curated:
                    ai_filtered_out_count = len(compared.get("scanner_only", []))
                    findings = ai_curated
                else:
                    findings = [*findings, *promoted]
            else:
                agreed_findings = []
                for scanner_finding in findings:
                    scanner_finding.provenance = FindingProvenance.SCANNER
            review_findings: list[Finding] = (
                [*agreed_findings, *promoted] if hunt_active else findings
            )
            from vulnscan.ai.review import run_ai_review
            from vulnscan.reporting.final_report import run_final_report

            review_profile = (
                config.provider_profile if (config.ai_review or config.mode == "hunt") else None
            )
            model_stage = "targeted_deep_analysis"
            if review_profile and review_findings:
                persist("targeted_deep_analysis", "running", "Reviewing selected findings")
            review_kwargs: dict[str, Any] = {
                "snapshot_root": str(snapshot_root),
                "coverage_summary": {
                    r.tool.value: [c.model_dump(mode="json") for c in r.coverage_records]
                    for r in results
                },
                "profile_id": review_profile,
                "model": config.provider_model,
                "max_findings": config.max_ai_findings,
                "budget": budget,
            }
            if hunt_scanner_service is not None:
                review_kwargs["scanner_service"] = hunt_scanner_service
            review = run_ai_review(review_findings, routing, **review_kwargs)
            persist("targeted_deep_analysis", review["status"], review["detail"])
            decisions = review["decisions"]
            if decisions:
                confirmed = sum(1 for d in decisions if d["new_status"] == "confirmed")
                rejected = sum(1 for d in decisions if d["new_status"] == "rejected")
                persist(
                    "independent_validation",
                    "completed" if confirmed or rejected else "partial",
                    f"{len(decisions)} validated: {confirmed} confirmed, {rejected} rejected",
                )
            else:
                persist(
                    "independent_validation",
                    "skipped",
                    review["detail"] or "no assessment evidence supplied",
                )
            model_stage = "final_report"
            report_profile = (
                config.provider_profile if (config.ai_report or config.mode == "hunt") else None
            )
            if report_profile:
                persist("final_report", "running", "Writing the final narrative")
            final = run_final_report(
                findings,
                decisions,
                {
                    "target": spec.target_repository_url,
                    "commit": manifest["commit"],
                    "gate": "pending",
                    "status": "pending",
                },
                profile_id=report_profile,
                model=config.provider_model,
                budget=budget,
                comparison=comparison if hunt_active else None,
            )
            persist("final_report", final["status"], final["detail"] or "narrative ready")
        except (ScanCancelled, KeyboardInterrupt):
            was_cancelled = True
            persist("execution", "cancelled", "Scan cancelled; partial evidence retained")
        except Exception as exc:  # noqa: BLE001 ? application boundary preserves partial evidence
            errors.append(f"{type(exc).__name__}: {exc}")
            persist("execution", "failed", errors[-1])
        finally:
            _cancel_check.reset(token)
            model_progress.reset(model_token)
            snapshot.cleanup()
        if orchestration_mode == "ai_orchestrated":
            required_tools = [r.tool.value for r in results if r.is_complete] or [
                r.tool.value for r in results
            ]
            coverage_errors = [
                e for e in reconcile(results, manifest) if "missing coverage" not in e
            ]
        else:
            required_tools = [t.tool.value for t in spec.tools]
            coverage_errors = reconcile(results, manifest)

        policy = gate(
            findings,
            results,
            required_tools,
            config.fail_on,
            coverage_errors,
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
                "orchestration": {
                    "mode": orchestration_mode,
                    "ai_invoked_tools": ai_invoked_tools,
                },
                "ai_filtering": {
                    "raw_scanner_findings": locals().get(
                        "raw_scanner_findings_count", len(findings)
                    ),
                    "ai_confirmed_from_scanners": len(locals().get("agreed_findings", [])),
                    "ai_added_logic_findings": len(locals().get("promoted", [])),
                    "ai_filtered_out": locals().get("ai_filtered_out_count", 0),
                    "final_findings": len(findings),
                },
                "model_hunt_tool_calls": dict(hunt_out.get("tool_call_counts") or {}),
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
                "assessments": review["assessments"],
                "validation_decisions": decisions,
                "model_calls": model_calls,
                "ai_usage": {**review["usage"], **_model_usage(model_calls, budget)},
                "final_report": {
                    "status": final["status"],
                    "ai_written": final["ai_written"],
                    "model": final["model"],
                    "provider": final["provider"],
                    "detail": final["detail"],
                },
                **policy,
                "reports": {},
            }
        )
        if config.mode == "hunt" and hunt_status != "skipped":
            summary["model_candidates"] = sanitize(hunt_candidates)
            summary["laya_verification"] = sanitize(verified)
            summary["comparison"] = sanitize(
                {
                    "agreed": [
                        {
                            "candidate": pair.get("candidate"),
                            "finding": pair.get("finding").model_dump(mode="json")
                            if hasattr(pair.get("finding"), "model_dump")
                            else pair.get("finding"),
                        }
                        for pair in comparison.get("agreed", [])
                    ],
                    "model_only": list(comparison.get("model_only", [])),
                    "scanner_only": [
                        f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                        for f in comparison.get("scanner_only", [])
                    ],
                    "counts": dict(comparison.get("counts", {})),
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
        try:
            (output / "final-report.md").write_text(final["markdown"], encoding="utf-8")
            summary["reports"]["final-report"] = str(output / "final-report.md")
            summary["final_report"]["ai_written"] = final["ai_written"]
        except OSError as exc:
            summary["errors"].append(sanitize(f"final-report export failed: {exc}"))
            with get_session(self.db_path) as session:
                saved = session.get(RunORM, pk)
                assert saved is not None
                saved.result_json = json.dumps(summary)
        if config.mode == "hunt" and hunt_status != "skipped":
            try:
                (output / "hunt.json").write_text(
                    json.dumps(
                        {
                            "candidates": summary.get("model_candidates", []),
                            "passes": sanitize(hunt_out.get("passes", [])),
                            "verification": summary.get("laya_verification", []),
                            "comparison": summary.get("comparison", {}),
                            "trace": sanitize(hunt_out.get("trace", [])),
                            "detail": sanitize(hunt_out.get("detail", "")),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                summary["reports"]["hunt"] = str(output / "hunt.json")
            except OSError as exc:
                summary["errors"].append(sanitize(f"hunt export failed: {exc}"))
        summary["duration_seconds"] = round(time.monotonic() - started, 3)
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
        from vulnscan.notifications.service import notify_finished

        summary["notifications"] = notify_finished(self.db_path, pk)
        return summary
