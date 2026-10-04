"""Owned application service over JSON-lines for the Go interface (IR-16).

EOF cancels active work and waits for evidence persistence. This is a child
service, never a detached daemon. Stdout contains protocol records only.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from contextlib import redirect_stdout
from dataclasses import asdict
from typing import Any

from filelock import FileLock, Timeout

from vulnscan.contracts import ExportFormat
from vulnscan.core.config import ScanConfig, resolve_config
from vulnscan.core.scan_service import ScanService, checkout_manifest
from vulnscan.core.security import sanitize
from vulnscan.core.source import resolve_source
from vulnscan.core.stdio_worker import MAX_MESSAGE_BYTES, PROTOCOL_VERSION
from vulnscan.scanners.process import ScanCancelled, _cancel_check
from vulnscan.version import APP_VERSION


class ServiceRPC:
    def __init__(self, service: ScanService) -> None:
        self.service = service
        self.output = sys.stdout.buffer
        self.output_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.running: dict[str, threading.Event] = {}
        self.threads: list[threading.Thread] = []
        self.slots = threading.BoundedSemaphore(4)
        self.native_lock = FileLock(service.db_path + ".lock", timeout=0, thread_local=False)

    def send(self, response: dict[str, Any]) -> None:
        line = json.dumps(sanitize(response), ensure_ascii=False).encode("utf-8") + b"\n"
        if len(line) > MAX_MESSAGE_BYTES:
            line = (
                json.dumps(
                    {
                        "version": PROTOCOL_VERSION,
                        "id": response.get("id"),
                        "ok": False,
                        "error": {
                            "code": "message_limit",
                            "message": "Response exceeds the protocol limit; use paginated reads or report artifacts.",
                        },
                    }
                ).encode()
                + b"\n"
            )
        with self.output_lock:
            self.output.write(line)
            self.output.flush()

    def dispatch(
        self, method: str, params: dict[str, Any], identifier: str, cancel: threading.Event
    ) -> Any:
        pk = str(params.get("run_id", ""))
        if method == "render_page":
            from pathlib import Path

            from jinja2 import Environment, FileSystemLoader, select_autoescape

            from vulnscan.contracts import Finding
            from vulnscan.web import app as web_app

            name = str(params["template"])
            if name not in {"targets.html", "runs.html", "findings.html", "evidence.html"}:
                raise ValueError("unknown dashboard template")
            context = params["context"]
            if "finding" in context:
                context["finding"] = Finding.model_validate(context["finding"])
            if "findings" in context:
                context["findings"] = [Finding.model_validate(f) for f in context["findings"]]
            environment = Environment(
                loader=FileSystemLoader(str(Path(web_app.__file__).with_name("templates"))),
                autoescape=select_autoescape(["html"]),
            )
            return environment.get_template(name).render(**context)
        if method == "lease_acquire":
            with self.state_lock:
                if self.native_lock.is_locked:
                    raise ValueError("another scan is active in this database")
                try:
                    self.native_lock.acquire()
                except Timeout as exc:
                    raise ValueError("another scan is active in this database") from exc
            return {"acquired": True}
        if method == "lease_release":
            self.native_lock.release()
            return {"released": True}
        if method == "specification":
            config = ScanConfig.model_validate(params["configuration"])
            spec = config.specification(
                str(params["checkout"]),
                str(params.get("commit") or "unresolved"),
                str(params.get("repo", "local")),
            )
            spec.run_id = str(params["public_id"])
            return spec.model_dump(mode="json")
        if method == "sanitize":
            return sanitize(params["value"])
        if method == "validate_findings":
            from vulnscan.contracts import Finding

            return [Finding.model_validate(f).model_dump(mode="json") for f in params["findings"]]
        if method == "scan_tool":
            from vulnscan.contracts import ScanSpecification, ToolName
            from vulnscan.infra.full_scan import run_isolated_tool

            spec = ScanSpecification.model_validate(params["specification"])
            tool = ToolName(params["tool"])
            if params["profile"] == "full" and tool in {
                ToolName.SPOTBUGS,
                ToolName.OWASP_DEPENDENCY_CHECK,
            }:
                scanner_result = run_isolated_tool(tool, spec, float(params["timeout"]))
            else:
                adapter = self.service.registry.get(tool)
                if adapter is None:
                    raise ValueError("adapter unavailable")
                adapter.default_timeout = float(params["timeout"])
                scanner_result = adapter.run(spec, workdir=spec.repository_checkout_path)
            return sanitize(scanner_result.model_dump(mode="json"))
        if method == "routing":
            from dataclasses import replace

            from vulnscan.contracts import Finding, ScanSpecification
            from vulnscan.decisions.config import load_config
            from vulnscan.pipeline.runner import ScanPipeline

            config = ScanConfig.model_validate(params["configuration"])
            advisory = replace(
                load_config(config.laya_config_path), enabled=config.laya and not config.ci
            )
            pipeline = ScanPipeline(
                ScanSpecification.model_validate(params["specification"]), laya_config=advisory
            )
            routing, stage = pipeline.run_routing(
                [Finding.model_validate(f) for f in params["findings"]]
            )
            return {
                "routing": routing,
                "stage": {"name": stage.name, "status": stage.status, "detail": stage.detail},
                "advisory_configuration": asdict(advisory),
            }
        if method == "reports":
            from vulnscan.contracts import Finding
            from vulnscan.reporting.reporter import ReportGenerator

            summary = params["summary"]
            generator = ReportGenerator(
                str(summary["run_id"]),
                [Finding.model_validate(f) for f in params["findings"]],
                coverage_summary=summary.get("coverage", {}),
                routing_payloads=summary.get("routing", []),
                run_metadata={
                    "commit": summary.get("commit"),
                    "configuration": summary["configuration"],
                    "status": summary["status"],
                    "gate": summary["gate"],
                    "errors": summary["errors"],
                },
            )
            reports: dict[str, str] = {}
            export_errors: list[str] = []
            for fmt in ExportFormat:
                try:
                    reports[fmt.value] = str(
                        generator.export(fmt, str(params["output"])).artifact_ref.path
                    )
                except (OSError, ValueError) as exc:
                    export_errors.append(f"{fmt.value} export failed: {exc}")
            return {"reports": reports, "errors": export_errors}
        if method == "hello":
            self.service.recover()
            return {
                "version": APP_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "db_path": self.service.db_path,
                "execution_owner": "python",
            }
        if method == "history":
            return self.service.history()
        if method == "summary":
            return self.service.summary(pk)
        if method == "findings":
            return self.service.finding_page(
                pk,
                params.get("query", ""),
                int(params.get("offset", 0)),
                int(params.get("limit", 200)),
            )
        if method == "finding":
            return self.service.finding(pk, str(params["finding_id"]))
        if method == "events":
            return self.service.progress_since(pk, int(params.get("cursor", 0)))
        if method == "detail":
            return self.service.detail(pk)
        if method == "config":
            return resolve_config(
                params.get("profile"), params.get("config_path"), **params.get("flags", {})
            ).model_dump()
        if method == "review":
            config = ScanConfig.model_validate(params["configuration"])
            source = resolve_source(
                str(params["checkout"]),
                str(params.get("workdir", "harness")),
                str(params.get("commit", "")),
            )
            manifest = checkout_manifest(
                source.checkout,
                config,
                expected=source.commit or str(params.get("commit", "")),
                excluded=self.service.runtime_paths(config),
            )
            manifest = dict(manifest)
            manifest["resolved_checkout"] = source.checkout
            manifest["repo_url"] = source.repo_url
            manifest["commit_sha"] = source.commit
            return {"manifest": manifest, "configuration": config.model_dump()}
        if method == "capabilities":
            return [
                asdict(adapter.capabilities())
                for adapter in self.service.registry.adapters.values()
            ]
        if method == "cancel":
            self.service.cancel(pk)
            return {"cancel_requested": True}
        if method == "export":
            return {
                "path": self.service.export(
                    pk,
                    ExportFormat(params.get("format", "json")),
                    str(params.get("output", "artifacts")),
                )
            }
        if method in {"run", "retry"}:

            def progress(event: Any) -> None:
                self.send(
                    {
                        "version": PROTOCOL_VERSION,
                        "id": identifier,
                        "kind": "event",
                        "sequence": event.sequence,
                        "event": asdict(event),
                    }
                )

            if method == "retry":
                result = self.service.retry(pk, progress, cancel_signal=cancel.is_set)
            else:
                result = self.service.run(
                    str(params["checkout"]),
                    ScanConfig.model_validate(params["configuration"]),
                    repo=str(params.get("repo", "local")),
                    expected_commit=str(params.get("commit", "")),
                    public_id=params.get("public_id"),
                    on_event=progress,
                    cancel_signal=cancel.is_set,
                )
            if len(json.dumps(result).encode()) > MAX_MESSAGE_BYTES // 2:
                return {
                    "result_ref": result["summary_path"],
                    "run_id": result["run_id"],
                    "status": result["status"],
                    "exit_code": result["exit_code"],
                }
            return result
        raise ValueError("unsupported service method")

    def serve(self) -> None:
        # Redirect vendor prints process-wide; protocol sends use the original buffer.
        with redirect_stdout(sys.stderr):
            try:
                while True:
                    line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
                    if not line:
                        break
                    identifier: str | None = None
                    try:
                        if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                            raise ValueError("request exceeds message limit")
                        request = json.loads(line)
                        identifier = request["id"]
                        if (
                            not isinstance(identifier, str)
                            or request["version"] != PROTOCOL_VERSION
                        ):
                            raise ValueError("invalid protocol identity")
                        method = str(request["method"])
                        params = request.get("params", {})
                        if method == "cancel_request":
                            with self.state_lock:
                                signal = self.running.get(str(params["request_id"]))
                                if signal:
                                    signal.set()
                            self.send(
                                {
                                    "version": PROTOCOL_VERSION,
                                    "id": identifier,
                                    "ok": True,
                                    "result": {"cancel_requested": signal is not None},
                                }
                            )
                            continue
                        if not self.slots.acquire(blocking=False):
                            raise ValueError("service is busy; retry the request")
                        with self.state_lock:
                            if identifier in self.running:
                                self.slots.release()
                                raise ValueError("duplicate in-flight request ID")
                            cancel = threading.Event()
                            self.running[identifier] = cancel
                        thread = threading.Thread(
                            target=self.handle, args=(method, params, identifier, cancel)
                        )
                        self.threads = [t for t in self.threads if t.is_alive()]
                        self.threads.append(thread)
                        thread.start()
                    except (ValueError, TypeError, KeyError) as exc:
                        self.send(
                            {
                                "version": PROTOCOL_VERSION,
                                "id": identifier,
                                "ok": False,
                                "error": {"code": "invalid_request", "message": str(exc)},
                            }
                        )
            finally:
                with self.state_lock:
                    for signal in self.running.values():
                        signal.set()
                for thread in self.threads:
                    thread.join()

    def handle(
        self, method: str, params: dict[str, Any], identifier: str, cancel: threading.Event
    ) -> None:
        token = _cancel_check.set(cancel.is_set)
        try:
            result = self.dispatch(method, params, identifier, cancel)
            self.send({"version": PROTOCOL_VERSION, "id": identifier, "ok": True, "result": result})
        except (ScanCancelled, Exception) as exc:  # noqa: BLE001 - application protocol boundary
            self.send(
                {
                    "version": PROTOCOL_VERSION,
                    "id": identifier,
                    "ok": False,
                    "error": {"code": "execution_error", "message": str(exc)},
                }
            )
        finally:
            _cancel_check.reset(token)
            with self.state_lock:
                self.running.pop(identifier, None)
            self.slots.release()


def main() -> None:
    parser = argparse.ArgumentParser(description="Owned Go/Python application bridge")
    parser.add_argument("--db-path", default="vulnscan.db")
    args = parser.parse_args()
    with redirect_stdout(sys.stderr):
        service = ScanService(args.db_path)
    ServiceRPC(service).serve()


if __name__ == "__main__":
    main()
