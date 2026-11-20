"""Giao diện adapter và registry cho scanner.

Một adapter là module *duy nhất* hiểu định dạng đầu ra gốc của từng nhà cung cấp.
Mọi thành phần phía sau chỉ tiêu thụ các envelope :class:`ScannerResult`.

Quy tắc thiết kế
----------------
* Thiếu binary là một điều kiện được ghi nhận, không bao giờ là ngoại lệ.
  ``AdapterCapability`` báo cáo sự hiện diện; các adapter trả về kết quả có
  ``status`` là ``failed`` kèm lý do trong ``errors`` (hoặc ``skipped`` khi
  scan spec vô hiệu hóa công cụ).
* Phân tích cú pháp thuần túy: ``parse`` nhận văn bản đã được lấy sẵn để các test có thể
  chạy fixture thông qua nó mà không cần tạo subprocess.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from vulnscan.contracts import (
    RunStatus,
    ScannerResult,
    ScanSpecification,
    ToolName,
)

from .platform import which
from .process import CommandResult, run_command

ADAPTER_VERSION = "0.2.0"
"""Bumped whenever an adapter's normalization logic changes output meaning."""


@dataclass(frozen=True)
class AdapterCapability:
    """Những gì một adapter khai báo về công cụ và môi trường của nó."""

    tool: ToolName
    binary: str | None = None
    version: str | None = None
    available: bool = False
    reason: str | None = None

    def unavailable_message(self) -> str:
        """Lý do ổn định, dễ đọc cho con người về việc không khả dụng."""
        if self.available:
            return ""
        if self.reason:
            return f"{self.binary or self.tool.value}: {self.reason}"
        return f"{self.binary or self.tool.value}: binary not found on PATH"


class ScannerAdapter(abc.ABC):
    """Scanner adapter dành riêng cho từng nhà cung cấp."""

    #: Công cụ mà adapter này liên kết tới.
    tool: ToolName
    #: Tên file thực thi được tìm kiếm trên PATH.
    binary_name: str
    #: Phiên bản hiện thực của adapter (xem :data:`ADAPTER_VERSION`).
    adapter_version: str = ADAPTER_VERSION
    #: Thời gian chờ mặc định cho mỗi lần gọi tính bằng giây.
    default_timeout: float = 600.0

    # ------------------------------------------------------------------ #
    # API công khai
    # ------------------------------------------------------------------ #

    @abc.abstractmethod
    def capabilities(self) -> AdapterCapability:
        """Thăm dò môi trường để tìm binary của công cụ và phiên bản của nó."""

    @abc.abstractmethod
    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        """Thực thi công cụ cho *spec* và trả về kết quả đã chuẩn hóa.

        Không bao giờ ném ngoại lệ do các vấn đề môi trường (thiếu binary, timeout,
        exit code khác 0): những thông tin đó được ghi nhận trong envelope trả về.
        """

    # ------------------------------------------------------------------ #
    # Các hàm trợ giúp dùng chung
    # ------------------------------------------------------------------ #

    def _tool_config(self, spec: ScanSpecification) -> Any:
        """Trả về :class:`ToolConfig` của công cụ này, hoặc ``None`` nếu vắng mặt."""
        for cfg in spec.tools:
            if cfg.tool == self.tool:
                return cfg
        return None

    def _skipped_result(
        self, spec: ScanSpecification, started_at: Any, reason: str
    ) -> ScannerResult:
        """Xây dựng một envelope ``skipped`` cho một công cụ bị tắt/vắng mặt."""
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version="unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.SKIPPED if "disabled" in reason else RunStatus.FAILED,
            started_at=started_at,
            finished_at=started_at,
            errors=[reason],
        )

    def _invoke(
        self,
        argv: Sequence[str],
        *,
        cwd: str,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Chạy binary của công cụ, chuyển đổi việc thiếu binary thành một kết quả."""
        if which(str(argv[0])) is None:
            return CommandResult(
                returncode=127,
                stderr=f"binary not found: {argv[0]}",
                command=tuple(str(a) for a in argv),
            )
        return run_command(
            argv,
            cwd=cwd,
            timeout=timeout if timeout is not None else self.default_timeout,
            env=env,
        )

    def _fatal(
        self,
        spec: ScanSpecification,
        started_at: Any,
        finished_at: Any,
        result: CommandResult,
        *,
        note: str,
    ) -> ScannerResult:
        """Envelope cho một lần gọi công cụ không thể tạo ra đầu ra."""
        detail = note
        if result.timed_out:
            detail = f"{note}; timed out after {result.duration_ms} ms"
        elif result.returncode not in (0, 1):
            detail = (
                f"{note}; exit code {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[:400]}"
            )
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version="unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.FAILED,
            started_at=started_at,
            finished_at=finished_at,
            errors=[detail],
            warnings=[] if result.succeeded or result.timed_out else [note],
            duration_ms=result.duration_ms,
        )


@dataclass
class AdapterRegistry:
    """Tra cứu tool -> adapter, được tạo một lần cho mỗi tiến trình."""

    adapters: dict[str, ScannerAdapter] = field(default_factory=dict)

    @classmethod
    def default(cls) -> AdapterRegistry:
        """Xây dựng registry với mọi adapter được đóng gói kèm theo package này."""
        from .codeql_adapter import CodeQLAdapter
        from .dependency_check_adapter import DependencyCheckAdapter
        from .gitleaks_adapter import GitleaksAdapter
        from .native_hunt_adapter import NativeHuntAdapter
        from .semgrep_adapter import SemgrepAdapter
        from .spotbugs_adapter import SpotBugsAdapter
        from .trivy_adapter import TrivyAdapter

        registry = cls()
        for adapter in (
            SemgrepAdapter(),
            NativeHuntAdapter(),
            SpotBugsAdapter(),
            DependencyCheckAdapter(),
            GitleaksAdapter(),
            CodeQLAdapter(),
            TrivyAdapter(),
        ):
            registry.register(adapter)
        return registry

    def register(self, adapter: ScannerAdapter) -> None:
        """Thêm *adapter* dưới tên công cụ tương ứng của nó."""
        self.adapters[adapter.tool.value] = adapter

    def get(self, tool: ToolName | str) -> ScannerAdapter | None:
        """Trả về adapter cho *tool*, hoặc ``None`` khi chưa được đăng ký."""
        return self.adapters.get(tool.value if isinstance(tool, ToolName) else tool)

    def __contains__(self, tool: ToolName | str) -> bool:
        return self.get(tool) is not None

    def __len__(self) -> int:
        return len(self.adapters)


__all__ = [
    "ADAPTER_VERSION",
    "AdapterCapability",
    "AdapterRegistry",
    "ScannerAdapter",
]
