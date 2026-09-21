"""T02 gate: missing binaries are a documented condition, never a crash."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


class TestAdapterUnavailability:
    """Every adapter must report absence, not raise."""

    @pytest.mark.parametrize(
        "adapter_cls",
        [
            "vulnscan.scanners.semgrep_adapter.SemgrepAdapter",
            "vulnscan.scanners.spotbugs_adapter.SpotBugsAdapter",
            "vulnscan.scanners.gitleaks_adapter.GitleaksAdapter",
            "vulnscan.scanners.dependency_check_adapter.DependencyCheckAdapter",
        ],
    )
    def test_missing_binary_is_documented(self, adapter_cls: str) -> None:
        import importlib

        module_name, cls_name = adapter_cls.rsplit(".", 1)
        mod = importlib.import_module(module_name)
        adapter = getattr(mod, cls_name)()

        cap = adapter.capabilities()
        # Either available (bin present) or unavailable with a real reason.
        if cap.available:
            pytest.skip(f"{cls_name} binary present on this host")
        assert cap.available is False
        assert cap.reason is not None and cap.reason != ""

    def test_unavailable_message_is_stable(self) -> None:
        from vulnscan.scanners.base import AdapterCapability

        cap = AdapterCapability(
            tool="semgrep",
            binary="semgrep",
            version=None,
            available=False,
            reason="semgrep not found on PATH",
        )
        msg = cap.unavailable_message()
        assert "semgrep" in msg
        assert "semgrep not found on PATH" in msg


class TestFakeAdapter:
    """The T01 fake adapter returns a canned result (used by platform tests)."""

    def test_fake_result_shape(self) -> None:
        from vulnscan.contracts import ScannerResult
        from vulnscan.scanners.fake import FakeScannerAdapter

        adapter = FakeScannerAdapter()
        assert adapter.capabilities().available is True

        from vulnscan.contracts import ScanSpecification

        spec = ScanSpecification(
            run_id="r-fake",
            target_repository_url="https://github.com/Moseyuh333/JVA-bookstore",
            target_commit_sha="dd48d12aabbcd1234abcd1234abcd1234abcd12",
            repository_checkout_path="/tmp/x",
            tools=[],
        )
        result = adapter.run(spec, workdir="/tmp")
        assert isinstance(result, ScannerResult)
        assert result.status.value in {"completed", "completed_with_errors", "failed"}
