"""TDD: test sources are not production attack surface."""

from __future__ import annotations

import subprocess
from pathlib import Path

from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import checkout_manifest


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True, cwd=cwd)


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "src" / "main" / "java" / "app").mkdir(parents=True)
    (tmp_path / "src" / "test" / "java" / "app").mkdir(parents=True)
    (tmp_path / "src" / "main" / "java" / "app" / "Order.java").write_text(
        "class Order { String q; }", encoding="utf-8"
    )
    (tmp_path / "src" / "test" / "java" / "app" / "OrderTest.java").write_text(
        "class OrderTest { String q; }", encoding="utf-8"
    )
    _git(tmp_path, "init", "-q", ".")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "T")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def test_inventory_excludes_test_sources(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    manifest = checkout_manifest(str(repo), ScanConfig())
    assert "src/main/java/app/Order.java" in manifest["inventory"]
    assert "src/test/java/app/OrderTest.java" not in manifest["inventory"]


def test_excluded_test_sources_are_still_snapshot_files(tmp_path: Path) -> None:
    """Test files stay in the immutable snapshot — only the scan inventory narrows."""
    repo = _make_repo(tmp_path)
    manifest = checkout_manifest(str(repo), ScanConfig())
    assert "src/test/java/app/OrderTest.java" in manifest["files"]
