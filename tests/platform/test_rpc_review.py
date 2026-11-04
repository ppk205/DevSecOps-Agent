"""FR-71: RPC review resolves local sources with optional commit pins."""

import subprocess
import threading

import pytest

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.core.rpc import ServiceRPC

__all__ = ["checkout", "service"]


@pytest.mark.parametrize("pinned", [False, True])
def test_fr71_review_returns_effective_configuration_and_source_manifest(
    service, checkout, tmp_path, pinned
):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    config = settings(tmp_path, mode="deterministic", laya=False)
    params = {
        "checkout": str(checkout),
        "workdir": str(tmp_path / "checkouts"),
        "configuration": config.model_dump(),
    }
    if pinned:
        params["commit"] = commit

    result = ServiceRPC(service).dispatch("review", params, "review", threading.Event())

    assert result["manifest"]["resolved_checkout"] == str(checkout.resolve())
    assert result["manifest"]["commit_sha"] == commit
    assert result["configuration"] == config.model_dump()
    assert result["manifest"]["source_kind"] == "local"


def test_fr01_review_accepts_unversioned_local_folder(service, tmp_path):
    folder = tmp_path / "plain folder"
    folder.mkdir()
    (folder / "Example.java").write_text("class Example {}", encoding="utf-8")
    result = ServiceRPC(service).dispatch(
        "review",
        {
            "checkout": str(folder),
            "configuration": settings(tmp_path, mode="deterministic", laya=False).model_dump(),
        },
        "review",
        threading.Event(),
    )
    manifest = result["manifest"]
    assert manifest["source_kind"] == "local"
    assert manifest["commit"] == "no-revision"
    assert manifest["dirty"] is None
    assert manifest["resolved_checkout"] == str(folder)
