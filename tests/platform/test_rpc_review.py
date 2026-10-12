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
    config = settings(tmp_path)
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
