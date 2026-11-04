"""FR-70/71, DR-09, IR-15: real Go/Python compatibility boundary."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.contracts import Finding
from vulnscan.core.scan_service import ScanService
from vulnscan.normalization.grouping import group_findings

__all__ = ["checkout", "service"]
ROOT = Path(__file__).parents[2]
BINARY = ROOT / "bin" / ("devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go")
pytestmark = pytest.mark.skipif(
    not BINARY.is_file(), reason="build the Go binary to run native parity tests"
)


def native(*args, slow=False):
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
        "DEVSECOPS_NATIVE": "python",
    }
    if slow:
        env["DEVSECOPS_FIXTURE_SLOW"] = "1"
    return subprocess.run(
        [str(BINARY), *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("directory", ["root", "bin", "unrelated"])
@pytest.mark.parametrize("command", ["history", "help"])
def test_qr20_native_launch_finds_application_python_from_any_directory(
    tmp_path, directory, command
):
    """Direct native launches use the application environment without shell activation."""
    env = dict(os.environ)
    for key in (
        "DEVSECOPS_PYTHON",
        "DEVSECOPS_RPC_MODULE",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "PYTHONPATH",
    ):
        env.pop(key, None)
    env["DEVSECOPS_NATIVE"] = "python"
    cwd = {"root": ROOT, "bin": BINARY.parent, "unrelated": tmp_path}[directory]
    args = (
        ["scan-list", "--db-path", str(tmp_path / "history.db"), "--json"]
        if command == "history"
        else ["--help"]
    )
    result = subprocess.run(
        [str(BINARY), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    if command == "history":
        assert json.loads(result.stdout) == []
    else:
        assert "scan-run" in result.stdout


def test_qr20_native_rpc_uses_the_selected_python_source_path(tmp_path):
    """A foreign PYTHONPATH must not shadow the selected application's package."""
    foreign = tmp_path / "foreign packages"
    package = foreign / "vulnscan"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        'raise RuntimeError("foreign PYTHONPATH shadowed application")\n', encoding="utf-8"
    )
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_NATIVE": "python",
        "PYTHONPATH": str(foreign),
    }
    env.pop("DEVSECOPS_RPC_MODULE", None)
    result = subprocess.run(
        [str(BINARY), "scan-list", "--db-path", str(tmp_path / "history.db"), "--json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout) == []


@pytest.mark.parametrize("without_git", [False, True])
def test_fr01_native_scan_accepts_plain_local_folders(tmp_path, without_git):
    folder = tmp_path / "source folder"
    folder.mkdir()
    (folder / "Example.java").write_text("class Example {}", encoding="utf-8")
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
        "DEVSECOPS_NATIVE": "python",
        "DEVSECOPS_FIXTURE_NATIVE_HUNT": "1",
    }
    if without_git:
        empty = tmp_path / "empty path"
        empty.mkdir()
        env["PATH"] = str(empty)
    result = subprocess.run(
        [
            str(BINARY),
            "scan-run",
            "--checkout",
            str(folder),
            "--db-path",
            str(tmp_path / "scan.db"),
            "--out",
            str(tmp_path / "reports"),
            "--json",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    summary = json.loads(result.stdout)
    assert summary["manifest"]["commit"] == "no-revision"
    assert summary["manifest"]["dirty"] is None
    assert summary["manifest"]["revision_reason"]
    assert summary["manifest"]["inventory"] == ["Example.java"]


def test_fr01_native_remote_input_scans_its_resolved_cached_checkout(checkout, tmp_path):
    """A local cached clone exercises remote resolution without any network call."""
    cached = tmp_path / "harness" / "repo"
    cached.parent.mkdir()
    subprocess.run(
        ["git", "clone", "--local", str(checkout), str(cached)], capture_output=True, check=True
    )
    url = "https://example.invalid/owner/repo.git"
    subprocess.run(
        ["git", "-C", str(cached), "remote", "set-url", "origin", url],
        capture_output=True,
        check=True,
    )
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
        "DEVSECOPS_NATIVE": "python",
        "DEVSECOPS_FIXTURE_NATIVE_HUNT": "1",
    }
    result = subprocess.run(
        [
            str(BINARY),
            "scan-run",
            "--checkout",
            url,
            "--db-path",
            str(tmp_path / "remote.db"),
            "--out",
            str(tmp_path / "reports"),
            "--workdir",
            str(cached.parent),
            "--json",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    summary = json.loads(result.stdout)
    assert summary["manifest"]["source_kind"] == "remote"
    assert summary["manifest"]["resolved_checkout"] == str(cached.resolve())
    detail = ScanService(str(tmp_path / "remote.db")).detail(summary["id"])
    assert detail["spec"]["repository_checkout_path"] == str(cached.resolve())
    assert detail["spec"]["target_repository_url"] == url


def identity(finding):
    return (
        finding["finding_id"],
        finding["fingerprint"],
        finding["severity"],
        finding["cwe_category"],
        finding["status"],
        finding["evidence_strength"],
        finding["metadata"],
    )


@pytest.mark.parametrize("laya", [False, True])
def test_fr70_native_scan_matches_python_findings_policy_and_history(
    service, checkout, tmp_path, laya
):
    # Compare the same advisory configuration; Python and native CLI defaults
    # differ after URL-scan support was added on main.
    baseline = service.run(str(checkout), settings(tmp_path, laya=laya))
    baseline_detail = service.detail(baseline["id"])
    path = tmp_path / "native.db"
    result = native(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(path),
        "--out",
        str(tmp_path / "go-reports"),
        "--json",
        *(["--laya"] if laya else []),
    )
    assert result.returncode == baseline["exit_code"], result.stderr + result.stdout
    actual = json.loads(result.stdout)
    detail = ScanService(str(path)).detail(actual["id"])
    assert [identity(f) for f in detail["findings"]] == [
        identity(f) for f in baseline_detail["findings"]
    ]
    assert actual["gate"] == baseline["gate"]
    assert actual["exceeded"] == baseline["exceeded"]
    assert actual["unknown_severity"] == baseline["unknown_severity"]
    assert actual["manifest"]["files"] == baseline["manifest"]["files"]
    for fmt in baseline["reports"]:
        assert Path(actual["reports"][fmt]).is_file()
    assert [e["stage"] for e in detail["events"]] == [e["stage"] for e in baseline_detail["events"]]
    history = native("scan-list", "--db-path", str(path), "--json")
    assert json.loads(history.stdout)[0]["run_id"] == actual["run_id"]
    retry = native("scan-retry", actual["run_id"], "--db-path", str(path))
    assert retry.returncode == 0, retry.stderr + retry.stdout
    assert ScanService(str(path)).history()[0]["attempt"] == 2


def test_native_group_contract_matches_python(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path))
    observations = [o for f in service.detail(result["id"])["findings"] for o in f["observations"]]
    from vulnscan.contracts import Observation

    baseline = group_findings([Observation.model_validate(o) for o in observations], "parity")
    request = {
        "version": 1,
        "id": "group",
        "method": "group",
        "params": {"observations": observations, "run_id": "parity"},
    }
    reply = subprocess.run(
        [str(BINARY), "worker"],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
        check=False,
    )
    payload = json.loads(reply.stdout)
    assert payload["ok"], payload
    actual = [Finding.model_validate(f).model_dump(mode="json") for f in payload["result"]]
    assert [identity(f) for f in actual] == [identity(f.model_dump(mode="json")) for f in baseline]
