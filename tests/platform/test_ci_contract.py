"""QR-22/23, FR-73/74: CI covers current surfaces and fails closed."""

from __future__ import annotations

import importlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]

ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
    "actions/setup-go": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
    "actions/upload-artifact": "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "actions/download-artifact": "9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "actions/setup-node": "949feb2413d6458794dcd2491c4babbbce0c15c1",
}


def workflow(name: str) -> dict:
    # BaseLoader preserves the GitHub Actions `on` key rather than YAML 1.1's bool.
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def commands(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_web_ui_job_installs_locked_and_runs_typecheck_tests_build():
    jobs = workflow("checks.yml")["jobs"]
    job = jobs["web-ui"]
    run = commands(job)
    for cmd in ("npm ci", "npm run lint", "npm test", "npm run build"):
        assert cmd in run
    assert "web-ui" in jobs["required"]["needs"]


def test_qr23_required_gate_covers_every_job_and_preserves_platform_matrix():
    jobs = workflow("checks.yml")["jobs"]
    assert set(jobs["required"]["needs"]) == set(jobs) - {"required"}
    assert jobs["required"]["if"] == "always()"
    matrix = jobs["tests"]["strategy"]["matrix"]["include"]
    assert {(row["os"], row["python"]) for row in matrix} == {
        ("ubuntu-latest", "3.11"),
        ("ubuntu-latest", "3.12"),
        ("ubuntu-latest", "3.13"),
        ("windows-latest", "3.11"),
        ("macos-latest", "3.11"),
    }
    assert "pytest tests " in commands(jobs["tests"])


def test_qr23_harness_and_native_have_explicit_suites_and_failure_artifacts():
    jobs = workflow("checks.yml")["jobs"]
    assert "tests/harness" in commands(jobs["harness"])
    assert "tests/platform tests/cli" in commands(jobs["native"])
    assert "tests/tui" not in commands(jobs["native"])
    for name in ("harness", "native", "tests"):
        assert "--junitxml=" in commands(jobs[name])
        uploads = [s for s in jobs[name]["steps"] if "upload-artifact@" in s.get("uses", "")]
        assert uploads and all(s["if"] == "always()" for s in uploads)


def test_qr22_workflows_pin_actions_and_keep_prs_unprivileged():
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        data = workflow(path.name)
        assert "pull_request_target" not in data["on"]
        assert data["permissions"] == {"contents": "read"}
        for job in data["jobs"].values():
            assert "secrets" not in job
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if uses and not uses.startswith("./"):
                    assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", uses), uses
                if uses.startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] == "false"


def test_qr23_locked_installs_are_not_resynced_without_their_extras():
    data = workflow("checks.yml")
    assert data["env"]["HF_HUB_OFFLINE"] == "1"
    assert data["env"]["TRANSFORMERS_OFFLINE"] == "1"
    assert data["env"]["DEVSECOPS_NATIVE"] == "python"
    assert "ci/check_lock_exports.py" in commands(data["jobs"]["quality"])
    for job in data["jobs"].values():
        for line in commands(job).splitlines() if "steps" in job else []:
            if "uv sync" in line:
                assert "--locked" in line
            if "uv run" in line:
                assert "--no-sync" in line


def test_fr74_release_uses_frozen_ref_and_both_required_workflows():
    data = workflow("release.yml")
    assert data["concurrency"]["cancel-in-progress"] == "false"
    assert set(data["jobs"]["publish"]["needs"]) == {"freeze", "checks", "integration"}
    for name in ("checks", "integration"):
        assert data["jobs"][name]["with"]["ref"] == "${{ needs.freeze.outputs.sha }}"
    assert data["jobs"]["publish"]["permissions"] == {"contents": "write"}
    for name in ("freeze", "publish"):
        assert any(
            s.get("uses", "").startswith("actions/setup-python@")
            for s in data["jobs"][name]["steps"]
        )


@pytest.mark.parametrize("status", ["failure", "cancelled", "skipped", "timed_out"])
def test_qr23_aggregate_gate_rejects_incomplete_or_failed_jobs(monkeypatch, status):
    gate = importlib.import_module("ci.require_success")
    monkeypatch.setenv(
        "CI_NEEDS_JSON",
        json.dumps(
            {
                "quality": {"result": "success"},
                "tests": {"result": status},
            }
        ),
    )
    assert gate.main() == 1


def test_qr23_aggregate_gate_accepts_only_nonempty_successes(monkeypatch):
    gate = importlib.import_module("ci.require_success")
    for needs, expected in [({}, 1), ({"tests": {"result": "success"}}, 0)]:
        monkeypatch.setenv("CI_NEEDS_JSON", json.dumps(needs))
        assert gate.main() == expected


@pytest.mark.parametrize(
    "drifted", ["requirements.lock", "requirements-build.lock", "requirements-scanners.lock"]
)
def test_qr22_export_check_detects_missing_runtime_dependency(tmp_path, monkeypatch, drifted):
    exports = importlib.import_module("ci.check_lock_exports")
    for name in ("requirements.lock", "requirements-build.lock", "requirements-scanners.lock"):
        (tmp_path / name).write_text("# generated header\ncvss==3.6\n")
    monkeypatch.setattr(
        exports.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "cvss==3.6\n", ""),
    )
    assert exports.check(tmp_path) == 0
    (tmp_path / drifted).write_text("# stale export\n")
    assert exports.check(tmp_path) == 1


def test_fr73_installed_smoke_refuses_unattended_chat_without_network(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "ci/smoke_installed.py")],
        cwd=tmp_path,
        input="",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Installed chat refused G0" in result.stdout


def test_fr73_every_packaged_delivery_path_checks_installed_chat():
    for name in ("package_smoke.py", "install_action.py", "scanners.Dockerfile"):
        assert "smoke_installed.py" in (ROOT / "ci" / name).read_text()
    assert "ci/smoke_installed.py" in (ROOT / "ci/build_image.py").read_text()


def test_qr22_actions_match_reviewed_stable_revisions_across_delivery_paths():
    paths = [
        *(ROOT / ".github/workflows").glob("*.yml"),
        ROOT / "action.yml",
        *(ROOT / "docs/examples").glob("security-*.yml"),
    ]
    for path in paths:
        for name, sha in re.findall(r"uses: (actions/[\w-]+)@([0-9a-f]+)", path.read_text()):
            assert sha == ACTION_PINS[name], f"{path.name}: {name} has a stale revision"


def test_qr23_package_smoke_selects_current_version_without_deleting_old_assets(tmp_path):
    module = importlib.import_module("ci.distributions")
    for version in ("0.2.0", "0.3.0"):
        (tmp_path / f"devsecops_agent-{version}-py3-none-any.whl").touch()
        (tmp_path / f"devsecops_agent-{version}.tar.gz").touch()
    wheel, source = module.select_current(tmp_path, "devsecops-agent", "0.3.0")
    assert wheel.name == "devsecops_agent-0.3.0-py3-none-any.whl"
    assert source.name == "devsecops_agent-0.3.0.tar.gz"
    assert (tmp_path / "devsecops_agent-0.2.0-py3-none-any.whl").exists()
    with pytest.raises(FileNotFoundError):
        module.select_current(tmp_path, "devsecops-agent", "9.0.0")
