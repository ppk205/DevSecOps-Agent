"""Complete exact-rule baseline and patched scans; no status authority."""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
from pathlib import Path

import pytest

from vulnscan.ai import fix
from vulnscan.scanners.process import CommandResult, ScanCancelled

RULE = "py-sql-injection"


@pytest.fixture
def files(tmp_path):
    original = tmp_path / "original"
    overlay = tmp_path / "overlay"
    for root, content in ((original, b"old\n"), (overlay, b"new\n")):
        (root / "src").mkdir(parents=True)
        (root / "src/app.py").write_bytes(content)
    return original, overlay


def output(path, *, matches=None, errors=None, scanned=True, skipped=None):
    return json.dumps(
        {
            "version": "1.178.0",
            "results": [
                {
                    "check_id": rule,
                    "path": str(path),
                    "start": {"line": line, "col": 1},
                    "end": {"line": line, "col": 4},
                    "extra": {"message": "synthetic", "lines": "password=synthetic-value"},
                }
                for rule, line in (matches or [])
            ],
            "errors": errors or [],
            "paths": {"scanned": [str(path)] if scanned else [], "skipped": skipped or []},
        }
    )


def runner(
    monkeypatch,
    files,
    *,
    baseline=None,
    patched=None,
    baseline_code=0,
    patched_code=0,
    cancel_at=None,
):
    original, overlay = files
    baseline = (
        baseline if baseline is not None else output(original / "src/app.py", matches=[(RULE, 4)])
    )
    patched = patched if patched is not None else output(overlay / "src/app.py")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        is_original = Path(kwargs["cwd"]).name == "baseline"
        if cancel_at == ("baseline" if is_original else "patched"):
            raise ScanCancelled()
        source = (original if is_original else overlay) / "src/app.py"
        payload = (baseline if is_original else patched).replace(
            json.dumps(str(source)), json.dumps(argv[-1])
        )
        return CommandResult(
            baseline_code if is_original else patched_code,
            payload,
            stderr="password=synthetic-value",
            command=tuple(argv),
        )

    monkeypatch.setattr(fix, "run_command", run, raising=False)
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def verify(files, rule=RULE, baseline=True):
    original, overlay = files
    kwargs = {}
    # Exercise unsafe old behavior in RED without relying on a missing keyword.
    if "baseline" in inspect.signature(fix.verify_fixed).parameters and baseline:
        kwargs["baseline"] = original / "src/app.py"
    return fix.verify_fixed(overlay, "src/app.py", rule, 4, "semgrep", **kwargs)


def test_refire_after_line_shift_is_not_fixed(monkeypatch, files):
    runner(monkeypatch, files, patched=output(files[1] / "src/app.py", matches=[(RULE, 8)]))
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == "failed"


@pytest.mark.parametrize("exit_code", [0, 1, 2, 7])
@pytest.mark.parametrize(
    "kind", ["error", "skipped", "no-file", "non-json", "malformed", "other-file"]
)
def test_error_json_or_skipped_target_is_incomplete(monkeypatch, files, exit_code, kind):
    path = files[1] / "src/app.py"
    data = {
        "error": output(
            path, errors=[{"type": "ParseError", "message": "password=synthetic-value"}]
        ),
        "skipped": output(path, skipped=[{"path": str(path), "reason": "timeout"}]),
        "no-file": output(path, scanned=False),
        "non-json": "not json",
        "malformed": '{"results":{},"errors":[],"paths":{"scanned":[]}}',
        "other-file": output(files[1] / "src/else.py"),
    }[kind]
    runner(monkeypatch, files, patched=data, patched_code=exit_code)
    result = verify(files)
    assert result["fixed"] is False
    assert result["outcome"] == "incomplete"


@pytest.mark.parametrize(
    "matches", [[], [("other.py-sql-injection", 4)], [("not-py-sql-injection", 4)]]
)
def test_baseline_must_reproduce_exact_rule(monkeypatch, files, matches):
    runner(monkeypatch, files, baseline=output(files[0] / "src/app.py", matches=matches))
    result = verify(files)
    assert result["outcome"] == "incomplete"


def test_complete_baseline_and_clean_patch_pass(monkeypatch, files):
    calls = runner(monkeypatch, files)
    result = verify(files)
    assert result["fixed"] is True and result["outcome"] == "passed"
    assert result["rule_id"] == RULE
    assert result["tool_version"] == "1.178.0"
    assert result["baseline_sha256"] == hashlib.sha256(b"old\n").hexdigest()
    assert result["patched_sha256"] == hashlib.sha256(b"new\n").hexdigest()
    assert len(calls) == 2
    assert all("--no-rewrite-rule-ids" in argv for argv, _ in calls)
    assert "human review required" in result["detail"].lower()
    assert "independently_verified" not in result
    assert "status" not in result


def test_collision_rule_in_patch_is_not_exact_refire(monkeypatch, files):
    runner(
        monkeypatch,
        files,
        patched=output(files[1] / "src/app.py", matches=[("other.py-sql-injection", 8)]),
    )
    assert verify(files)["fixed"] is True


@pytest.mark.parametrize(
    "rule", ["no-such-rule", "evil.py-sql-injection", "native.py-sql-injection"]
)
def test_unsupported_rule_never_passes(monkeypatch, files, rule):
    calls = runner(monkeypatch, files)
    result = verify(files, rule)
    assert result["fixed"] is False and result["outcome"] == "unavailable"
    assert calls == []


def test_missing_baseline_is_incomplete_and_runs_nothing(monkeypatch, files):
    calls = runner(monkeypatch, files)
    result = verify(files, baseline=False)
    assert result["fixed"] is False and result["outcome"] == "incomplete"
    assert calls == []


@pytest.mark.parametrize(
    "code,outcome", [(127, "unavailable"), (-1, "incomplete"), (2, "incomplete"), (7, "incomplete")]
)
def test_tool_failures_never_pass(monkeypatch, files, code, outcome):
    runner(monkeypatch, files, patched_code=code)
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == outcome


@pytest.mark.parametrize("stage", ["baseline", "patched"])
def test_cancellation_is_retained_without_success(monkeypatch, files, stage):
    runner(monkeypatch, files, cancel_at=stage)
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == "cancelled"
    assert files[0].joinpath("src/app.py").read_bytes() == b"old\n"
    if stage == "patched":
        assert Path(result["baseline_artifact"]).is_file()


def test_artifacts_are_sanitized_append_only(monkeypatch, files):
    runner(monkeypatch, files)
    first = verify(files)
    baseline = Path(first["baseline_artifact"])
    patched = Path(first["patched_artifact"])
    before = {p: p.read_bytes() for p in (baseline, patched)}
    second = verify(files)
    assert second["baseline_artifact"] != first["baseline_artifact"]
    for p, data in before.items():
        assert p.read_bytes() == data
        assert b"synthetic-value" not in data
        assert b"[REDACTED]" in data
        assert p.is_relative_to(files[1])


@pytest.mark.parametrize("stage", ["baseline", "patched"])
def test_incomplete_baseline_or_timeout_never_passes(monkeypatch, files, stage):
    calls = runner(
        monkeypatch,
        files,
        baseline=output(files[0] / "src/app.py", errors=[{"type": "ParseError"}])
        if stage == "baseline"
        else None,
    )
    if stage == "patched":
        previous = fix.run_command
        monkeypatch.setattr(
            fix,
            "run_command",
            lambda *args, **kwargs: (
                CommandResult(0, timed_out=True) if len(calls) else previous(*args, **kwargs)
            ),
        )
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == "incomplete"


@pytest.mark.parametrize("stage", ["baseline", "patched"])
def test_cancelled_stage_has_sanitized_artifact(monkeypatch, files, stage):
    runner(monkeypatch, files, cancel_at=stage)
    result = verify(files)
    artifact = result[f"{stage}_artifact"]
    assert artifact is not None
    retained = json.loads(Path(artifact).read_text())
    assert retained["outcome"] == "cancelled"
    assert "stdout" not in retained


@pytest.mark.parametrize("prefix", ["src.vulnscan.scanners.rules.", "evil."])
def test_exact_bundled_namespace_preserves_identity(monkeypatch, files, prefix):
    runner(monkeypatch, files)
    result = verify(files, prefix + RULE)
    assert result["rule_id"] == prefix + RULE
    assert result["fixed"] is (prefix != "evil.")


@pytest.mark.parametrize("stage", ["baseline", "patched"])
@pytest.mark.parametrize("mutate_copy", [False, True])
def test_source_mutation_during_scan_never_passes(monkeypatch, files, stage, mutate_copy):
    runner(monkeypatch, files)
    previous = fix.run_command

    def mutate(argv, **kwargs):
        result = previous(argv, **kwargs)
        if Path(kwargs["cwd"]).name == stage:
            target = (
                Path(argv[-1]) if mutate_copy else files[int(stage == "patched")] / "src/app.py"
            )
            target.write_bytes(b"changed\n")
        return result

    monkeypatch.setattr(fix, "run_command", mutate)
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == "incomplete"


@pytest.mark.parametrize(
    "malformed",
    [
        {"results": [], "errors": [], "paths": {"scanned": ["src/app.py", {}]}},
        {"results": [], "errors": [], "paths": {"scanned": ["src/app.py"], "skipped": [{}]}},
        {
            "results": [{"check_id": RULE, "path": "src/app.py", "start": {"line": True}}],
            "errors": [],
            "paths": {"scanned": ["src/app.py"]},
        },
    ],
)
def test_malformed_coverage_or_match_does_not_pass(monkeypatch, files, malformed):
    runner(monkeypatch, files, patched=json.dumps({"version": "1.178.0", **malformed}))
    result = verify(files)
    assert result["fixed"] is False and result["outcome"] == "incomplete"


def test_baseline_credential_parent_is_rejected_before_runner(monkeypatch, files):
    baseline = files[0] / ".secrets"
    baseline.mkdir()
    (baseline / "app.py").write_bytes(b"old\n")
    calls = runner(monkeypatch, files)
    result = fix.verify_fixed(files[1], "src/app.py", RULE, 4, baseline=baseline / "app.py")
    assert result["fixed"] is False and result["outcome"] == "incomplete"
    assert calls == []


def test_contract_rejects_inconsistent_success():
    from pydantic import ValidationError

    from vulnscan.contracts.remediation import FixVerification

    with pytest.raises(ValidationError):
        FixVerification(fixed=True, detail="synthetic", outcome="incomplete", rule_id=RULE)


def test_only_exact_selected_rule_is_executed(monkeypatch, files):
    calls = runner(monkeypatch, files)
    assert verify(files)["fixed"] is True
    for argv, _ in calls:
        excluded = [argv[i + 1] for i, value in enumerate(argv) if value == "--exclude-rule"]
        assert "py-hardcoded-secret" in excluded
        assert "py-command-injection" in excluded
        assert "py-sql-injection" not in excluded
        assert len(excluded) == 19


@pytest.mark.parametrize("suffix", ["go", "rb", "cs"])
def test_unsupported_language_cannot_qualify(monkeypatch, files, suffix):
    for root in files:
        (root / f"src/app.{suffix}").write_bytes(b"synthetic\n")
    calls = runner(monkeypatch, files)
    result = fix.verify_fixed(
        files[1], f"src/app.{suffix}", RULE, 4, baseline=files[0] / f"src/app.{suffix}"
    )
    assert result["fixed"] is False and result["outcome"] == "unavailable"
    assert calls == []


@pytest.mark.parametrize("name", [".secrets.", ".env ", "CON", "directory."])
def test_baseline_aliases_rejected_before_filesystem(monkeypatch, files, name):
    calls = runner(monkeypatch, files)
    real_stat = Path.stat

    def forbidden(self, *args, **kwargs):
        if self.is_relative_to(files[0]) or self.is_relative_to(files[1]):
            raise AssertionError("baseline alias reached filesystem")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    result = fix.verify_fixed(files[1], "src/app.py", RULE, 4, baseline=files[0] / name / "app.py")
    assert result["fixed"] is False and result["outcome"] == "incomplete"
    assert calls == []


def test_scanner_receives_validated_bytes_not_a_racy_source_path(monkeypatch, files):
    runner(monkeypatch, files)
    previous = fix.run_command
    scanned = []

    def capture(argv, **kwargs):
        target = Path(argv[-1])
        assert target.relative_to(kwargs["cwd"]).as_posix() == "src/app.py"
        assert all(not target.is_relative_to(source) for source in files)
        scanned.append((target, target.read_bytes()))
        return previous(argv, **kwargs)

    monkeypatch.setattr(fix, "run_command", capture)
    assert verify(files)["fixed"] is True
    assert [data for _, data in scanned] == [b"old\n", b"new\n"]
    assert all(not target.exists() for target, _ in scanned)
