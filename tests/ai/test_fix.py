"""AI fix proposals: prompt/parse unit tests (no network) + apply/verify on fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnscan.ai.fix import (
    apply_unified_diff,
    build_fix_prompt,
    extract_diff,
    prepare_overlay,
    verify_fixed,
)
from vulnscan.scanners.platform import which


def _finding() -> dict:
    return {
        "finding_id": "abc123",
        "title": "CWE-89 at src/app.py:8",
        "severity": "high",
        "cwe_category": "CWE-89",
        "observations": [
            {
                "rule_id": "py-sql-injection",
                "location": {
                    "file_path": "src/app.py",
                    "line_start": 8,
                    "snippet": 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
                },
            }
        ],
    }


def test_build_fix_prompt_contains_evidence() -> None:
    prompt = build_fix_prompt(_finding())
    assert "CWE-89" in prompt
    assert "src/app.py" in prompt
    assert "cur.execute" in prompt


def test_build_fix_prompt_numbers_context() -> None:
    prompt = build_fix_prompt(_finding(), code_context="  8| foo()\n  9| bar()\n")
    assert "8| foo()" in prompt
    assert "strip the prefixes" in prompt


def test_extract_diff_prefers_fenced_block() -> None:
    reply = (
        "Here is the fix:\n```diff\n--- a/src/app.py\n+++ b/src/app.py\n"
        "@@ -8 +8 @@\n-old\n+new\n```\nDone."
    )
    diff = extract_diff(reply)
    assert diff.startswith("--- a/src/app.py")
    assert "+new" in diff


def test_extract_diff_empty_without_diff() -> None:
    assert extract_diff("No vulnerabilities found.") == ""


@pytest.mark.parametrize("real_scanner", [False, True], ids=["offline", "semgrep"])
def test_apply_and_verify_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, real_scanner: bool
) -> None:
    if real_scanner and which("semgrep") is None:
        pytest.skip("Semgrep is not installed; offline overlay roundtrip is tested separately")
    checkout = tmp_path / "repo"
    src = checkout / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text(
        "import sqlite3\n"
        "def user(name):\n"
        "    cur = sqlite3.connect('a.db').cursor()\n"
        '    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        "    return cur.fetchall()\n",
        encoding="utf-8",
    )
    diff = (
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,5 +1,5 @@\n"
        " import sqlite3\n"
        " def user(name):\n"
        "     cur = sqlite3.connect('a.db').cursor()\n"
        '-    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        '+    cur.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        "     return cur.fetchall()\n"
    )
    overlay = prepare_overlay(str(checkout), "src/app.py", tmp_path / "overlay")
    assert (overlay / "src" / "app.py").is_file()
    # Original checkout untouched.
    assert "+ name +" in (src / "app.py").read_text(encoding="utf-8")
    applied = apply_unified_diff(overlay, diff)
    assert applied == ["src/app.py"]
    patched = (overlay / "src" / "app.py").read_text(encoding="utf-8")
    assert "?" in patched and "+ name +" not in patched
    assert "+ name +" in (src / "app.py").read_text(encoding="utf-8")
    if not real_scanner:

        def fake_scan(args, **kwargs):
            assert Path(args[-1]) == overlay / "src" / "app.py"
            assert Path(args[args.index("--config") + 1]).name == "python.yml"
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"results": [], "errors": [], "paths": {"scanned": [args[-1]]}}),
            )

        monkeypatch.setattr("vulnscan.ai.fix.subprocess.run", fake_scan)
    result = verify_fixed(overlay, "src/app.py", "py-sql-injection", 4)
    assert result["fixed"] is True, result


def test_apply_rejects_bad_context(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    try:
        apply_unified_diff(
            repo,
            "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-goodbye\n+hello\n",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_apply_rejects_path_escape(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    try:
        apply_unified_diff(
            repo,
            "--- a/../evil.txt\n+++ b/../evil.txt\n@@ -0,0 +1 @@\n+x\n",
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")
