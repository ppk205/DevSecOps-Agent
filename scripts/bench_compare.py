"""Cross-repo benchmark: native-hunt vs semgrep vs gitleaks.

Clones a fixed list of small/medium web repos (shallow), runs the three
scanners in-process, and writes per-repo folders with manifest + per-tool
JSON + overlap stats. No backend, no model calls — deterministic only.

Output: artifacts/bench-compare/<slug>/ {manifest.json, native.json,
semgrep.json, gitleaks.json, comparison.json} + SUMMARY.md
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPOS: list[tuple[str, str]] = [
    ("spring-boot-demo", "https://github.com/xkcoding/spring-boot-demo"),
    ("problem-spring-web", "https://github.com/zalando/problem-spring-web"),
    ("thelounge", "https://github.com/thelounge/thelounge"),
    ("matter-js", "https://github.com/liabru/matter-js"),
    ("vue-mdc", "https://github.com/posva/vue-mdc"),
    ("taiga-ui", "https://github.com/taiga-family/taiga-ui"),
    ("flask-tutorial", "https://github.com/helloflask/flask-tutorial"),
    ("falcon", "https://github.com/falconry/falcon"),
    ("sanic", "https://github.com/sanic-org/sanic"),
    ("laravel-terminal", "https://github.com/recca0120/laravel-terminal"),
    ("pikachu", "https://github.com/zhuifengshaonianhanlu/pikachu"),
    ("easyappointments", "https://github.com/alextselegidis/easyappointments"),
]

ROOT = Path("D:/dev/bench-repos")
OUT = Path("artifacts/bench-compare")


def run(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return proc.returncode, (proc.stdout + proc.stderr)[-500:]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def main() -> None:
    from vulnscan.contracts import ScanSpecification, ToolConfig, ToolName
    from vulnscan.native_hunt import scan_snapshot
    from vulnscan.scanners.base import AdapterRegistry

    ROOT.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    registry = AdapterRegistry.default()
    summary: list[dict[str, object]] = []
    for slug, url in REPOS:
        dest = ROOT / slug
        row: dict[str, object] = {"repo": slug, "url": url}
        repo_dir = OUT / slug
        repo_dir.mkdir(parents=True, exist_ok=True)
        if not (dest / ".git").exists():
            code, tail = run(
                ["git", "clone", "--depth", "1", url, str(dest)], 300
            )
            row["clone_exit"] = code
            if code != 0:
                row["note"] = tail[-200:]
                (repo_dir / "manifest.json").write_text(
                    json.dumps(row, indent=2), encoding="utf-8"
                )
                summary.append(row)
                continue
        rev = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()
        row["commit"] = rev

        # Native (in-process, always available).
        t0 = time.perf_counter()
        try:
            snap = scan_snapshot(
                str(dest), ["java", "javascript", "python", "php"]
            )
            native = [
                {
                    "file": f.file,
                    "line": f.line,
                    "rule_id": f.rule_id,
                    "cwe": f.cwe,
                    "confidence": f.confidence,
                    "snippet": f.snippet,
                }
                for f in snap.findings
            ]
            row["native_files"] = len(snap.scanned)
            row["native_skipped"] = len(snap.skipped)
            row["native_time_s"] = round(time.perf_counter() - t0, 1)
        except Exception as exc:  # noqa: BLE001 - one repo never kills the batch
            native = []
            row["native_error"] = f"{type(exc).__name__}: {exc}"[:200]
        (repo_dir / "native.json").write_text(
            json.dumps(native, indent=2), encoding="utf-8"
        )

        # Semgrep + gitleaks via adapters (deterministic, no provider).
        for tool_name, fname, timeout in [
            (ToolName.SEMGREP, "semgrep.json", 600),
            (ToolName.GITLEAKS, "gitleaks.json", 300),
        ]:
            adapter = registry.get(tool_name)
            spec = ScanSpecification(
                run_id=f"bench-{slug}",
                target_repository_url=url,
                target_commit_sha=rev or "0" * 40,
                repository_checkout_path=str(dest),
                tools=[ToolConfig(tool=tool_name)],
            )
            t0 = time.perf_counter()
            try:
                res = adapter.run(spec, workdir=str(dest))  # type: ignore[union-attr]
                obs = [
                    {
                        "file": o.location.file_path,
                        "line": o.location.line_start,
                        "rule_id": o.rule_id,
                        "cwe": str(o.cwe_category) if o.cwe_category else None,
                        "severity": str(o.severity),
                    }
                    for o in res.observations
                ]
                row[f"{fname.split('.')[0]}_time_s"] = round(time.perf_counter() - t0, 1)
                row[f"{fname.split('.')[0]}_errors"] = res.errors[:3]
            except Exception as exc:  # noqa: BLE001
                obs = []
                row[f"{fname.split('.')[0]}_error"] = f"{type(exc).__name__}: {exc}"[:200]
            (repo_dir / fname).write_text(
                json.dumps(obs, indent=2), encoding="utf-8"
            )

        # Overlap on (file, line).
        sem_keys = {
            (o["file"], o["line"])
            for o in json.loads((repo_dir / "semgrep.json").read_text(encoding="utf-8"))
        }
        nat_keys = {(f["file"], f["line"]) for f in native}
        git_keys = {
            (o["file"], o["line"])
            for o in json.loads((repo_dir / "gitleaks.json").read_text(encoding="utf-8"))
        }
        comp = {
            "native_lines": len(nat_keys),
            "semgrep_lines": len(sem_keys),
            "gitleaks_lines": len(git_keys),
            "native_and_semgrep": len(nat_keys & sem_keys),
            "native_only": len(nat_keys - sem_keys - git_keys),
            "semgrep_only": len(sem_keys - nat_keys),
            "gitleaks_only": len(git_keys - nat_keys),
        }
        (repo_dir / "comparison.json").write_text(
            json.dumps(comp, indent=2), encoding="utf-8"
        )
        (repo_dir / "manifest.json").write_text(
            json.dumps(row, indent=2), encoding="utf-8"
        )
        summary.append({**row, **comp})
        print(f"{slug}: native={len(nat_keys)} semgrep={len(sem_keys)} "
              f"gitleaks={len(git_keys)} overlap={len(nat_keys & sem_keys)}", flush=True)
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
