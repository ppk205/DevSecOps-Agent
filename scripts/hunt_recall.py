"""Hunt recall harness: native baseline vs hunt candidates on a snapshot.

Offline default (no network): runs the deterministic native-hunt engine
over ``--snapshot`` and matches candidates from ``--hunt-json`` by
(file, line ±3). ``--live`` additionally runs ``hunt_all`` against the
configured provider (key from env, never printed) and matches that output.

Outputs a JSON report to ``--out`` and prints a short markdown summary.
Provider/upstream failures are fail-soft: the report records the error
with zero live candidates instead of raising.

Examples:
    python scripts/hunt_recall.py --snapshot harness/WebGoat \\
        --hunt-json artifacts/live-mega/run-XXX/hunt.json
    python scripts/hunt_recall.py --snapshot harness/WebGoat --live \\
        --out artifacts/hunt-recall/report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ when not already set (no echo)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def native_baseline(snapshot: str) -> list[dict]:
    from vulnscan.native_hunt import scan_snapshot

    snap = scan_snapshot(snapshot, ["java", "javascript", "python", "php"])
    return [
        {"file": f.file, "line": f.line, "rule_id": f.rule_id, "cwe": f.cwe} for f in snap.findings
    ]


def candidates_from_hunt_json(path: str) -> list[dict]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        for key in ("candidates", "model_candidates"):
            if isinstance(raw.get(key), list):
                return [dict(c) for c in raw[key] if isinstance(c, dict)]
        return []
    return [dict(c) for c in raw if isinstance(c, dict)]


def git_inventory(snapshot: str) -> list[str]:
    """Tracked-file inventory like the pipeline manifest (no .git noise)."""
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "-C", snapshot, "ls-files", "-z"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception:  # noqa: BLE001 - harness inventory is best-effort
        return []
    if proc.returncode != 0:
        return []
    return sorted({e for e in proc.stdout.split("\0") if e})


def prepare_snapshot(repo: str, dest: str) -> str:
    """Materialize a clean snapshot (tracked files only) via git archive."""
    import subprocess
    import tarfile

    dest_path = Path(dest)
    if dest_path.exists():
        import shutil

        shutil.rmtree(dest_path)
    dest_path.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", repo, "archive", "HEAD"],
        capture_output=True,
        timeout=300,
        check=False,
    )
    if archive.returncode != 0:
        raise RuntimeError(f"git archive failed: {archive.stderr.decode()[:200]}")
    import io

    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(dest_path)
    return str(dest_path)


def run_live_hunt(
    snapshot: str, model: str, profile: str, inventory_repo: str | None = None
) -> dict:
    from vulnscan.ai.hunt import detect_families, hunt_all
    from vulnscan.providers.budget import BudgetManager
    from vulnscan.providers.client import ProviderClient
    from vulnscan.providers.profile_store import load_profile

    client = ProviderClient(load_profile(profile), BudgetManager())
    inventory = git_inventory(inventory_repo or snapshot)
    families = detect_families(inventory)
    started = time.time()
    hunt_out = hunt_all(
        snapshot_root=snapshot,
        client=client,
        model=model,
        families=families,
        logic_pass=True,
        broad_pass=True,
        micro_passes=True,
        max_rounds=16,
        max_findings=200,
        deep=True,
    )
    hunt_out["elapsed_s"] = round(time.time() - started, 1)
    return hunt_out


def main() -> int:
    parser = argparse.ArgumentParser(description="Hunt recall vs native baseline.")
    parser.add_argument("--snapshot", default="harness/WebGoat")
    parser.add_argument("--git-archive", default="", help="git repo to snapshot via git archive")
    parser.add_argument("--snapshot-prep", default="artifacts/hunt-recall/snapshot")
    parser.add_argument("--hunt-json", default="")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--profile", default="opencode-free")
    parser.add_argument("--model", default="iceman-contributor-free")
    parser.add_argument("--tolerance", type=int, default=3)
    parser.add_argument("--out", default="artifacts/hunt-recall/report.json")
    args = parser.parse_args()

    _load_dotenv(REPO_ROOT / ".env")
    inventory_repo = None
    if args.git_archive:
        repo = str(
            REPO_ROOT / args.git_archive
            if not os.path.isabs(args.git_archive)
            else args.git_archive
        )
        snapshot = prepare_snapshot(repo, str(REPO_ROOT / args.snapshot_prep))
        inventory_repo = repo
    else:
        snapshot = str(
            REPO_ROOT / args.snapshot if not os.path.isabs(args.snapshot) else args.snapshot
        )

    from vulnscan.ai.recall import match_candidates_to_native, recall_report

    native = native_baseline(snapshot)
    report: dict = {
        "snapshot": args.snapshot,
        "native_total": len(native),
        "tolerance": args.tolerance,
    }

    if args.hunt_json:
        candidates = candidates_from_hunt_json(args.hunt_json)
        match = match_candidates_to_native(candidates, native, tolerance=args.tolerance)
        report["hunt_json"] = args.hunt_json
        report["static"] = {
            "candidates": len(candidates),
            "matched": match["matched"],
            "recall": match["recall"],
            "precision": match["precision"],
            "by_rule": match["by_rule"],
        }
        report["static_summary"] = recall_report(match)

    if args.live:
        try:
            hunt_out = run_live_hunt(snapshot, args.model, args.profile, inventory_repo)
            live_candidates = [dict(c) for c in hunt_out.get("candidates", [])]
            match = match_candidates_to_native(live_candidates, native, tolerance=args.tolerance)
            out_path = REPO_ROOT / args.out if not os.path.isabs(args.out) else Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path = out_path.with_name("hunt-out.json")
            try:
                raw_path.write_text(json.dumps(hunt_out, indent=2)[:500000], encoding="utf-8")
            except OSError:
                pass
            report["live"] = {
                "candidates": len(live_candidates),
                "matched": match["matched"],
                "recall": match["recall"],
                "precision": match["precision"],
                "by_rule": match["by_rule"],
                "passes": hunt_out.get("passes", []),
                "rounds": hunt_out.get("rounds", 0),
                "elapsed_s": hunt_out.get("elapsed_s", 0),
                "status": hunt_out.get("status", ""),
                "detail": str(hunt_out.get("detail", ""))[:500],
            }
            report["live_summary"] = recall_report(match)
        except Exception as exc:  # noqa: BLE001 - harness is fail-soft by design
            report["live"] = {"error": f"{type(exc).__name__}", "candidates": 0}
            report["live_summary"] = f"live hunt failed ({type(exc).__name__}), recall 0%"

    out_path = REPO_ROOT / args.out if not os.path.isabs(args.out) else Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"# Hunt recall vs native ({args.snapshot})")
    print(f"- native findings: {len(native)}")
    if "static_summary" in report:
        print(f"- hunt.json: {report['static_summary']}")
    if "live_summary" in report:
        print(f"- live: {report['live_summary']}")
    print(f"- report: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
