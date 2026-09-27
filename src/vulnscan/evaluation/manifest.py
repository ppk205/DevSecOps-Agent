"""Build the evidence manifest for T10 handover.

Every entry is derived from a file that exists; nothing is asserted from
memory. A missing artifact is reported as missing rather than omitted, so the
manifest can never look more complete than the repository is.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.decisions.protocol import (
    CONTRACT_VERSION,
    MODEL_ID,
    MODEL_LICENSE,
    MODEL_REVISION,
    QUESTION_SET_VERSION,
    STATUS_OWNER,
    VERIFIED_DEPENDENCIES,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Paths the plan requires for handover. A missing entry is a finding, not a
#: reason to drop the line.
REQUIRED_ARTIFACTS = (
    "docs/REPRODUCTION.md",
    "requirements.lock.txt",
    "scripts/record_environment.sh",
    "scripts/laya_bench.py",
    "src/vulnscan/decisions/protocol.py",
    "evidence/t09/ground_truth.json",
    "evidence/environment/pip-freeze.txt",
)


@dataclass(frozen=True)
class Artifact:
    path: str
    present: bool
    sha256: str | None
    size_bytes: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "present": self.present,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def describe(rel_path: str, root: Path = REPO_ROOT) -> Artifact:
    """Hash one artifact; a missing file is reported, never skipped."""
    target = root / rel_path
    if not target.is_file():
        return Artifact(path=rel_path, present=False, sha256=None, size_bytes=None)
    data = target.read_bytes()
    return Artifact(
        path=rel_path,
        present=True,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def ground_truth_state(root: Path = REPO_ROOT) -> dict[str, Any]:
    """Read the T09 ground truth, reporting honestly if it is unadjudicated."""
    path = root / "evidence" / "t09" / "ground_truth.json"
    if not path.is_file():
        return {"present": False, "adjudicated": False, "rows": 0}

    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("rows", data) if isinstance(data, dict) else data
    return {
        "present": True,
        "adjudicated": bool(data.get("adjudicated", False)) if isinstance(data, dict) else False,
        "rows": len(rows),
    }


def build_manifest(root: Path = REPO_ROOT) -> dict[str, Any]:
    artifacts = [describe(p, root) for p in REQUIRED_ARTIFACTS]
    missing = [a.path for a in artifacts if not a.present]
    truth = ground_truth_state(root)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "protocol": {
            "contract_version": CONTRACT_VERSION,
            "question_set_version": QUESTION_SET_VERSION,
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "model_license": MODEL_LICENSE,
            "status_owner": STATUS_OWNER,
            "verified_dependencies": VERIFIED_DEPENDENCIES,
        },
        "artifacts": [a.to_dict() for a in artifacts],
        "missing_artifacts": missing,
        "t09_ground_truth": truth,
        "blockers": _blockers(truth, missing),
    }


def _blockers(truth: dict[str, Any], missing: list[str]) -> list[str]:
    """Plain statements of what prevents T09/T10 being called complete."""
    blockers: list[str] = []
    if not truth.get("adjudicated") or not truth.get("rows"):
        blockers.append(
            "T09 cannot produce accuracy, ECE, or Brier: no adjudicated ground "
            "truth exists, so every graded metric is reported as null."
        )
    if missing:
        blockers.append(f"Missing required handover artifacts: {', '.join(missing)}")
    return blockers


if __name__ == "__main__":  # pragma: no cover - manual invocation
    print(json.dumps(build_manifest(), indent=2, default=str))
