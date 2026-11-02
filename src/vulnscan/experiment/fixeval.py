"""Evaluate an owner-supplied fix in a scratch clone, never the target checkout.

This is an offline experiment CLI, not a model-callable harness tool. Detector
removal is a static observation; a human verdict is separate and never inferred.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import re
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, cast

from vulnscan.experiment.groundtruth import GTItem, Row, load_gt, match, normalise_path
from vulnscan.harness.fixes import changed_lines, diff_hunks
from vulnscan.harness.scanning import extract_candidates
from vulnscan.harness.tools import FIX_WINDOW, MAX_FIX_LINES
from vulnscan.harness.workspace import Workspace
from vulnscan.providers.credentials import redact, redact_json

Detector = Callable[[Path], list[Row]]


@dataclass
class FixScore:
    applies: bool = False
    compiles: bool | None = None
    vuln_removed_by_detector: bool | None = None
    files_changed: int | None = None
    lines_changed: int | None = None
    in_scope: bool = False
    new_alerts: int | None = None
    human_verdict: str | None = None
    human_reason: str | None = None
    errors: list[str] = field(default_factory=list)
    commands: list[dict[str, Any]] = field(default_factory=list)
    before_alerts: list[Row] = field(default_factory=list)
    after_alerts: list[Row] = field(default_factory=list)


def coverage(alerts: Iterable[str], suggestions: Mapping[str, str | None]) -> float | None:
    """Fraction of distinct alert ids with a nonempty suggestion; no alerts -> null."""
    ids = set(alerts)
    return (
        sum(bool(suggestions.get(key, "") and str(suggestions[key]).strip()) for key in ids)
        / len(ids)
        if ids
        else None
    )


def _run(
    cwd: Path, args: list[str], input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Substituted in tests; fixed argv, no shell and a bounded wait."""
    # Binary stdin preserves patch newlines on Windows; text mode inserts CRs.
    result = subprocess.run(
        args,
        cwd=cwd,
        input=input_text.encode("utf-8") if input_text is not None else None,
        capture_output=True,
        check=False,
        timeout=300,
    )
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        result.stdout.decode("utf-8", errors="replace"),
        result.stderr.decode("utf-8", errors="replace"),
    )


def _paths(diff: str, ws: Workspace) -> list[str]:
    paths: list[str] = []
    for line in diff.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        raw = line[4:].split("\t", 1)[0]
        if raw == "/dev/null":
            continue
        if not raw.startswith(("a/", "b/")):
            raise ValueError("only plain a/ and b/ unified diff paths are supported")
        relative = raw[2:]
        if ".git" in Path(relative).parts:
            raise ValueError("patch cannot touch git metadata")
        ws.resolve(relative)
        paths.append(relative)
    if not paths or not diff_hunks(diff):
        raise ValueError("patch has no supported textual hunks")
    return sorted(set(paths))


def _line_map(before: str, after: str) -> dict[int, int]:
    """Map old positions to new positions, including replacement/deletion anchors."""
    result: dict[int, int] = {}
    for _tag, i, j, k, end in SequenceMatcher(
        None, before.splitlines(), after.splitlines(), autojunk=False
    ).get_opcodes():
        for old in range(i, j):
            result[old + 1] = k + min(old - i, max(end - k - 1, 0)) + 1
    return result


def _key(row: Row) -> tuple[str, int, str]:
    return normalise_path(row.file), row.line, row.cwe


def evaluate_fix(
    repo: Path, commit: str, diff: str, finding: GTItem, detector: Detector
) -> FixScore:
    """Score one fix against the same detector before and after the patch.

    Only a local source repository and pinned commit are accepted. All git
    operations, Maven compilation and detector calls operate under a disposable
    scratch directory. Failed/unavailable stages stay null with a recorded error.
    """
    score = FixScore()
    try:
        hunks = diff_hunks(diff)
        score.lines_changed = changed_lines(diff)
    except ValueError as exc:
        score.errors.append(redact(f"unsupported or malformed diff: {exc}"))
        return score
    if not repo.is_dir() or not re.fullmatch(r"[a-fA-F0-9]{7,64}", commit):
        score.errors.append("requires a local repository and a pinned hexadecimal commit")
        return score
    if finding.kind != "vuln" or not finding.agreed:
        score.errors.append("fix evaluation requires an agreed vulnerable ground-truth item")
        return score
    score.files_changed = len({path for path, _, _ in hunks})
    score.in_scope = (
        bool(hunks)
        and score.lines_changed <= MAX_FIX_LINES
        and all(
            normalise_path(path) == normalise_path(finding.file)
            and start >= finding.line_start - FIX_WINDOW
            and end <= finding.line_end + FIX_WINDOW
            for path, start, end in hunks
        )
    )

    def command(cwd: Path, args: list[str], input_text: str | None = None) -> bool:
        result = _run(cwd, args, input_text)
        score.commands.append(
            {
                "argv": args,
                "returncode": result.returncode,
                "stdout": redact(result.stdout),
                "stderr": redact(result.stderr),
            }
        )
        if result.returncode:
            score.errors.append(
                redact(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
            )
        return result.returncode == 0

    try:
        temporary_parent = Path(tempfile.gettempdir()).resolve()
        if temporary_parent.is_relative_to(repo.resolve()):
            raise ValueError("temporary directory must be outside the target")
        with tempfile.TemporaryDirectory(prefix="devsec-fixeval-", dir=temporary_parent) as temp:
            root = Path(temp).resolve()
            # An externally configured temp directory must not put scratch data in the target.
            if root.is_relative_to(repo.resolve()):
                raise ValueError("temporary directory must be outside the target")
            clone = root / "clone"
            tree = root / "worktree"
            if not command(
                root,
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "clone",
                    "--no-hardlinks",
                    "--no-checkout",
                    "--",
                    str(repo.resolve()),
                    str(clone),
                ],
            ):
                return score
            if not command(
                clone,
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "worktree",
                    "add",
                    "--detach",
                    str(tree),
                    commit,
                ],
            ):
                return score
            ws = Workspace(tree, commit)
            paths = _paths(diff, ws)
            score.files_changed = len(paths)
            # Reject patch metadata that could introduce a link followed outside the tree.
            if re.search(r"^(?:new|old) (?:file )?mode 120000", diff, re.MULTILINE):
                raise ValueError("symbolic-link patches are not supported")
            before_text = {
                path: ws.resolve(path).read_text(encoding="utf-8")
                if ws.resolve(path).is_file()
                else ""
                for path in paths
            }
            before_ok = True
            try:
                score.before_alerts = detector(tree)
            except Exception as exc:  # noqa: BLE001 - detector/plugin boundary
                score.errors.append(redact(f"before detector unavailable: {exc}"))
                before_ok = False
            if not command(tree, ["git", "apply", "--check", "-"], diff):
                return score
            if not command(tree, ["git", "apply", "-"], diff):
                return score
            score.applies = True
            try:
                score.compiles = command(tree, ["mvn", "-q", "-o", "compile"])
            except (OSError, subprocess.SubprocessError) as exc:
                score.errors.append(redact(f"compile unavailable: {exc}"))
            try:
                score.after_alerts = detector(tree)
            except Exception as exc:  # noqa: BLE001 - detector/plugin boundary
                score.errors.append(redact(f"after detector unavailable: {exc}"))
                return score
            if not before_ok:
                return score
            maps = {
                path: _line_map(
                    before_text[path],
                    ws.resolve(path).read_text(encoding="utf-8")
                    if ws.resolve(path).is_file()
                    else "",
                )
                for path in paths
            }
            mapped = [
                replace(row, line=maps.get(normalise_path(row.file), {}).get(row.line, row.line))
                for row in score.before_alerts
            ]
            score.new_alerts = len(
                {_key(row) for row in score.after_alerts} - {_key(row) for row in mapped}
            )
            before_matches = match(score.before_alerts, [finding], {}).tp
            if before_matches:
                positions = maps.get(normalise_path(finding.file), {})
                shifted = replace(
                    finding,
                    line_start=positions.get(finding.line_start, finding.line_start),
                    line_end=positions.get(finding.line_end, finding.line_end),
                )
                score.vuln_removed_by_detector = not bool(
                    match(score.after_alerts, [shifted], {}).tp
                )
            else:
                score.errors.append(
                    "target site was not reported before patch; detector removal is unknown"
                )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        score.errors.append(redact(str(exc)))
    return score


def harness_detector(path: Path) -> list[Row]:
    """Static candidates only, with no model, gates or human status changes."""
    return [
        Row("F1", 1, c.file, c.line, c.cwe, None, None, "baseline", c.id)
        for c in extract_candidates(Workspace(path, "scratch"))
    ]


def _verdict(path: Path, finding_id: str, score: FixScore) -> None:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("finding_id") == finding_id]
    if len(rows) != 1:
        raise ValueError("verdict CSV must have exactly one matching finding_id")
    row = rows[0]
    if row.get("agreed", "").lower() != "true":
        return
    if not row.get("labeller_a") or not row.get("labeller_b") or not row.get("human_reason"):
        raise ValueError("agreed verdict needs two labellers and a reason")
    if row.get("human_verdict") not in {"accept", "reject", "need_more"}:
        raise ValueError("human_verdict must be accept, reject or need_more")
    score.human_verdict, score.human_reason = row["human_verdict"], row["human_reason"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--diff", required=True, type=Path)
    parser.add_argument("--gt", required=True, type=Path)
    parser.add_argument("--finding", required=True)
    parser.add_argument(
        "--detector",
        required=True,
        help="harness or trusted owner module:function returning list[Row]",
    )
    parser.add_argument("--verdicts", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f"output already exists: {args.out}")
        items = [item for item in load_gt(args.gt) if item.id == args.finding]
        if len(items) != 1:
            raise ValueError("ground truth must contain exactly one requested finding")
        detector: Detector = harness_detector
        if args.detector != "harness":
            module, name = args.detector.split(":", 1)
            detector = cast(Detector, getattr(importlib.import_module(module), name))
        score = evaluate_fix(
            args.repo, args.commit, args.diff.read_text(encoding="utf-8"), items[0], detector
        )
        if args.verdicts:
            _verdict(args.verdicts, args.finding, score)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as handle:
            handle.write(
                redact_json(
                    {
                        "finding_id": args.finding,
                        "commit": args.commit,
                        "detector": args.detector,
                        **asdict(score),
                    },
                    indent=2,
                )
            )
        return 0
    except (OSError, ValueError, ImportError, AttributeError) as exc:
        print(redact(str(exc)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
