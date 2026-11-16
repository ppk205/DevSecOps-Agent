"""AI-generated fix proposals for findings.

The model only writes a unified diff — it never touches source. Applying a
proposal copies the affected files into an overlay directory under artifacts,
patches the copy, and compares complete baseline/patched rule scans. This
limited mechanical observation still requires human review. The user's checkout
is never modified.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnscan.contracts.enums import language_from_extension
from vulnscan.contracts.remediation import FixVerification
from vulnscan.core.security import sanitize
from vulnscan.providers.budget import BudgetExhausted, BudgetManager
from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.credentials import redact
from vulnscan.providers.profile_store import load_profile
from vulnscan.scanners.process import CommandResult, ScanCancelled, run_command
from vulnscan.scanners.semgrep_adapter import _NO_RULE_LANGUAGES

from . import _fix_fs as fs

FIX_SYSTEM = (
    "You are a secure-code repair assistant. Given one vulnerability finding "
    "with its source snippet, output ONLY a unified diff that fixes it. "
    "Rules: keep the diff minimal; do not change behavior beyond the fix; "
    "do not include explanations, only the diff in a ```diff block. "
    "Use `a/<path>` / `b/<path>` headers with the repo-relative file path."
)

FIX_USER_TEMPLATE = """\
CWE: {cwe}
Title: {title}
Rule: {rule}
File: {file_path} (line {line})
Severity: {severity}

Vulnerable code:
```
{snippet}
```
{context_section}
Write the minimal unified diff fixing this {cwe} issue."""


@dataclass
class FixProposal:
    finding_id: str
    file_path: str
    diff_text: str
    model: str | None
    usage: dict[str, int] | None = None
    profile_id: str | None = None


def build_fix_prompt(finding: dict[str, Any], code_context: str = "") -> str:
    """Render the user prompt for one finding dict (Finding dump).

    ``code_context`` is wider surrounding source from the local checkout.
    Without it the model reconstructs plausible-but-wrong context lines and
    the strict applier rightly rejects the patch.
    """
    section = ""
    if code_context.strip():
        section = (
            "Full surrounding code for exact context lines "
            "(each line is prefixed `NN|` with its real number — "
            "strip the prefixes, never renumber, copy context verbatim):\n```\n"
            + code_context[:4000]
            + "\n```\n"
        )
    obs = (finding.get("observations") or [{}])[0]
    loc = obs.get("location", {})
    return FIX_USER_TEMPLATE.format(
        cwe=finding.get("cwe_category") or "unknown",
        title=finding.get("title", ""),
        rule=obs.get("rule_id", ""),
        file_path=loc.get("file_path", ""),
        line=loc.get("line_start", "?"),
        severity=finding.get("severity", ""),
        snippet=(loc.get("snippet") or "")[:2000],
        context_section=section,
    )


def extract_diff(reply: str) -> str:
    """Pull the ```diff block out of a model reply; empty string if none."""
    _check_diff_text(reply)
    match = re.search(r"```diff\s*(.*?)```", reply, re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    # Fallback: raw diff starting at the first --- a/ header.
    start = reply.find("--- a/")
    if start >= 0:
        return reply[start:].strip() + "\n"
    return ""


def propose_fix(
    finding: dict[str, Any],
    profile_id: str,
    model: str | None = None,
    max_tokens: int = 2000,
    code_context: str = "",
    *,
    budget: BudgetManager | None = None,
) -> FixProposal:
    """Ask the model for a unified diff fixing one finding."""
    profile = load_profile(profile_id)
    tracker = budget if budget is not None else BudgetManager()
    if tracker.available <= 0:
        raise BudgetExhausted("Recorded budget is exhausted")
    client = ProviderClient(profile, budget=tracker)
    response = client.chat(
        [
            ChatMessage(role="system", content=FIX_SYSTEM),
            ChatMessage(role="user", content=build_fix_prompt(finding, code_context)),
        ],
        model=model or profile.default_model,
        temperature=0.0,
        max_tokens=max_tokens,
    )
    diff = extract_diff(response.content or "")
    if not diff:
        raise ValueError("Model reply contained no unified diff")
    obs = (finding.get("observations") or [{}])[0]
    _parse_diff(diff)
    return FixProposal(
        finding_id=str(finding.get("finding_id", "")),
        file_path=str(obs.get("location", {}).get("file_path", "")),
        diff_text=diff,
        model=returned_model
        if isinstance((returned_model := response.raw.get("model")), str) and returned_model.strip()
        else None,
        usage=dict(response.usage) if response.usage else None,
        profile_id=profile.id,
    )


_DIFF_LIMIT = 256 * 1024
_FILE_LIMIT = 1024 * 1024


def _relative_path(name: str) -> Path:
    return fs.relative(name)


def _read_file(source: fs.File) -> bytes:
    data = source.read(_FILE_LIMIT)
    _decode_source(data)
    return data


def _decode_source(data: bytes) -> tuple[list[str], str, bool, bytes]:
    bom = b"\xef\xbb\xbf" if data.startswith(b"\xef\xbb\xbf") else b""
    try:
        text = data[len(bom) :].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Unsupported source encoding; UTF-8 required") from None
    if "\x00" in text:
        raise ValueError("Binary source is unsupported")
    newline = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized or (newline == "\r\n" and text.count("\n") != text.count("\r\n")):
        raise ValueError("Mixed or unsupported source newlines")
    final_newline = normalized.endswith("\n")
    lines = normalized.split("\n")
    if final_newline:
        lines.pop()
    if not normalized:
        lines = []
    return lines, newline, final_newline, bom


def _check_diff_text(text: str) -> None:
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError("Unsupported diff encoding") from None
    if size > _DIFF_LIMIT:
        raise ValueError("Diff exceeds 256 KiB")
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        raise ValueError("Malformed diff text")
    if redact(text) != text or sanitize(text) != text or "[REDACTED]" in text:
        raise ValueError("Secret-bearing or redacted diff is not usable")


@dataclass
class _Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    entries: list[tuple[str, str, bool]]


def _parse_diff(diff_text: str) -> tuple[str, list[_Hunk]]:
    _check_diff_text(diff_text)
    lines = diff_text.replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) < 3 or not lines[0].startswith("--- a/") or not lines[1].startswith("+++ b/"):
        raise ValueError("Expected exactly one existing-file unified diff")
    target = lines[0][6:]
    _relative_path(target)
    if lines[1][6:] != target:
        raise ValueError("Adds, deletes and renames are unsupported")
    hunks: list[_Hunk] = []
    index = 2
    while index < len(lines):
        # Section labels are optional opaque data after the closing @@.
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?", lines[index])
        if match is None:
            raise ValueError("Malformed or multiple-file diff header")
        old_start, old_count = int(match[1]), int(match[2] or 1)
        new_start, new_count = int(match[3]), int(match[4] or 1)
        if (old_count and not old_start) or (new_count and not new_start):
            raise ValueError("Invalid hunk coordinates")
        index += 1
        entries: list[tuple[str, str, bool]] = []
        while index < len(lines) and not lines[index].startswith("@@"):
            value = lines[index]
            if value == "\\ No newline at end of file":
                if not entries or entries[-1][2]:
                    raise ValueError("Malformed no-newline marker")
                kind, text, _ = entries[-1]
                entries[-1] = (kind, text, True)
            elif value[:1] in (" ", "-", "+"):
                entries.append((value[0], value[1:], False))
            else:
                raise ValueError("Malformed diff context or unsupported patch metadata")
            index += 1
        if (
            sum(kind != "+" for kind, _, _ in entries) != old_count
            or sum(kind != "-" for kind, _, _ in entries) != new_count
            or not any(kind in ("-", "+") for kind, _, _ in entries)
        ):
            raise ValueError("Incorrect hunk counts or no patch changes")
        hunks.append(_Hunk(old_start, old_count, new_start, new_count, entries))
    if not hunks:
        raise ValueError("Diff has no hunks")
    return target, hunks


def _patched_bytes(before: bytes, hunks: list[_Hunk]) -> bytes:
    original, newline, final_newline, bom = _decode_source(before)
    patched: list[str] = []
    cursor = delta = 0
    previous_base = -1
    unterminated_new: int | None = None
    for hunk in hunks:
        base = hunk.old_start - 1 if hunk.old_count else hunk.old_start
        expected_new = base + delta + (1 if hunk.new_count else 0)
        if (
            base < cursor
            or base <= previous_base
            or base > len(original)
            or hunk.new_start != expected_new
        ):
            raise ValueError("Overlapping or inconsistent hunk coordinates")
        previous_base = base
        patched.extend(original[cursor:base])
        cursor = base
        for kind, text, no_newline in hunk.entries:
            if kind in (" ", "-"):
                if cursor >= len(original) or original[cursor] != text:
                    raise ValueError(f"Context or removal mismatch at line {cursor + 1}")
                if no_newline and (cursor != len(original) - 1 or final_newline):
                    raise ValueError("No-newline marker does not match original source")
                cursor += 1
            if kind in (" ", "+"):
                if no_newline and final_newline:
                    raise ValueError("Patch changes source newline convention")
                if unterminated_new is not None:
                    raise ValueError("No-newline marker describes an interior patched line")
                patched.append(text)
                if no_newline:
                    unterminated_new = len(patched) - 1
        delta += hunk.new_count - hunk.old_count
    patched.extend(original[cursor:])
    if unterminated_new is not None and unterminated_new != len(patched) - 1:
        raise ValueError("No-newline marker describes an interior patched line")
    after = bom + (newline.join(patched) + (newline if final_newline and patched else "")).encode(
        "utf-8"
    )
    if len(after) > _FILE_LIMIT:
        raise ValueError("Patched file exceeds 1 MiB")
    return after


def apply_unified_diff(repo_root: Path, diff_text: str) -> list[str]:
    """Preflight the complete diff, then patch through retained directory handles."""
    target, hunks = _parse_diff(diff_text)
    relative = _relative_path(target)
    root = fs.absolute(repo_root)
    try:
        with fs.directory(root) as directory, directory.descend(relative.parts[:-1]) as parent:
            temporary: fs.File | None = None
            try:
                with parent.file(relative.name) as source:
                    before = _read_file(source)
                    after = _patched_bytes(before, hunks)
                    mode = stat.S_IMODE(source.info().st_mode)
                    temporary = parent.file(".fix-" + uuid.uuid4().hex, create=True)
                    temporary.write(after)
                    temporary.mode(mode)
                    if _read_file(source) != before:
                        raise ValueError("Source changed during patch application")
                # Windows must release the source's deny-delete share before rename.
                parent.replace(temporary, relative.name)
                parent.attached()
            finally:
                if temporary is not None:
                    temporary.close()
                    parent.unlink(temporary.name)
    except OSError as exc:
        raise ValueError("Confined patch I/O failed") from exc
    return [target]


def prepare_overlay(
    checkout: str,
    file_path: str,
    overlay_root: Path,
    *,
    expected_sha256: str | None = None,
) -> Path:
    """Copy bounded source into a new attempt using held source/destination handles."""
    relative = _relative_path(file_path)
    source_root, destination_root = fs.absolute(Path(checkout)), fs.absolute(overlay_root)
    if destination_root.is_relative_to(source_root) or source_root.is_relative_to(destination_root):
        raise ValueError("Overlay root overlaps the pristine checkout")
    try:
        with ExitStack() as stack:
            source_directory = stack.enter_context(fs.directory(source_root))
            source_parent = stack.enter_context(source_directory.descend(relative.parts[:-1]))
            source = stack.enter_context(source_parent.file(relative.name))
            before = _read_file(source)
            if (
                expected_sha256 is not None
                and expected_sha256 != hashlib.sha256(before).hexdigest()
            ):
                raise ValueError("Recorded source hash does not match checkout")
            destination_parent = stack.enter_context(
                fs.directory(destination_root.parent, create=True)
            )
            attempt = stack.enter_context(
                destination_parent.child(destination_root.name, create=True, exclusive=True)
            )
            parent = stack.enter_context(attempt.descend(relative.parts[:-1], create=True))
            if _read_file(source) != before:
                raise ValueError("Source changed during overlay preparation")
            with parent.file(relative.name, create=True) as destination:
                destination.write(before)
                destination.mode(stat.S_IMODE(source.info().st_mode))
                if _read_file(source) != before or _read_file(destination) != before:
                    raise ValueError("Source changed during overlay preparation")
    except OSError as exc:
        raise ValueError("Confined overlay I/O failed") from exc
    return overlay_root


def _bundled_rule(rule_id: str) -> tuple[Path, str] | None:
    rules_dir = Path(__file__).resolve().parent.parent / "scanners/rules"
    for candidate in sorted(rules_dir.glob("*.yml")):
        for identity in re.findall(
            r"(?m)^\s*-\s+id:\s+([\w.-]+)\s*$", candidate.read_text(encoding="utf-8")
        ):
            # Accept only the exact bundled ID or its concrete Semgrep namespace.
            aliases = {identity}
            try:
                relative = candidate.relative_to(Path.cwd())
            except ValueError:
                relative = candidate
            for namespace in (relative, candidate):
                prefix = re.sub(
                    r"[^a-zA-Z0-9._-]", "", ".".join(namespace.parts[:-1]).lstrip("./").lstrip(".")
                )
                if prefix:
                    aliases.add(f"{prefix}.{identity}")
            if rule_id in aliases:
                return candidate, identity
    return None


def _matches_path(value: Any, target: Path, cwd: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    if not path.is_absolute():
        path = cwd / path
    return path.absolute() == target.absolute()


def _scan_results(
    result: CommandResult, target: Path, cwd: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if result.timed_out or result.returncode not in (0, 1):
        raise ValueError(f"Incomplete Semgrep process (exit {result.returncode})")
    try:
        data = json.loads(result.stdout)
    except ValueError:
        raise ValueError("Semgrep output is not JSON") from None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("results"), list)
        or data.get("errors") != []
    ):
        raise ValueError("Malformed or error Semgrep output")
    paths = data.get("paths")
    if not isinstance(paths, dict):
        raise TypeError("Semgrep analyzed-file coverage is missing")
    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or any(not isinstance(p, str) or not p for p in scanned):
        raise ValueError("Semgrep analyzed-file coverage is malformed")
    if not any(_matches_path(p, target, cwd) for p in scanned):
        raise ValueError("Semgrep did not analyze the target file")
    skipped = paths.get("skipped", [])
    if not isinstance(skipped, list) or any(
        not isinstance(p, dict)
        or not isinstance(p.get("path"), str)
        or not p["path"]
        or _matches_path(p["path"], target, cwd)
        for p in skipped
    ):
        raise ValueError("Semgrep skipped the target or returned malformed coverage")
    results = data["results"]
    for match in results:
        if (
            not isinstance(match, dict)
            or not isinstance(match.get("check_id"), str)
            or not _matches_path(match.get("path"), target, cwd)
            or not isinstance(match.get("start"), dict)
            or type(match["start"].get("line")) is not int
            or match["start"]["line"] < 1
        ):
            raise ValueError("Malformed or foreign-file Semgrep result")
    return data, results


def _tool_artifact(parent: fs.Directory, name: str, result: CommandResult) -> None:
    try:
        stdout = json.loads(result.stdout)
    except ValueError:
        stdout = result.stdout
    _write_artifact(
        parent,
        name,
        {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stdout": stdout,
            "stderr": result.stderr,
            "command": list(result.command),
            "duration_ms": result.duration_ms,
        },
    )


def _write_artifact(parent: fs.Directory, name: str, payload: dict[str, Any]) -> None:
    data = redact(json.dumps(sanitize(payload), ensure_ascii=False, sort_keys=True)).encode("utf-8")
    with parent.file(name, create=True) as file:
        file.write(data)


def verify_fixed(
    overlay: Path,
    file_path: str,
    rule_id: str,
    line: int | None,
    semgrep_bin: str = "semgrep",
    *,
    baseline: Path | None = None,
) -> dict[str, Any]:
    """Compare complete full-file exact-rule scans (FR-02/19; never FR-50 authority).

    ``baseline`` is the original copied file, or a root containing ``file_path``.
    ``line`` remains positional for compatibility; refires anywhere fail.
    Artifacts are sanitized and exclusive-created in a fresh verification folder.
    """
    verification = FixVerification(
        fixed=False, detail="Verification incomplete", outcome="incomplete", rule_id=rule_id
    )
    try:
        relative = _relative_path(file_path)
        overlay_path = fs.absolute(overlay)
        baseline_path = fs.absolute(baseline) if baseline is not None else None
        if baseline_path is None:
            verification.detail = "Reproducible baseline is required"
            return verification.model_dump()
        with ExitStack() as stack:
            patched_root = stack.enter_context(fs.directory(overlay_path))
            patched_parent = stack.enter_context(patched_root.descend(relative.parts[:-1]))
            patched_file = stack.enter_context(patched_parent.file(relative.name))
            patched = patched_parent.path / relative.name
            if baseline_path == Path(baseline_path.anchor):
                original_root = stack.enter_context(fs.directory(baseline_path))
                original_parent = stack.enter_context(original_root.descend(relative.parts[:-1]))
                original = original_parent.path / relative.name
            else:
                baseline_parent = stack.enter_context(fs.directory(baseline_path.parent))
                if baseline_parent.kind(baseline_path.name) == "directory":
                    original_root = stack.enter_context(baseline_parent.child(baseline_path.name))
                    original_parent = stack.enter_context(
                        original_root.descend(relative.parts[:-1])
                    )
                    original = original_parent.path / relative.name
                else:
                    original_parent, original = baseline_parent, baseline_path
            if original == patched:
                raise ValueError("Baseline and patched files must be separate")
            original_file = stack.enter_context(original_parent.file(original.name))
            before, after = _read_file(original_file), _read_file(patched_file)
            verification.baseline_sha256 = hashlib.sha256(before).hexdigest()
            verification.patched_sha256 = hashlib.sha256(after).hexdigest()
            bundled = _bundled_rule(rule_id)
            if bundled is None or language_from_extension(file_path) in _NO_RULE_LANGUAGES:
                verification.outcome = "unavailable"
                verification.detail = "Rule is not an exact supported bundled Semgrep rule"
                return verification.model_dump()
            rule_file, identity = bundled
            excluded = re.findall(
                r"(?m)^\s*-\s+id:\s+([\w.-]+)\s*$", rule_file.read_text(encoding="utf-8")
            )
            artifacts = stack.enter_context(patched_root.new_directory(".fix-verification-"))
            for stage, target, held_file, expected in (
                ("baseline", original, original_file, before),
                ("patched", patched, patched_file, after),
            ):
                argv = [
                    semgrep_bin,
                    "--metrics",
                    "off",
                    "--disable-version-check",
                    "--config",
                    str(rule_file),
                    "--no-rewrite-rule-ids",
                    "--no-git-ignore",
                    "--jobs",
                    "1",
                ]
                for other in excluded:
                    if other != identity:
                        argv.extend(["--exclude-rule", other])
                argv.extend(["--stdin-filename", str(target), "--json", "-"])
                artifact = artifacts.path / f"{stage}.json"
                if stage == "baseline":
                    verification.baseline_artifact = str(artifact)
                else:
                    verification.patched_artifact = str(artifact)
                try:
                    result = run_command(
                        argv, cwd=rule_file.parent, timeout=300, input_text=expected.decode("utf-8")
                    )
                except (ScanCancelled, KeyboardInterrupt):
                    _write_artifact(
                        artifacts, artifact.name, {"outcome": "cancelled", "command": argv}
                    )
                    raise
                _tool_artifact(artifacts, artifact.name, result)
                if result.returncode == 127:
                    verification.outcome = "unavailable"
                    verification.detail = "Semgrep executable is unavailable"
                    return verification.model_dump()
                data, matches = _scan_results(result, target, rule_file.parent)
                version = data.get("version")
                if not isinstance(version, str) or not version:
                    raise ValueError("Semgrep tool version is unavailable")
                if verification.tool_version is not None and version != verification.tool_version:
                    raise ValueError("Semgrep version changed between scans")
                verification.tool_version = version
                if _read_file(held_file) != expected:
                    raise ValueError("Source changed during verification")
                refires = [match for match in matches if match["check_id"] == identity]
                if stage == "baseline" and not refires:
                    raise ValueError("Baseline does not reproduce the exact rule")
                if stage == "patched" and refires:
                    verification.outcome = "failed"
                    verification.detail = (
                        "Exact rule refired in the patched file; human review required"
                    )
                    return verification.model_dump()
            if _read_file(original_file) != before or _read_file(patched_file) != after:
                raise ValueError("Source changed during verification")
            verification = verification.model_copy(update={"fixed": True, "outcome": "passed"})
            verification.detail = "Rule no longer fires; human review required"
    except (ScanCancelled, KeyboardInterrupt):
        verification.outcome = "cancelled"
        verification.detail = "Verification cancelled; retained partial artifacts"
    except (ValueError, TypeError, OSError) as exc:
        verification.outcome = "incomplete"
        verification.detail = redact(str(sanitize(str(exc))))
    return verification.model_dump()
