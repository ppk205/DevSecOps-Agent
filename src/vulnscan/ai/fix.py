"""AI-generated fix proposals for findings.

The model only writes a unified diff — it never touches source. Applying a
proposal copies the affected files into an overlay directory under artifacts,
patches the copy, and rescans the copy with the finding's rule to prove the
finding is gone. The user's checkout is never modified.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.profile_store import load_profile

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
    model: str


def build_fix_prompt(finding: dict[str, Any], code_context: str = "") -> str:
    """Render the user prompt for one finding dict (Finding dump).

    ``code_context`` is wider surrounding source from the local checkout.
    Without it the model reconstructs plausible-but-wrong context lines and
    the strict applier rightly rejects the patch.
    """
    section = ""
    if code_context.strip():
        section = (
            "Full surrounding code for exact context lines:\n```\n"
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
) -> FixProposal:
    """Ask the model for a unified diff fixing one finding."""
    profile = load_profile(profile_id)
    client = ProviderClient(profile)
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
    return FixProposal(
        finding_id=str(finding.get("finding_id", "")),
        file_path=str(obs.get("location", {}).get("file_path", "")),
        diff_text=diff,
        model=str(model or profile.default_model or profile.id),
    )


def apply_unified_diff(repo_root: Path, diff_text: str) -> list[str]:
    """Apply a unified diff to files under repo_root (pure Python).

    Only supports single-file `--- a/x` / `+++ b/x` hunks with context,
    which is what the fix prompt requests. Raises ValueError on anything
    unexpected instead of guessing.
    """
    lines = diff_text.splitlines()
    target: str | None = None
    hunks: list[tuple[int, int, list[str]]] = []
    current: list[str] | None = None
    old_start = new_start = 0
    for line in lines:
        if line.startswith("--- a/"):
            continue
        if line.startswith("+++ b/"):
            target = line[len("+++ b/") :].strip()
            continue
        match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if match:
            if current is not None:
                hunks.append((old_start, new_start, current))
            old_start, new_start = int(match.group(1)), int(match.group(2))
            current = []
            continue
        if current is not None and line[:1] in (" ", "-", "+", "\\"):
            if line.startswith("\\"):
                continue
            current.append(line)
    if current is not None:
        hunks.append((old_start, new_start, current))
    if not target or not hunks:
        raise ValueError("Diff has no target file or hunks")
    if ".." in Path(target).parts or Path(target).is_absolute():
        raise ValueError("Diff target escapes the overlay")
    path = repo_root / target
    original = path.read_text(encoding="utf-8").splitlines()
    patched: list[str] = []
    cursor = 0
    for start, _new_start, hunk in hunks:
        base = start - 1
        if base < cursor:
            raise ValueError("Overlapping hunks")
        patched.extend(original[cursor:base])
        cursor = base
        for hline in hunk:
            kind, text = hline[0], hline[1:]
            if kind == " ":
                if cursor >= len(original) or original[cursor] != text:
                    raise ValueError(f"Context mismatch at line {cursor + 1}")
                patched.append(original[cursor])
                cursor += 1
            elif kind == "-":
                if cursor >= len(original) or original[cursor] != text:
                    raise ValueError(f"Removal mismatch at line {cursor + 1}")
                cursor += 1
            elif kind == "+":
                patched.append(text)
            else:
                raise ValueError(f"Unknown hunk prefix {kind!r}")
    patched.extend(original[cursor:])
    path.write_text("\n".join(patched) + "\n", encoding="utf-8")
    return [target]


def verify_fixed(
    overlay: Path,
    file_path: str,
    rule_id: str,
    line: int | None,
    semgrep_bin: str = "semgrep",
) -> dict[str, Any]:
    """Rescan the patched file with the bundled rules; the finding must be gone.

    Returns {fixed: bool, detail: str}. A refire of the same rule at the same
    location means the patch did not fix it.
    """
    import json as _json

    rules_dir = Path(__file__).resolve().parent.parent / "scanners" / "rules"
    rule_file = None
    for candidate in sorted(rules_dir.glob("*.yml")):
        text = candidate.read_text(encoding="utf-8")
        if re.search(rf"(?m)^\s*-\s+id:\s+{re.escape(rule_id)}\s*$", text):
            rule_file = candidate
            break
    if rule_file is None:
        return {"fixed": False, "detail": f"rule {rule_id} not in bundled rules"}
    proc = subprocess.run(
        [
            semgrep_bin,
            "--metrics",
            "off",
            "--disable-version-check",
            "--config",
            str(rule_file),
            "--json",
            str(overlay / file_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode not in (0, 1, 2, 7):
        return {"fixed": False, "detail": f"semgrep exit {proc.returncode}"}
    try:
        data = _json.loads(proc.stdout or "{}")
    except ValueError:
        return {"fixed": False, "detail": "semgrep output not JSON"}
    refires = [
        r
        for r in data.get("results", [])
        if r.get("check_id", "").endswith(rule_id)
        and (line is None or r.get("start", {}).get("line") == line)
    ]
    if refires:
        return {
            "fixed": False,
            "detail": f"rule refired at {[r.get('start', {}) for r in refires]}",
        }
    return {"fixed": True, "detail": "rule no longer fires on the patched file"}


def prepare_overlay(checkout: str, file_path: str, overlay_root: Path) -> Path:
    """Copy the affected file into an overlay dir (never touches checkout)."""
    src = Path(checkout) / file_path
    if ".." in Path(file_path).parts or not src.is_file():
        raise ValueError("Finding file is not inside the checkout")
    overlay_root.mkdir(parents=True, exist_ok=True)
    dest = overlay_root / file_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return overlay_root
