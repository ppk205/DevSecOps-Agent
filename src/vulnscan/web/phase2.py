"""Các helper Phase 2: tools, settings, keys, usage, scans (lớp mỏng trên services).

Khóa CHỈ được lưu qua cơ chế ``.env`` cục bộ của dự án
(:class:`vulnscan.infra.envfile.EnvFile`) cùng với profile ``.providers/*.json``
(:mod:`vulnscan.providers.profile_store`). Secret không bao giờ được trả về —
chỉ trả về chuỗi hiển thị đã che ``••••`` + 4 ký tự cuối.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from vulnscan.infra.envfile import EnvFile, find_project_root

BUDGET_TOTAL_USD = 50.0

_SETTINGS_FILENAME = ".pitwall-settings.json"

_GENERAL_DEFAULTS: dict[str, Any] = {
    "timezone": "Asia/Saigon",
    "timeout": 600,
    "max_files": 100000,
    "output_dir": "artifacts",
    "fail_on": "high",
    "profile": "fast",
}

_GENERAL_FIELDS = set(_GENERAL_DEFAULTS)


def settings_path() -> Path:
    return find_project_root() / _SETTINGS_FILENAME


def load_general_settings() -> dict[str, Any]:
    merged = dict(_GENERAL_DEFAULTS)
    path = settings_path()
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return merged
        if isinstance(payload, dict):
            for key in _GENERAL_FIELDS:
                if key in payload:
                    merged[key] = payload[key]
    return merged


def save_general_settings(patch: dict[str, Any]) -> dict[str, Any]:
    merged = load_general_settings()
    for key, value in patch.items():
        if key not in _GENERAL_FIELDS:
            raise ValueError(f"Unknown settings field: {key}")
        merged[key] = value
    _validate_general_settings(merged)
    path = settings_path()
    path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def _validate_general_settings(values: dict[str, Any]) -> None:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        ZoneInfo(str(values.get("timezone", "Asia/Saigon")))
    except ZoneInfoNotFoundError as exc:
        raise ValueError("unknown display timezone") from exc
    timeout = values.get("timeout")
    if not isinstance(timeout, int) or not 1 <= timeout <= 86400:
        raise ValueError("timeout must be an int in 1..86400")
    max_files = values.get("max_files")
    if not isinstance(max_files, int) or max_files < 1:
        raise ValueError("max_files must be a positive int")
    if str(values.get("fail_on")) not in {"critical", "high", "medium", "low", "info", "none"}:
        raise ValueError("fail_on must be critical|high|medium|low|info|none")
    if str(values.get("profile")) not in {"fast", "full"}:
        raise ValueError("profile must be fast|full")
    if not str(values.get("output_dir", "")).strip():
        raise ValueError("output_dir must not be empty")


def mask_key(value: str) -> str:
    """Hiển thị dạng che: ``••••`` + 4 ký tự cuối. Không bao giờ là chính secret."""
    if not value or not value.strip():
        return ""
    stripped = value.strip()
    if len(stripped) <= 4:
        return "••••"
    return "••••" + stripped[-4:]


def key_value(env_name: str, env: EnvFile | None = None) -> str:
    live = os.environ.get(env_name, "").strip()
    if live:
        return live
    store = env or EnvFile()
    return (store.get(env_name) or "").strip()


def key_status(env_name: str, env: EnvFile | None = None) -> dict[str, Any]:
    value = key_value(env_name, env)
    return {"configured": bool(value), "masked": mask_key(value) if value else ""}


def unset_key(env_name: str, env: EnvFile | None = None) -> bool:
    store = env or EnvFile()
    path = Path(store.path)
    if not path.is_file():
        return False
    target = env_name.strip().upper()
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [ln for ln in lines if ln.strip().upper().split("=", 1)[0].strip() != target]
    if len(kept) == len(lines):
        return False
    path.write_text("".join(kept), encoding="utf-8")
    return True


def _scanner_image_present() -> bool:
    """True when Docker has the image for isolated Dependency-Check."""
    from vulnscan.infra.full_scan import IMAGE
    from vulnscan.scanners.process import run_command

    try:
        return run_command(["docker", "image", "inspect", IMAGE], timeout=10).succeeded
    except OSError:
        return False


def probe_tools(with_versions: bool = False) -> list[dict[str, Any]]:
    """Fast tool health: ``which`` on PATH; versions only when asked.

    Dependency-Check also counts as available when Docker has the
    scanner image, because full-profile scans run them in that container.
    """
    from vulnscan.scanners.base import AdapterRegistry
    from vulnscan.scanners.platform import which

    registry = AdapterRegistry.default()
    order = ["semgrep", "native-hunt", "gitleaks", "trivy", "owasp-dependency-check", "codeql"]
    out: list[dict[str, Any]] = []
    image: bool | None = None
    for name in order:
        adapter = registry.get(name)
        if adapter is None:
            continue
        binary = adapter.binary_name
        if name == "native-hunt":
            capability = adapter.capabilities()
            out.append(
                {
                    "tool": name,
                    "binary": binary,
                    "path": None,
                    "available": capability.available,
                    "version": capability.version if with_versions else None,
                    "hint": capability.reason,
                }
            )
            continue
        resolved = which(binary)
        version: str | None = None
        if resolved is None and name == "owasp-dependency-check" and which("docker"):
            if image is None:
                image = _scanner_image_present()
            if image:
                from vulnscan.infra.full_scan import IMAGE

                out.append(
                    {
                        "tool": name,
                        "binary": binary,
                        "path": f"docker:{IMAGE}",
                        "available": True,
                        "version": None,
                        "hint": f"Runs in the {IMAGE} container for full profile scans",
                    }
                )
                continue
        if resolved is not None and with_versions:
            try:
                from vulnscan.scanners.tool_versions import probe_version

                version = probe_version(binary)
            except OSError:
                version = None
        out.append(
            {
                "tool": name,
                "binary": binary,
                "path": resolved,
                "available": resolved is not None,
                "version": version,
                "hint": None
                if resolved
                else (
                    "Install dependency-check on PATH; OSV.dev covers manifests meanwhile"
                    if name == "owasp-dependency-check"
                    else f"Install {binary} on PATH"
                ),
            }
        )
    return out


def aggregate_usage(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Tính tổng các tóm tắt ``ai_usage`` được lưu trong các blob kết quả lượt chạy."""
    total_spent = 0.0
    by_provider: dict[str, float] = {}
    for snapshot in runs:
        usage = snapshot.get("ai_usage") or {}
        if not isinstance(usage, dict):
            continue
        spent = usage.get("total_spent")
        try:
            total_spent += float(spent or 0.0)
        except (TypeError, ValueError):
            pass
        for key, value in usage.items():
            if key.startswith("spent_"):
                provider = key[len("spent_") :]
                try:
                    by_provider[provider] = by_provider.get(provider, 0.0) + float(value or 0.0)
                except (TypeError, ValueError):
                    continue
    total_spent = round(total_spent, 6)
    available = round(max(0.0, BUDGET_TOTAL_USD - total_spent), 6)
    return {
        "total_budget": BUDGET_TOTAL_USD,
        "total_spent": total_spent,
        "available": available,
        "by_provider": by_provider,
    }
