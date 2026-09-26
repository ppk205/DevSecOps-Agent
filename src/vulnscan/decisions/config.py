"""Load and validate the optional Laya runtime configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_TRUE_MODES = {"shadow", "advisory", "off"}
_FALSE_MODES = {"off", "disabled"}


@dataclass(frozen=True)
class LayaConfig:
    """Validated Laya settings; defaults keep the baseline behaviour intact."""

    enabled: bool = False
    mode: str = "shadow"
    model_id: str = "convaiinnovations/laya"
    revision: str | None = None
    device: str = "auto"
    batch_size: int = 4
    max_input_tokens: int = 512
    timeout_seconds: int = 30
    cache_enabled: bool = True
    high_confidence_threshold: float = 0.85
    review_threshold: float = 0.60
    affects_finding_status: bool = False

    def validate(self) -> None:
        """Reject configurations that could grant Laya status authority."""
        if self.mode not in _TRUE_MODES | _FALSE_MODES:
            raise ValueError(f"unsupported Laya mode: {self.mode!r}")
        if self.batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if self.max_input_tokens < 1:
            raise ValueError("max_input_tokens must be >= 1")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if not 0.0 <= self.review_threshold <= self.high_confidence_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= review <= high <= 1")
        if self.affects_finding_status:
            raise ValueError("Laya must never own finding status (affects_finding_status)")


def load_config(path: str | Path | None = None) -> LayaConfig:
    """Load config from JSON; a missing file yields the safe defaults."""
    if path is None:
        return LayaConfig()
    file = Path(path)
    if not file.exists():
        return LayaConfig()
    raw = json.loads(file.read_text(encoding="utf-8"))
    config = LayaConfig(
        enabled=bool(raw.get("enabled", False)),
        mode=str(raw.get("mode", "shadow")),
        model_id=str(raw.get("model_id", "convaiinnovations/laya")),
        revision=raw.get("revision") or None,
        device=str(raw.get("device", "auto")),
        batch_size=int(raw.get("batch_size", 4)),
        max_input_tokens=int(raw.get("max_input_tokens", 512)),
        timeout_seconds=int(raw.get("timeout_seconds", 30)),
        cache_enabled=bool(raw.get("cache_enabled", True)),
        high_confidence_threshold=float(raw.get("high_confidence_threshold", 0.85)),
        review_threshold=float(raw.get("review_threshold", 0.60)),
        affects_finding_status=bool(raw.get("affects_finding_status", False)),
    )
    config.validate()
    return config
