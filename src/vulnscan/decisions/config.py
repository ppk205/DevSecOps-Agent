"""Load and validate the optional Laya runtime configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from vulnscan.decisions.protocol import (
    HIGH_CONFIDENCE_THRESHOLD,
    MAX_INPUT_TOKENS,
    MODEL_ID,
    MODEL_REVISION,
    REVIEW_THRESHOLD,
)

_TRUE_MODES = {"shadow", "advisory", "off"}
_FALSE_MODES = {"off", "disabled"}


def _import_torch() -> bool:
    """Import torch lazily; unit tests must never require the heavy dep."""
    try:
        import torch  # noqa: F401
    except ImportError:
        return False
    return True


def _torch_cuda_ok() -> bool:
    """True only when CUDA is importable *and* a device answers."""
    try:
        import torch

        return bool(torch.cuda.is_available())
    except (ImportError, RuntimeError):
        return False


@dataclass(frozen=True)
class LayaConfig:
    """Validated Laya settings; defaults keep the baseline behaviour intact."""

    enabled: bool = False
    mode: str = "shadow"
    model_id: str = MODEL_ID
    revision: str | None = MODEL_REVISION
    device: str = "auto"
    batch_size: int = 1
    max_input_tokens: int = MAX_INPUT_TOKENS
    timeout_seconds: int = 300
    cache_enabled: bool = True
    high_confidence_threshold: float = HIGH_CONFIDENCE_THRESHOLD
    review_threshold: float = REVIEW_THRESHOLD
    affects_finding_status: bool = False

    def validate(self) -> None:
        """Reject configurations that could grant Laya status authority."""
        if self.mode not in _TRUE_MODES | _FALSE_MODES:
            raise ValueError(f"unsupported Laya mode: {self.mode!r}")
        if self.device not in {"auto", "cuda", "cpu"}:
            raise ValueError("device must be one of: auto, cuda, cpu")
        if self.device == "cuda":
            _import_torch()
            if not _torch_cuda_ok():
                raise ValueError("device 'cuda' requested but torch.cuda is unavailable")
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
        model_id=str(raw.get("model_id", MODEL_ID)),
        revision=raw.get("revision") or None,
        device=str(raw.get("device", "auto")),
        batch_size=int(raw.get("batch_size", 4)),
        max_input_tokens=int(raw.get("max_input_tokens", MAX_INPUT_TOKENS)),
        timeout_seconds=int(raw.get("timeout_seconds", 30)),
        cache_enabled=bool(raw.get("cache_enabled", True)),
        high_confidence_threshold=float(
            raw.get("high_confidence_threshold", HIGH_CONFIDENCE_THRESHOLD)
        ),
        review_threshold=float(raw.get("review_threshold", REVIEW_THRESHOLD)),
        affects_finding_status=bool(raw.get("affects_finding_status", False)),
    )
    config.validate()
    return config
