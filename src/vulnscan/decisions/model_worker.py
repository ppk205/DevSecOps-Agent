"""Laya-only child runtime. Its stdout is exclusively versioned JSON-lines."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from vulnscan.core.stdio_worker import MAX_MESSAGE_BYTES, PROTOCOL_VERSION


def load_checkpoint(model_id: str, revision: str | None, device: str) -> tuple[Any, str]:
    laya = importlib.import_module("laya")
    root = Path(model_id)
    if root.is_dir():
        digest = hashlib.sha256()
        for file in sorted(root.rglob("*")):
            if file.is_file() and file.suffix in {".json", ".safetensors"}:
                digest.update(file.relative_to(root).as_posix().encode())
                with file.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
        identity = "sha256:" + digest.hexdigest()
    else:
        hub = importlib.import_module("huggingface_hub")
        root = Path(hub.snapshot_download(repo_id=model_id, revision=revision))
        identity = root.name
    # Laya ~0.4B (ModernBERT-large + heads) fits any modern CPU; a 4GB laptop
    # GPU OOMs on the forward pass and silently falls back to CPU anyway, so
    # pin CPU and spend the budget on a warm worker instead of VRAM roulette.
    agent = laya.load(str(root), device="cpu")
    return agent, identity


def main() -> None:
    agent: Any = None
    key: tuple[str, str | None, str] | None = None
    identity = ""
    while True:
        line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            break
        response: dict[str, Any] = {"version": PROTOCOL_VERSION, "id": None, "ok": False}
        try:
            if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                raise ValueError("request exceeds message limit")
            request = json.loads(line)
            response["id"] = request["id"]
            if request["version"] != PROTOCOL_VERSION or request["method"] != "predict_batch":
                raise ValueError("unsupported model worker request")
            params = request["params"]
            current = (str(params["model_id"]), params.get("revision"), str(params["device"]))
            with redirect_stdout(sys.stderr):
                if current != key:
                    if agent is not None:
                        agent.__exit__(None, None, None)
                    agent, identity = load_checkpoint(*current)
                    key = current
                raw = agent.predict_batch(
                    params["states"],
                    params["questions"],
                    batch_size=len(params["states"]),
                    max_len=int(params["max_input_tokens"]),
                )
            response.update(
                ok=True,
                result={
                    "rows": raw,
                    "model_id": current[0],
                    "model_revision": identity,
                    "device": str(getattr(agent, "device", "unknown")),
                },
            )
        except Exception as exc:  # noqa: BLE001 - model process boundary
            response["error"] = {
                "code": "dependency_unavailable"
                if isinstance(exc, ImportError)
                else "backend_unavailable",
                "message": str(exc)[:1024],
            }
        encoded = json.dumps(response).encode() + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            encoded = (
                json.dumps(
                    {
                        "version": PROTOCOL_VERSION,
                        "id": response["id"],
                        "ok": False,
                        "error": {"message": "response exceeds message limit"},
                    }
                ).encode()
                + b"\n"
            )
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
