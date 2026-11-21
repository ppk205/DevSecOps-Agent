"""Runtime con chỉ dành cho Laya. stdout của nó hoàn toàn là các dòng JSON có phiên bản."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from vulnscan.core.stdio_worker import MAX_MESSAGE_BYTES, PROTOCOL_VERSION


def _device_candidates(requested: str) -> tuple[str, ...]:
    """Probe accelerators in the interpreter that will run inference."""
    requested = requested.strip().lower()
    accelerators = ("cuda", "vulkan")
    if requested not in (*accelerators, "auto"):
        return ("cpu",)
    try:
        torch = importlib.import_module("torch")
    except (ImportError, OSError, RuntimeError):
        return ("cpu",)
    available = []
    for device in accelerators if requested == "auto" else (requested,):
        try:
            probe = torch.cuda.is_available if device == "cuda" else torch.is_vulkan_available
            if probe():
                available.append(device)
        except (AttributeError, OSError, RuntimeError):
            continue
    return (*available, "cpu")


def _checkpoint(model_id: str, revision: str | None) -> tuple[Path, str]:
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
    return root, identity


def _on_cpu(agent: Any) -> bool:
    return str(agent.device).split(":", 1)[0] == "cpu"


def _load_agent(laya: Any, root: Path, devices: tuple[str, ...]) -> tuple[Any, tuple[str, ...]]:
    for index, device in enumerate(devices):
        remaining = devices[index + 1 :]
        try:
            agent = laya.load(str(root), device=device)
        except Exception:
            if not remaining:
                raise
            continue
        if not _on_cpu(agent):
            return agent, remaining
        if "vulkan" not in remaining:
            return agent, ()
        # Laya can fall back to CPU inside load(). Give Vulkan its turn first.
        agent.__exit__(None, None, None)
    raise RuntimeError("no Laya device could load the checkpoint")


def main() -> None:
    agent: Any = None
    laya: Any = None
    root = Path()
    remaining: tuple[str, ...] = ()
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
                if current != key or agent is None:
                    if agent is not None:
                        agent.__exit__(None, None, None)
                        agent = None
                    laya = importlib.import_module("laya")
                    root, identity = _checkpoint(*current[:2])
                    agent, remaining = _load_agent(laya, root, _device_candidates(current[2]))
                    key = current
                while True:
                    try:
                        raw = agent.predict_batch(
                            params["states"],
                            params["questions"],
                            batch_size=len(params["states"]),
                            max_len=int(params["max_input_tokens"]),
                        )
                    except RuntimeError:
                        if not remaining or (_on_cpu(agent) and "vulkan" not in remaining):
                            raise
                    else:
                        if "vulkan" not in remaining or not _on_cpu(agent):
                            break
                    agent.__exit__(None, None, None)
                    agent = None
                    agent, remaining = _load_agent(laya, root, remaining)
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
