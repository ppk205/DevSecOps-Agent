"""The devsec-chat/1 stdio adapter and shared client message dispatcher."""

from __future__ import annotations

import json
import os
import sys
import threading
from io import TextIOWrapper
from pathlib import Path
from typing import Any, TextIO, cast

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.decisions.config import LayaConfig, load_config
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.credentials import redact_value

from .audit import SessionLog, new_session_path
from .gates import GateKeeper, refuse_all
from .host import MAX_LINE_BYTES, PROTOCOL, Emit, SessionHost, excluded_command_path
from .messages import Message, ProviderError, Reply, Usage
from .providers import all_profiles, make_transport
from .session import Session
from .tools import ToolContext
from .workspace import Workspace


class _FileTransport:
    # ponytail: test-only transport, remove if a recorded-HTTP fixture replaces it
    def __init__(self, path: Path, profile: ProviderProfile, model: str) -> None:
        if excluded_command_path(path):
            raise ValueError("invalid fake transport script")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.replies = payload if isinstance(payload, list) else payload["replies"]
        self.profile, self.model = profile, model

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> Reply:
        if not self.replies:
            raise ProviderError("fake transport script exhausted")
        item = self.replies.pop(0)
        if "error" in item:
            raise ProviderError(str(item["error"]))
        return Reply(
            Message.from_dict(item["message"]),
            Usage(**item.get("usage", {})),
            item.get("model", self.model),
            item.get("stop_reason", ""),
        )


def build_host(message: dict[str, Any], emit: Emit) -> SessionHost:
    """Construct a host; caller attaches a human relay before calling start()."""
    from vulnscan.infra.envfile import EnvFile

    from .models import resolve_model

    mode = message.get("mode", "ask")
    if mode not in {"ask", "auto"}:
        raise ValueError("mode must be ask or auto")
    target = Path(_string(message, "target"))
    if not target.is_dir():
        raise ValueError("target must be a directory")
    EnvFile().load_into_environ()
    if message.get("provider"):
        profile = all_profiles().get(_string(message, "provider"))
        if profile is None:
            raise ValueError("unknown provider")
        model = str(message.get("model") or profile.default_model or "")
        if not model:
            raise ValueError("a model id is required")
    else:
        profile, model = resolve_model(_string(message, "model"))
    fake = os.environ.get("DEVSEC_CHAT_FAKE_TRANSPORT")
    transport = (
        _FileTransport(Path(fake), profile, model) if fake else make_transport(profile, model)
    )
    resume = message.get("resume")
    if resume:
        path = Path(str(resume))
        if excluded_command_path(path) or path.suffix != ".jsonl" or not path.is_file():
            raise ValueError("invalid session log")
    else:
        root = Path(str(message.get("sessions_dir", ".devsec/sessions")))
        if excluded_command_path(root):
            raise ValueError("invalid session directory")
        path = new_session_path(root)
    log = SessionLog(path)
    config_path = Path(str(message.get("laya_config", "config/laya.json")))
    config = load_config(config_path) if config_path.is_file() else LayaConfig(timeout_seconds=300)
    gates = GateKeeper(refuse_all, log.append, person="tui", mode=mode, interactive=False)
    ctx = ToolContext(Workspace.open(target), gates, log, config)
    return SessionHost(
        Session(transport, ctx, budget=BudgetManager(total_usd=float(message.get("budget", 50)))),
        emit,
    )


def _string(message: dict[str, Any], key: str, *, empty: bool = False) -> str:
    value = message.get(key)
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise ValueError(f"{key} must be a string")
    return value


def _args(message: dict[str, Any]) -> list[str]:
    args = message.get("args", [])
    if isinstance(args, str):
        return args.split()
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise ValueError("args must be a list of strings")
    return args


class RPCController:
    """Route both stdio and authenticated HTTP messages to one SessionHost."""

    def __init__(self, emit: Emit, host: SessionHost | None = None) -> None:
        self.emit, self.host = emit, host
        self._prelude: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._detach: Any = None
        self.remote: Any = None

    def publish(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.host is not None:
            return self.host.publish(event)
        with self._lock:
            payload = redact_value({**event, "protocol": PROTOCOL, "seq": len(self._prelude) + 1})
            self._prelude.append(payload)
            self.emit(payload)
            return dict(payload)

    def handle(self, message: dict[str, Any], client_id: str = "tui") -> dict[str, Any]:
        try:
            if message.get("protocol") != PROTOCOL:
                raise ValueError("protocol must be devsec-chat/1")
            kind = _string(message, "type")
            if kind == "hello":
                from .models import list_models, models_event

                self.publish(models_event(list_models()))
                return {"ok": True}
            if kind in {"model_add", "model_remove", "model_key"}:
                return self._model_command(kind, message)
            if kind == "start":
                with self._lock:
                    if self.host is not None:
                        if self.host.started or self.host.busy:
                            raise ValueError("a session already exists")
                        return {"ok": self.host.start()}
                    self.host = build_host(message, self.emit)
                    self.host.seed_events(self._prelude)
                    self._detach = self.host.attach(client_id, "tui")
                    self.host.enable_pending()
                    return {"ok": self.host.start()}
            host = self.host
            if host is None:
                raise ValueError("start a session first")
            if kind == "permission_reply":
                result = host.reply(client_id, message)
                if not result["ok"]:
                    self.publish({"type": "error", "message": result["error"]})
                return result
            if kind == "interrupt":
                host.interrupt()
                return {"ok": True}
            if kind == "user_message":
                if not host.started:
                    raise ValueError("G0 approval is required before sending messages")
                return {"ok": host.submit(_string(message, "text"))}
            if kind == "command":
                name, args = _string(message, "name").lstrip("/"), _args(message)
                if name == "quit":
                    self.close()
                    return {"ok": True}
                if name == "remote":
                    self._remote(args)
                    return {"ok": True}
                if name == "pending":
                    if len(args) != 2 or args[0] not in {"review", "dismiss"}:
                        raise ValueError("usage: /pending review|dismiss <id>")
                    return {"ok": host.review_pending(args[1], dismiss=args[0] == "dismiss")}
                return {"ok": host.command(name, args, client_id)}
            raise ValueError("unknown message type")
        except Exception as exc:  # noqa: BLE001 - invalid client input must not kill the relay
            # Never echo model management arguments: a malformed key request
            # must not put the raw value into an error or session log.
            error = (
                "model operation failed"
                if str(message.get("type", "")).startswith("model_")
                else str(exc)
            )
            self.publish({"type": "error", "message": error})
            return cast(dict[str, Any], redact_value({"ok": False, "error": error}))

    def _model_command(self, kind: str, message: dict[str, Any]) -> dict[str, Any]:
        from .models import add_model, list_models, models_event, remove_model, set_key

        if self.host is not None and self.host.busy:
            raise ValueError("a turn is already running")
        alias = _string(message, "alias")
        if kind == "model_remove":
            remove_model(alias)
        elif kind == "model_key":
            set_key(alias, _string(message, "key"))
        else:
            models = message.get("models")
            if not isinstance(models, list) or not all(isinstance(m, str) for m in models):
                raise ValueError("models must be a list of strings")
            template, key = message.get("template"), message.get("key")
            if template is not None and not isinstance(template, str):
                raise ValueError("invalid template")
            if key is not None and not isinstance(key, str):
                raise ValueError("invalid key")
            add_model(
                alias,
                template,
                _string(message, "protocol_name")
                if "protocol_name" in message
                else _string(message, "model_protocol"),
                _string(message, "base_url"),
                models,
                key,
            )
        self.publish(models_event(list_models()))
        return {"ok": True}

    def _remote(self, args: list[str]) -> None:
        from .remote import RemoteServer

        if args not in [["on"], ["off"]]:
            raise ValueError("usage: /remote on|off")
        if self.remote is not None:
            self.remote.close()
            self.remote = None
        if args == ["off"]:
            self.publish({"type": "remote", "off": True})
        else:
            assert self.host is not None
            self.remote = RemoteServer(self.host)
            self.remote.start()
            self.publish({"type": "remote", "url": self.remote.url})

    def close(self) -> None:
        if self.remote is not None:
            self.remote.close()
            self.remote = None
        if self._detach is not None:
            self._detach()
            self._detach = None
        if self.host is not None:
            self.host.close()


def serve(stdin: TextIO, stdout: TextIO) -> int:
    lock = threading.Lock()

    def emit(event: dict[str, Any]) -> None:
        with lock:
            stdout.write(json.dumps(redact_value(event), ensure_ascii=False) + "\n")
            stdout.flush()

    controller = RPCController(emit)
    try:
        while True:
            line = stdin.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                while line and not line.endswith("\n"):
                    line = stdin.readline(MAX_LINE_BYTES + 1)
                controller.publish(
                    {"type": "error", "message": "line exceeds the 8 MiB protocol limit"}
                )
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise TypeError("message must be a JSON object")
            except (ValueError, TypeError):
                controller.publish({"type": "error", "message": "malformed JSON object"})
                continue
            controller.handle(message)
            if controller.host is not None and controller.host.closed:
                break
    except (OSError, KeyboardInterrupt):
        pass
    finally:
        controller.close()
    return 0


if __name__ == "__main__":
    if isinstance(sys.stdin, TextIOWrapper) and isinstance(sys.stdout, TextIOWrapper):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(serve(sys.stdin, sys.stdout))
