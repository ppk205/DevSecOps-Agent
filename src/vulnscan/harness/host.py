"""Single-owner session host, durable events and human client gate replies."""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import uuid
from collections.abc import Callable
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Literal, cast

from vulnscan.providers.credentials import redact_value

from .audit import SessionLog
from .gates import (
    CHOICES,
    DANGEROUS,
    Asker,
    Gate,
    GateDecision,
    GateKeeper,
    GateRequest,
    refuse_all,
)
from .messages import Message
from .providers import is_local
from .session import Session

PROTOCOL = "devsec-chat/1"
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_MEMORY_EVENTS = 5000
PENDING_PROMPT = (
    "Review the changes in {ref}: {files}. Start with propose_scan_plan limited to these files."
)
Emit = Callable[[dict[str, Any]], None]


def _decision(request: GateRequest, reply: dict[str, Any]) -> GateDecision:
    choice = reply.get("choice")
    reason = reply.get("reason", "")
    edits = reply.get("edits", {})
    if not isinstance(choice, str) or choice not in (*CHOICES[request.gate], "undecided"):
        choice, reason = "undecided", "invalid choice"
    if not isinstance(edits, dict):
        choice, reason, edits = "undecided", "edits must be a JSON object", {}
    if not isinstance(reason, str):
        choice, reason = "undecided", "reason must be a string"
    return GateDecision(request.gate, choice, reason, edits, str(reply.get("person", "")))


def bridge_asker(emit: Emit, replies: queue.Queue[dict[str, Any] | None]) -> Asker:
    """Emit a request and wait for its matching reply; shutdown never approves."""

    def ask(request: GateRequest) -> GateDecision:
        request_id = str(uuid.uuid4())
        try:
            emit(
                {
                    "type": "permission_request",
                    "request_id": request_id,
                    "gate": request.gate.value,
                    "title": request.title,
                    "detail": request.detail,
                    "payload": request.payload,
                    "ai_recommendation": request.ai_recommendation,
                    "mode": "ask",
                    "dangerous": request.gate in DANGEROUS,
                    "choices": list(CHOICES[request.gate]),
                }
            )
            while True:
                reply = replies.get()
                if reply is None:
                    return GateDecision(request.gate, "undecided", "prompt closed")
                if reply.get("request_id") == request_id:
                    return _decision(request, reply)
        except Exception:  # noqa: BLE001 - a broken relay must leave the gate undecided
            return GateDecision(request.gate, "undecided", "prompt failed")

    return ask


def ready_event(session: Session) -> dict[str, Any]:
    ws, transport = session.ctx.ws, session.transport
    return {
        "type": "ready",
        "target": str(ws.target),
        "commit": ws.commit,
        "dirty": ws.dirty,
        "provider": transport.profile.id,
        "model": transport.model,
        "mode": session.ctx.gates.mode,
        "local": is_local(transport.profile),
        "session_log": str(session.ctx.log.path.resolve()),
    }


class SessionHost:
    """Own one worker, serialize replies, and retain all events in the audit log."""

    def __init__(self, session: Session, emit: Emit) -> None:
        self.session, self.emit = session, emit
        self._lock = session.ctx.log.lock
        self._busy = False
        self._closed = False
        self._audit_error = False
        self.started = False
        self._idle = threading.Event()
        self._idle.set()
        self._stop = threading.Event()
        self._clients: dict[str, tuple[str, int]] = {}
        self._listeners: list[Emit] = []
        self._pending: dict[str, Any] | None = None
        self._answered: dict[str, str] = {}
        self._replies: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._usage: dict[str, Any] | None = None
        self._remaining_tools: set[str] = set()
        self._review_store: Path | None = None
        self._reviews: list[dict[str, Any]] = []
        self._watcher: Any = None
        self._monitor: threading.Thread | None = None
        self._thread: threading.Thread | None = None
        self._events: list[dict[str, Any]] = []
        self._seq = 0
        self._original_asker = session.ctx.gates.asker
        self._use_bridge = self._original_asker is refuse_all
        self._totals = session.ctx.log.totals()
        for record in session.ctx.log.events():
            if record.get("type") == "host_event" and isinstance(record.get("event"), dict):
                event = record["event"]
                self._seq = max(self._seq, int(event["seq"]))
                self._events.append(event)
                if event["type"] == "gate_result" and event.get("request_id"):
                    self._answered[event["request_id"]] = event.get("person", "previous client")
        self._events = self._events[-MAX_MEMORY_EVENTS:]
        self._unsubscribe = session.ctx.log.subscribe(self._on_log)
        session.ctx.gates.asker = self._ask
        session.ctx.gates.record = self._record_gate
        session.ctx.gates.interactive = False
        self._recover_pending()

    def _recover_pending(self) -> None:
        """A crashed worker cannot continue its gate: record it as undecided."""
        pending: dict[str, dict[str, Any]] = {}
        for record in self.session.ctx.log.events():
            if record.get("type") == "host_event":
                event = record["event"]
                if event["type"] == "permission_request":
                    pending[event["request_id"]] = event
                elif event["type"] == "gate_result":
                    pending.pop(event.get("request_id", ""), None)
            elif record.get("type") == "gate":
                pending.pop(record.get("request_id", ""), None)
        for event in pending.values():
            self._pending = event
            keeper = GateKeeper(
                lambda req: GateDecision(req.gate, "undecided", "host restarted"),
                self._record_gate,
                person="host",
                mode="ask",
            )
            keeper.ask(
                GateRequest(
                    Gate(event["gate"]),
                    event["title"],
                    event["detail"],
                    event["payload"],
                    event.get("ai_recommendation", ""),
                )
            )

    def publish(self, event: dict[str, Any]) -> dict[str, Any]:
        """Persist before delivering, with a monotonically increasing sequence."""
        with self._lock:
            payload = redact_value(deepcopy(event))
            payload.update(protocol=PROTOCOL, seq=self._seq + 1)
            if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) + 1 > MAX_LINE_BYTES:
                payload = {
                    "type": "error",
                    "message": "event exceeds the 8 MiB protocol limit",
                    "protocol": PROTOCOL,
                    "seq": self._seq + 1,
                }
                self.interrupt()
            if not self._audit_error:
                try:
                    self.session.ctx.log.append({"type": "host_event", "event": payload})
                except OSError:
                    self._audit_error = True
                    self._closed = True
                    self._stop.set()
                    self.interrupt()
                    payload = {
                        "type": "error",
                        "message": "audit log unavailable; session stopped",
                        "seq": self._seq + 1,
                        "protocol": PROTOCOL,
                        "persisted": False,
                    }
            else:
                payload["persisted"] = False
                if payload["type"] == "done":
                    payload["reason"] = "failed"
            self._seq += 1
            self._events.append(payload)
            self._events = self._events[-MAX_MEMORY_EVENTS:]
            try:
                self.emit(deepcopy(payload))
            except (OSError, ValueError):
                self.interrupt()
            for listener in tuple(self._listeners):
                listener(deepcopy(payload))
            return deepcopy(payload)

    def subscribe(self, listener: Emit) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def events(self) -> list[dict[str, Any]]:
        return self.events_after(0)

    def events_after(self, seq: int) -> list[dict[str, Any]]:
        with self._lock:
            if not self._events or seq >= self._events[0]["seq"] - 1:
                events = self._events
            else:
                events = [
                    record["event"]
                    for record in self.session.ctx.log.events()
                    if record.get("type") == "host_event"
                ]
            return cast(
                list[dict[str, Any]],
                redact_value(deepcopy([event for event in events if event["seq"] > seq])),
            )

    def state(self) -> dict[str, Any]:
        with self._lock:
            return cast(
                dict[str, Any],
                redact_value(
                    {
                        "ready": ready_event(self.session),
                        "pending": deepcopy(self._pending),
                        "totals": dict(self._totals),
                        "seq": self._seq,
                        "busy": self._busy,
                        "started": self.started,
                        "messages": [m.to_dict() for m in self.session.messages],
                        "pending_reviews": deepcopy(self._reviews),
                    }
                ),
            )

    def _flush_usage(self) -> None:
        if self._usage is not None:
            event, self._usage = self._usage, None
            self.publish(event)

    def _on_log(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "usage":
            self._flush_usage()
            for key in ("input_tokens", "output_tokens", "cost_usd"):
                self._totals[key] += event.get(key) or 0
            self._totals["turns"] += 1
            self._usage = {
                **event,
                "total_tokens": int(self._totals["input_tokens"] + self._totals["output_tokens"]),
                "total_cost_usd": self._totals["cost_usd"],
            }
        elif kind == "message":
            message = event["message"]
            if message["role"] == "user":
                self.publish(
                    {"type": "text_delta", "role": "user", "text": message.get("content", "")}
                )
            elif message["role"] == "assistant":
                if message.get("content"):
                    self.publish(
                        {"type": "text_delta", "role": "assistant", "text": message["content"]}
                    )
                calls = message.get("tool_calls") or []
                self._remaining_tools = {call["id"] for call in calls}
                for call in calls:
                    self.publish({"type": "tool_call", **call})
                if not calls:
                    self._flush_usage()
            elif message["role"] == "tool":
                content = message.get("content", "")
                try:
                    result = json.loads(content)
                except ValueError:
                    result = content
                self.publish(
                    {
                        "type": "tool_result",
                        "id": message.get("tool_call_id"),
                        "name": message.get("name"),
                        "summary": " ".join(content.split())[:120],
                        "result": result,
                    }
                )
                self._remaining_tools.discard(message.get("tool_call_id"))
                if not self._remaining_tools:
                    self._flush_usage()
        elif kind == "gate":
            self.publish(
                {
                    "type": "gate_result",
                    **{
                        key: event.get(key, "")
                        for key in ("request_id", "gate", "choice", "reason", "person")
                    },
                    "mode": self.session.ctx.gates.mode,
                }
            )
        elif kind == "error":
            self.publish({"type": "error", "message": event.get("error", "session failed")})

    def attach(self, client_id: str, kind: Literal["tui", "web"]) -> Callable[[], None]:
        with self._lock:
            if self._closed or kind not in {"tui", "web"} or not client_id:
                raise ValueError("cannot attach client")
            previous = self._clients.get(client_id)
            if previous is not None and previous[0] != kind:
                raise ValueError("client kind cannot change")
            self._clients[client_id] = (kind, 1 + (previous[1] if previous else 0))
            self._use_bridge = True
            self.session.ctx.gates.interactive = True
        detached = False

        def detach() -> None:
            nonlocal detached
            with self._lock:
                if detached:
                    return
                detached = True
                current = self._clients.get(client_id)
                if current and current[1] > 1:
                    self._clients[client_id] = (kind, current[1] - 1)
                else:
                    self._clients.pop(client_id, None)
                self.session.ctx.gates.interactive = bool(self._clients)
                if not self._clients:
                    self.interrupt()

        return detach

    def _person(self, client_id: str) -> str:
        kind = self._clients[client_id][0]
        return (
            "tui" if kind == "tui" else "web:" + hashlib.sha256(client_id.encode()).hexdigest()[:8]
        )

    def reply(self, client_id: str, message: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if client_id not in self._clients or self._closed:
                return {"ok": False, "error": "client is not attached"}
            request_id = message.get("request_id")
            if not isinstance(request_id, str):
                return {"ok": False, "error": "request_id must be a string"}
            if request_id in self._answered:
                return {"ok": False, "error": "already answered by " + self._answered[request_id]}
            if self._pending is None or request_id != self._pending["request_id"]:
                return {"ok": False, "error": "unknown permission request"}
            reply = deepcopy(message)
            reply["person"] = self._person(client_id)
            gate = Gate(self._pending["gate"])
            if self._clients[client_id][0] == "web" and gate in DANGEROUS:
                word = "send" if gate == Gate.G0_SESSION else "apply"
                choice = reply.get("choice")
                if (
                    isinstance(choice, str)
                    and choice in {"approve", "apply"}
                    and reply.get("confirm") != word
                ):
                    reply.update(choice="undecided", reason="confirmation word missing")
            self._answered[request_id] = reply["person"]
            self._replies.put(reply)
            return {"ok": True}

    def _ask(self, request: GateRequest) -> GateDecision:
        with self._lock:
            if self._closed or self.session.cancelled:
                return GateDecision(request.gate, "undecided", "interrupted")
            if not self._use_bridge:
                return self._original_asker(request)
            self._replies = queue.Queue()

        def emit(event: dict[str, Any]) -> None:
            with self._lock:
                event["mode"] = self.session.ctx.gates.mode
                self._pending = event
                self._pending = self.publish(event)
                if self._closed or self.session.cancelled:
                    self._replies.put(None)

        return bridge_asker(emit, self._replies)(request)

    def _record_gate(self, event: dict[str, Any]) -> None:
        with self._lock:
            event = dict(event)
            if self._pending is not None and self._pending["gate"] == event["gate"]:
                request_id = self._pending["request_id"]
                event["request_id"] = request_id
                self._answered.setdefault(request_id, event.get("person") or "host")
                self._pending = None
            self.session.ctx.log.append(event)

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._busy

    @property
    def closed(self) -> bool:
        return self._closed

    def _launch(self, operation: Callable[[], object]) -> bool:
        with self._lock:
            if self._closed or self._busy:
                self.publish(
                    {
                        "type": "error",
                        "message": "host is closed"
                        if self._closed
                        else "a turn is already running",
                    }
                )
                return False
            self._busy = True
            self._idle.clear()
            self.session.last_outcome = "completed"
            self.session.prepare_turn()
            self._thread = threading.Thread(target=self._run, args=(operation,), daemon=True)
            self._thread.start()
            return True

    def submit(self, text: str) -> bool:
        return self._launch(lambda: self.session.send(text))

    def start(self) -> bool:
        """Emit ready immediately, then ask G0 on the worker (no provider call)."""

        def begin() -> None:
            self._use_bridge = True
            self.publish(ready_event(self.session))
            self.started = self.session.start()
            if not self.started:
                self.session.last_outcome = "interrupted" if self.session.cancelled else "failed"

        return self._launch(begin)

    def _run(self, operation: Callable[[], object]) -> None:
        try:
            operation()
            self.session.snapshot()
        except Exception as exc:  # noqa: BLE001 - one failed operation must not kill the host
            self.session.last_outcome = "failed"
            self.publish({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            with self._lock:
                if self._audit_error:
                    self.session.last_outcome = "failed"
                self._flush_usage()
                self.publish({"type": "done", "reason": self.session.last_outcome})
                self._busy = False
                if self._closed:
                    self._unsubscribe()
                else:
                    self._auto_pending()
                if not self._busy:
                    self._idle.set()

    def interrupt(self) -> None:
        with self._lock:
            self.session.cancel()
            if self._pending is not None:
                self._answered.setdefault(self._pending["request_id"], "host (interrupted)")
                # Discard an accepted reply not yet consumed when the host closes.
                while not self._replies.empty():
                    try:
                        self._replies.get_nowait()
                    except queue.Empty:
                        break
                self._replies.put(None)

    def wait_idle(self, timeout: float) -> bool:
        return self._idle.wait(timeout)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            self.interrupt()
        if self._thread is not threading.current_thread():
            self.wait_idle(2)
        if not self.busy:
            self._unsubscribe()

    def seed_events(self, events: list[dict[str, Any]]) -> None:
        """Retain pre-session handshake events without emitting them a second time."""
        with self._lock:
            if self._seq:
                return
            for event in events:
                self.session.ctx.log.append({"type": "host_event", "event": event})
                self._events.append(deepcopy(event))
                self._seq = event["seq"]

    def resume(self, path: Path) -> None:
        """Replace the audit/history/state together, then ask fresh session consent."""
        from vulnscan.providers.budget import BudgetManager

        from .workspace import Workspace

        if excluded_command_path(path) or path.suffix != ".jsonl" or not path.is_file():
            raise ValueError("invalid session log")
        old = self.session
        log = SessionLog(path)
        log.lock = self._lock
        gates = GateKeeper(
            self._ask,
            self._record_gate,
            person=old.ctx.gates.person,
            mode=old.ctx.gates.mode,
            interactive=bool(self._clients),
        )
        context = replace(old.ctx, log=log, gates=gates, ws=Workspace.open(old.ctx.ws.target))
        budget = BudgetManager(old.budget.total_budget, old.budget._reserve) if old.budget else None
        replacement = Session(old.transport, context, old.max_rounds, budget)
        with self._lock:
            self._unsubscribe()
            self.session = replacement
            self._totals = log.totals()
            self._usage = None
            self._remaining_tools.clear()
            self._events = [r["event"] for r in log.events() if r.get("type") == "host_event"]
            self._seq = max(self._seq, max((e["seq"] for e in self._events), default=0))
            self._events = self._events[-MAX_MEMORY_EVENTS:]
            self._unsubscribe = log.subscribe(self._on_log)
            self.started = False
            self._recover_pending()
            self.publish(ready_event(self.session))
        self.started = self.session.start()
        if not self.started:
            self.session.last_outcome = "interrupted" if self.session.cancelled else "failed"

    def command(self, name: str, args: list[str], client_id: str = "") -> bool:
        """Run console-equivalent actions on the worker, through the bridge asker."""
        with self._lock:
            if client_id not in self._clients:
                self.publish({"type": "error", "message": "client is not attached"})
                return False
            person = self._person(client_id)
        return self._launch(lambda: self._command(name.lstrip("/"), args, person))

    def _command(self, name: str, args: list[str], person: str) -> None:
        from .models import list_models, models_event, resolve_model
        from .providers import make_transport
        from .report import export

        ctx = self.session.ctx

        def text(value: str) -> None:
            self.publish({"type": "text_delta", "text": value})

        if name in {"model", "keys"} and not args:
            self.publish(models_event(list_models()))
        elif name == "model":
            if len(args) != 1:
                raise ValueError("usage: /model <alias>[:model-id]")
            profile, model = resolve_model(args[0])
            if self.session.switch(make_transport(profile, model)):
                self.publish(ready_event(self.session))
            else:
                text("switch rejected; keeping the previous provider")
        elif name == "mode":
            if not args or args[0] not in {"ask", "auto"} or len(args) > 2:
                raise ValueError("usage: /mode ask|auto")
            if args[0] == "auto" and ctx.gates.mode != "auto" and args != ["auto", "confirm"]:
                text(
                    "Confirm auto mode: routine scanning gates will be approved automatically. "
                    "G5 and G6 still need you. Send /mode auto confirm to continue."
                )
                return
            ctx.gates.mode = args[0]
            ctx.log.append({"type": "mode", "mode": args[0], "person": person})
            self.publish(ready_event(self.session))
        elif name == "cost":
            totals = ctx.log.totals()
            self.publish(
                {
                    "type": "usage",
                    **totals,
                    "total_tokens": int(totals["input_tokens"] + totals["output_tokens"]),
                    "total_cost_usd": totals["cost_usd"],
                }
            )
        elif name == "review":
            keeper = GateKeeper(self._ask, self._record_gate, person=person, mode="ask")
            pending = sorted(
                (f for f in ctx.ws.findings.values() if f.status == "proposed"), key=lambda f: f.id
            )
            if not pending:
                text("No finding is awaiting review.")
            for finding in pending:
                if self.session.cancelled:
                    break
                decision = keeper.ask(
                    GateRequest(
                        Gate.G5_FINDING,
                        f"Review {finding.id}: {finding.title}",
                        finding.explanation,
                        {"finding_id": finding.id, **asdict(finding)},
                        "Only a human sets a finding's final status.",
                    )
                )
                status = {
                    "confirm": "confirmed",
                    "reject": "rejected",
                    "need_more": "need_more",
                }.get(decision.choice)
                if status:
                    finding.status, finding.decided_by, finding.reason = (
                        status,
                        decision.person,
                        decision.reason,
                    )
                text(f"{finding.id}: {finding.status}")
        elif name == "export":
            out = Path(args[0]) if args else Path(".devsec/reports") / ctx.log.path.stem
            if len(args) > 1 or excluded_command_path(out):
                raise ValueError("invalid report directory")
            paths = export(ctx.ws, ctx.log, out)
            text(f"report: {paths['markdown']}\njson: {paths['json']}")
        elif name == "resume":
            if len(args) != 1:
                raise ValueError("usage: /resume <session.jsonl>")
            path = Path(args[0])
            if excluded_command_path(path) or path.suffix != ".jsonl" or not path.is_file():
                raise ValueError("invalid session log")
            self.resume(path)
        elif name == "clear":
            self.session.messages = []
            ctx.log.append({"type": "clear"})
            text("conversation cleared")
        elif name == "findings":
            self.publish(
                {
                    "type": "findings",
                    "items": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "cwe": f.cwe,
                            "status": f.status,
                            "file": ctx.ws.candidates[f.candidate_id].file
                            if f.candidate_id in ctx.ws.candidates
                            else (f.path[0].file if f.path else ""),
                        }
                        for f in ctx.ws.findings.values()
                    ],
                }
            )
        elif name == "help":
            text(
                "/model <alias>[:id]\n/mode ask|auto\n/cost\n/review\n/export [dir]\n/resume <session.jsonl>\n/clear\n/keys\n/findings\n/pending review|dismiss <id>\n/remote on|off\n/help\n/quit"
            )
        else:
            raise ValueError(f"unknown command /{name}; /help lists commands")

    def _auto_pending(self) -> None:
        # The polling integration fills this list; no provider is called here
        # until a session has passed G0 and a human client is attached.
        if (
            self._reviews
            and self._review_store
            and self.started
            and not self._busy
            and not self._closed
            and self._clients
            and self.session.ctx.gates.mode == "auto"
            and is_local(self.session.transport.profile)
        ):
            self.review_pending(self._reviews[0]["id"])

    def enable_pending(self, root: Path = Path(".")) -> None:
        """Poll the queue and, for unversioned targets, run the folder watcher."""
        from .pending import store_path
        from .watcher import Watcher

        with self._lock:
            if self._monitor is not None:
                return
            self._review_store = store_path(root, self.session.ctx.ws.target)
            if self.session.ctx.ws.commit == "unversioned":
                if self._review_store.resolve().is_relative_to(
                    self.session.ctx.ws.target.resolve()
                ):
                    self._review_store = None
                    self.publish(
                        {
                            "type": "pending",
                            "items": [],
                            "status": "unavailable",
                            "reason": "watch queue must be outside the target; run from a separate harness directory",
                        }
                    )
                    return
                self._watcher = Watcher(self.session.ctx.ws, self._review_store)
                self._watcher.tick()
            self.refresh_pending()

            def monitor() -> None:
                while not self._stop.wait(5):
                    try:
                        if self._watcher is not None:
                            self._watcher.tick()
                        self.refresh_pending()
                    except (OSError, ValueError) as exc:
                        self.publish(
                            {"type": "error", "message": f"pending reviews unavailable: {exc}"}
                        )

            self._monitor = threading.Thread(target=monitor, daemon=True)
            self._monitor.start()

    def refresh_pending(self) -> None:
        from .pending import read_pending

        with self._lock:
            if self._review_store is None or self._closed:
                return
            ws = self.session.ctx.ws
            reviews = [
                asdict(review)
                for review in read_pending(
                    ws.target if ws.commit != "unversioned" else None, self._review_store
                )
            ]
            if reviews != self._reviews:
                self._reviews = reviews
                self.publish({"type": "pending", "items": reviews})
            self._auto_pending()

    def review_pending(self, review_id: str, *, dismiss: bool = False) -> bool:
        from .pending import mark

        with self._lock:
            review = next((r for r in self._reviews if r["id"] == review_id), None)
            if review is None or self._review_store is None:
                return False
            if not dismiss and (self._busy or not self.started or not self._clients):
                return False
            # Validate queue paths again before putting their names into a prompt.
            files = []
            for name in review["files"]:
                self.session.ctx.ws.resolve(name)
                files.append(name)
            if not dismiss and not files:
                return False
            mark(self._review_store, review_id, "dismissed" if dismiss else "started")
            self._reviews.remove(review)
            self.publish({"type": "pending", "items": self._reviews})
            if dismiss:
                return True
            return self.submit(
                PENDING_PROMPT.format(ref=review["ref"] or "working folder", files=", ".join(files))
            )


def message_text(message: Message) -> str:
    return " ".join(message.content.split())


def excluded_command_path(path: Path) -> bool:
    """Also exclude resolved aliases for human-command file arguments."""
    from .workspace import Workspace

    return Workspace._excluded(path) or Workspace._excluded(path.resolve())
