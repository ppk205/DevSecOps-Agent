"""Console front end: the gate prompts and the chat slash commands."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.credentials import redact

from .audit import SessionLog
from .gates import Asker, Gate, GateDecision, GateKeeper, GateRequest
from .messages import Message
from .providers import all_profiles, make_transport
from .report import export
from .session import Session

__all__ = ["ChatConsole", "console_asker"]

_KEYMAP: dict[Gate, dict[str, str]] = {
    Gate.G0_SESSION: {"y": "approve", "n": "reject"},
    Gate.G1_PLAN: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G2_SCAN: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G3_TRIAGE: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G4_INVESTIGATE: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G5_FINDING: {"c": "confirm", "r": "reject", "m": "need_more"},
    Gate.G6_FIX: {"a": "apply", "r": "reject", "d": "defer"},
    Gate.G7_RESCAN: {"y": "approve", "n": "reject"},
}

_REASON_CHOICES = frozenset({"reject", "need_more", "defer"})
_STATUS_BY_CHOICE = {"confirm": "confirmed", "reject": "rejected", "need_more": "need_more"}

_HELP = (
    "/model <provider> [model]  switch provider\n"
    "/mode ask|auto            set the gate mode\n"
    "/cost                     tokens and cost so far\n"
    "/review                   settle findings awaiting a human\n"
    "/export [dir]             write report.md and report.json\n"
    "/resume <session.jsonl>   load that session's history\n"
    "/clear                    forget the conversation\n"
    "/quit                     leave"
)


def console_asker(
    read: Callable[[str], str] = input, write: Callable[[str], None] = print
) -> Asker:
    """Ask in the terminal; an empty line re-prompts and never means yes."""

    def emit(text: str) -> None:
        write(redact(text))

    def ask(request: GateRequest) -> GateDecision:
        emit(f"[{request.gate.value}] {request.title}")
        if request.detail:
            emit(request.detail)
        if request.ai_recommendation:
            emit(f"AI: {request.ai_recommendation}")
        if request.payload:
            payload = {key: value for key, value in request.payload.items() if key != "diff"}
            emit(json.dumps(payload, indent=2, default=str))
            if "diff" in request.payload:
                emit(str(request.payload["diff"]))
        options = _KEYMAP[request.gate]
        emit("  " + "  ".join(f"[{key}] {choice}" for key, choice in options.items()))
        while True:
            answer = read("choice: ").strip().lower()
            choice = options.get(answer)
            if choice is None:
                emit("Press one of: " + ", ".join(options))
                continue
            edits: dict[str, Any] = {}
            reason = ""
            if choice == "edit":
                raw = read("edits (JSON): ").strip()
                try:
                    parsed: Any = json.loads(raw)
                except ValueError:
                    return GateDecision(request.gate, "undecided", "invalid edit JSON")
                if not isinstance(parsed, dict):
                    return GateDecision(request.gate, "undecided", "edits must be a JSON object")
                edits = parsed
            elif choice in _REASON_CHOICES:
                reason = read("reason: ").strip()
            return GateDecision(request.gate, choice, reason, edits)

    return ask


class ChatConsole:
    """Read lines, print replies, and run the slash commands."""

    def __init__(
        self,
        session: Session,
        read: Callable[[str], str] = input,
        write: Callable[[str], None] = print,
        profiles: dict[str, ProviderProfile] | None = None,
    ) -> None:
        self.session = session
        self.read = read
        self.write: Callable[[str], None] = lambda text: write(redact(text))
        self.profiles = profiles or all_profiles()

    # ------------------------------------------------------------------
    # loop
    # ------------------------------------------------------------------
    def run(self, prompt: str | None = None) -> int:
        if prompt is not None:
            self._send(prompt)
            return 0
        self.write("devsec chat — /help lists commands, /quit leaves.")
        while True:
            try:
                line = self.read("> ")
            except (EOFError, KeyboardInterrupt):
                return 0
            if not self.handle(line):
                return 0

    def handle(self, line: str) -> bool:
        text = line.strip()
        if not text:
            return True
        if text.startswith("/"):
            return self._command(text)
        self._send(text)
        return True

    # ------------------------------------------------------------------
    # commands
    # ------------------------------------------------------------------
    def _command(self, text: str) -> bool:
        parts = text.split()
        name = parts[0].lower()
        if name == "/quit":
            return False
        if name == "/help":
            self.write(_HELP)
        elif name == "/model":
            self._model(parts[1:])
        elif name == "/mode":
            self._mode(parts[1:])
        elif name == "/cost":
            self.write(json.dumps(self.session.ctx.log.totals(), indent=2))
        elif name == "/review":
            self._review()
        elif name == "/export":
            self._export(parts[1:])
        elif name == "/resume":
            self._resume(parts[1:])
        elif name == "/clear":
            self.session.ctx.log.append({"type": "clear"})
            self.session.messages = []
            self.write("conversation cleared")
        else:
            self.write(f"unknown command {name}; /help lists commands")
        return True

    def _model(self, args: list[str]) -> None:
        if not args:
            self.write("usage: /model <provider> [model]")
            return
        profile = self.profiles.get(args[0])
        if profile is None:
            self.write(f"unknown provider {args[0]!r}; known: {', '.join(sorted(self.profiles))}")
            return
        try:
            transport = make_transport(profile, args[1] if len(args) > 1 else None)
        except Exception as exc:  # noqa: BLE001 - a bad choice must not end the session
            self.write(f"cannot use that provider: {exc}")
            return
        if self.session.switch(transport):
            self.write(f"now using {transport.profile.id} / {transport.model}")
        else:
            self.write("switch rejected; keeping the previous provider")

    def _mode(self, args: list[str]) -> None:
        from .gates import MODES

        if not args or args[0] not in MODES:
            self.write("usage: /mode ask|auto")
            return
        self.session.ctx.gates.mode = args[0]
        self.session.ctx.log.append({"type": "mode", "mode": args[0]})
        self.write(f"gate mode: {args[0]}")

    def _review(self) -> None:
        ctx = self.session.ctx
        keeper = GateKeeper(
            console_asker(self.read, self.write),
            ctx.log.append,
            person=ctx.gates.person or "human",
            mode="ask",
        )
        pending = sorted(
            (finding for finding in ctx.ws.findings.values() if finding.status == "proposed"),
            key=lambda finding: finding.id,
        )
        if not pending:
            self.write("No finding is awaiting review.")
            return
        for finding in pending:
            decision = keeper.ask(
                GateRequest(
                    Gate.G5_FINDING,
                    f"Review {finding.id}: {finding.title}",
                    f"{finding.cwe} · CVSS {finding.cvss_score}\n{finding.explanation}",
                    {"finding_id": finding.id, "evidence_errors": finding.evidence_errors},
                    "Only a human sets a finding's final status.",
                )
            )
            if decision.choice in _STATUS_BY_CHOICE:
                finding.status = _STATUS_BY_CHOICE[decision.choice]
                finding.decided_by = decision.person
                finding.reason = decision.reason
            self.write(f"{finding.id}: {finding.status}")

    def _export(self, args: list[str]) -> None:
        ctx = self.session.ctx
        if args:
            out_dir = Path(args[0])
        else:
            out_dir = Path(".devsec/reports") / Path(ctx.log.path).stem
        paths = export(ctx.ws, ctx.log, out_dir)
        self.write(f"report: {paths['markdown']}")
        self.write(f"json: {paths['json']}")

    def _resume(self, args: list[str]) -> None:
        if not args:
            self.write("usage: /resume <session.jsonl>")
            return
        # ponytail: loads the history into this session; worktrees and findings
        # are rebuilt only by replaying the tools, which is not done here.
        messages = SessionLog(Path(args[0])).messages()
        self.session.messages = messages
        self.write(f"loaded {len(messages)} message(s) from {args[0]}")

    # ------------------------------------------------------------------
    # sending
    # ------------------------------------------------------------------
    def _send(self, text: str) -> None:
        for message in self.session.send(text):
            self._print(message)

    def _print(self, message: Message) -> None:
        if message.role == "assistant":
            if message.content:
                self.write(message.content)
            for call in message.tool_calls:
                self.write(f"● {call.name}({json.dumps(call.arguments, sort_keys=True)})")
        elif message.role == "tool":
            self.write(f"  {message.content[:200]}")
