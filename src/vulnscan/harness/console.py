"""Console front end: the gate prompts and the chat slash commands."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.credentials import redact

from .audit import SessionLog
from .gates import DANGEROUS, Asker, Gate, GateDecision, GateKeeper, GateRequest
from .messages import Message
from .models import ModelEntry, add_model, list_models, remove_model, resolve_model, set_key
from .providers import BUILTIN_PROFILES, make_transport
from .report import export
from .session import Session
from .workspace import Workspace

__all__ = ["ChatConsole", "console_asker"]

_KEYMAP: dict[Gate, dict[str, str]] = {
    Gate.G0_SESSION: {"y": "approve", "n": "reject"},
    Gate.G1_PLAN: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G2_SCAN: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G3_TRIAGE: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G4_INVESTIGATE: {"y": "approve", "e": "edit", "n": "reject"},
    Gate.G5_FINDING: {"c": "confirm", "r": "reject", "m": "need_more"},
    Gate.G6_FIX: {"a": "apply", "r": "reject", "d": "defer"},
    Gate.G7_RESCAN: {"y": "approve", "e": "edit", "n": "reject"},
}

_REASON_CHOICES = frozenset({"reject", "need_more", "defer"})
_STATUS_BY_CHOICE = {"confirm": "confirmed", "reject": "rejected", "need_more": "need_more"}

_HELP = (
    "/model [alias[:model-id]]  list or switch added models\n"
    "/model add                add a model with a masked key\n"
    "/model key|remove <alias> manage an added model\n"
    "/keys                     show added models and key status\n"
    "/mode ask|auto            set the gate mode\n"
    "/cost                     tokens and cost so far\n"
    "/review                   settle findings awaiting a human\n"
    "/export [dir]             write report.md and report.json\n"
    "/resume <session.jsonl>   restore session state and costs with fresh consent\n"
    "/clear                    forget the conversation\n"
    "/quit                     leave"
)


def console_asker(
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    *,
    mode: str | Callable[[], str] = "ask",
) -> Asker:
    """Ask in the terminal; an empty line re-prompts and never means yes."""

    def emit(text: str) -> None:
        write(redact(text))

    def ask(request: GateRequest) -> GateDecision:
        danger = " DANGEROUS" if request.gate in DANGEROUS else ""
        current_mode = mode() if callable(mode) else mode
        emit(f"[{request.gate.value}]{danger} {request.title} · mode: {current_mode}")
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


def model_summary(entry: ModelEntry) -> str:
    """The same public label is used by the CLI and console."""
    location = "local" if entry.local else "cloud"
    key_status = "key set" if entry.key_set else "key missing"
    return redact(f"{entry.alias}:{entry.default_model} · {location} · {key_status}")


def prompt_model_key(*, local: bool = False) -> str:
    """Read a key without allowing getpass's unmasked fallback."""
    import getpass
    import warnings

    suffix = "; Enter skips for a local URL" if local else ""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(f"API key (hidden{suffix}): ")
    except (getpass.GetPassWarning, OSError):
        raise ValueError("Hidden key input requires a terminal") from None
    except (EOFError, KeyboardInterrupt):
        raise ValueError("Model key entry cancelled") from None


def add_model_wizard(
    template: str | None = None,
    *,
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
) -> ModelEntry:
    """One add-model form shared by devsec model add and /model add."""
    from vulnscan.core.model_consent import is_local_base_url

    try:
        alias = read("Name (lowercase letters, digits, dashes): ").strip()
        if template is None:
            write("Templates: " + ", ".join(BUILTIN_PROFILES) + ", custom")
            template = read("Template: ").strip().lower()
        if template == "custom":
            template = None
        source = BUILTIN_PROFILES.get(template) if template else None
        if template and source is None:
            raise ValueError("Unknown model template")
        default_protocol = source.protocol.value if source else "openai_compatible"
        protocol = read(f"Protocol [{default_protocol}]: ").strip() or default_protocol
        default_url = source.base_url if source else ""
        url = read(f"Base URL [{default_url}]: ").strip() or default_url
        ids = [
            item.strip() for item in read("Model ids (comma-separated, default first): ").split(",")
        ]
        key = prompt_model_key(local=is_local_base_url(url))
        entry = add_model(alias, template, protocol, url, ids, key)
    except (EOFError, KeyboardInterrupt):
        raise ValueError("Add model cancelled") from None
    write(model_summary(entry))
    return entry


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
        self.profiles = profiles if profiles is not None else dict(BUILTIN_PROFILES)

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
        elif name == "/keys":
            self._model([])
        elif name == "/mode":
            self._mode(parts[1:])
        elif name == "/cost":
            self.write(json.dumps(self.session.ctx.log.totals(), indent=2))
        elif name == "/review":
            self._review()
        elif name == "/export":
            self._export(parts[1:])
        elif name == "/resume":
            self._resume([text.split(maxsplit=1)[1]] if len(parts) > 1 else [])
        elif name == "/clear":
            self.session.ctx.log.append({"type": "clear"})
            self.session.messages = []
            self.write("conversation cleared")
        else:
            self.write(f"unknown command {name}; /help lists commands")
        return True

    def _model(self, args: list[str]) -> None:
        try:
            if not args:
                entries = list_models()
                for entry in entries:
                    self.write(model_summary(entry))
                if not entries:
                    self.write("No models added. Use /model add.")
                return
            if args == ["add"]:
                add_model_wizard(read=self.read, write=self.write)
                return
            if len(args) == 2 and args[0] in {"key", "remove"}:
                if args[0] == "key":
                    set_key(args[1], prompt_model_key())
                    self.write("Model key set.")
                else:
                    remove_model(args[1])
                    self.write("Model removed.")
                return
            if len(args) == 1:
                profile, model = resolve_model(args[0])
            elif len(args) == 2 and args[0] in self.profiles:
                # ponytail: legacy /model <provider> <id> is kept for one release.
                profile, model = self.profiles[args[0]], args[1]
            else:
                self.write("usage: /model [alias[:model-id]|add|key <alias>|remove <alias>]")
                return
            transport = make_transport(profile, model)
        except Exception:  # noqa: BLE001 - never echo credential-bearing errors
            self.write("Cannot use or manage that model. Check its alias, settings and key.")
            return
        if self.session.switch(transport):
            self.write(f"now using {transport.profile.id} / {transport.model}")
        else:
            self.write("switch rejected; keeping the previous provider")

    def _mode(self, args: list[str]) -> None:
        from .gates import MODES

        if len(args) != 1 or args[0] not in MODES:
            self.write("usage: /mode ask|auto")
            return
        if args[0] == "auto" and self.session.ctx.gates.mode != "auto":
            self.write("Auto mode approves routine gates. G5 and G6 still need a human.")
            try:
                approved = (
                    self.read("Switch to auto? [y] confirm, any other input cancels: ")
                    .strip()
                    .lower()
                    == "y"
                )
            except (EOFError, KeyboardInterrupt):
                approved = False
            except Exception:  # noqa: BLE001 - a broken prompt never changes the mode
                approved = False
            if not approved:
                self.write("Mode unchanged.")
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
                self.session.snapshot()
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
        old = self.session
        try:
            path = Path(args[0].strip('"'))
            if (
                Workspace._excluded(path)
                or Workspace._excluded(path.resolve())
                or path.suffix != ".jsonl"
                or not path.is_file()
            ):
                raise ValueError("invalid session log")
            log = SessionLog(path)
            gates = GateKeeper(
                old.ctx.gates.asker,
                log.append,
                person=old.ctx.gates.person,
                mode=old.ctx.gates.mode,
                interactive=old.ctx.gates.interactive,
            )
            ctx = replace(old.ctx, log=log, gates=gates, ws=Workspace.open(old.ctx.ws.target))
            budget = (
                BudgetManager(old.budget.total_budget, old.budget._reserve) if old.budget else None
            )
            replacement = Session(old.transport, ctx, old.max_rounds, budget)
        except (OSError, ValueError, TypeError, KeyError):
            self.write("Cannot resume: check the session log and its target/commit.")
            return
        if not replacement.start():
            self.write("Resume not approved; keeping the current session.")
            return
        self.session = replacement
        self.write(f"loaded {len(replacement.messages)} message(s) from {path}")

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
