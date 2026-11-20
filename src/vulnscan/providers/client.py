"""Chat Completions & v0 Platform HTTP client — provider-agnostic, BYOK.

Supports any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI,
OpenRouter, OpenCode Zen, etc.) as well as the Vercel v0 Platform API v1
(``POST /v1/chats`` and ``POST /v1/chats/{chatId}/messages``).  Wire protocol
is plain HTTP; no SDK dependency.  Keys never leave the process; they are
passed via ``Authorization: Bearer <key>`` headers only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile, ProviderUsage

from .budget import BudgetManager
from .credentials import load_api_key, redact
from .events import emit_model_event


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(part.get("text", "")) for part in value if isinstance(part, dict))
    return ""


def _redact_data(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        text = redact(value)
        return text.replace(secret, "[REDACTED]") if secret else text
    if isinstance(value, dict):
        return {key: _redact_data(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_data(item, secret) for item in value]
    return value


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


@dataclass
class ChatResponse:
    """Parsed response from /chat/completions or v0 /v1/chats."""

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    model: str = ""
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


def _make_http_client(timeout: float) -> httpx.Client:
    """Create an ``httpx.Client`` resilient to malformed IPv6 ``NO_PROXY`` entries.

    ``httpx`` 0.28 raises ``InvalidURL`` when ``NO_PROXY`` contains bare or
    bracketed IPv6 tokens such as ``::1,[::1]``.  When that happens we fall
    back to explicit ``HTTP_PROXY`` / ``HTTPS_PROXY`` mounts while preserving
    ``SSL_CERT_FILE`` / ``REQUESTS_CA_BUNDLE`` verification.
    """
    try:
        return httpx.Client(timeout=timeout)
    except httpx.InvalidURL:
        cafile = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or None
        ssl_ctx = ssl.create_default_context(cafile=cafile)
        mounts: dict[str, httpx.BaseTransport | None] = {}
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
        if http_proxy:
            mounts["http://"] = httpx.HTTPTransport(proxy=http_proxy, verify=ssl_ctx)
        if https_proxy:
            mounts["https://"] = httpx.HTTPTransport(proxy=https_proxy, verify=ssl_ctx)
        if all_proxy:
            mounts["all://"] = httpx.HTTPTransport(proxy=all_proxy, verify=ssl_ctx)

        raw_no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
        for item in raw_no_proxy.split(","):
            host = item.strip()
            if not host or ":" in host:
                continue
            pattern = f"all://*{host}" if host.startswith(".") else f"all://{host}"
            mounts[pattern] = None

        return httpx.Client(
            timeout=timeout,
            mounts=mounts or None,
            verify=ssl_ctx,
            trust_env=False,
        )


def _serialize_openai_message(m: ChatMessage) -> dict[str, Any]:
    """Serialize a :class:`ChatMessage` for OpenAI-compatible ``/chat/completions``."""
    msg: dict[str, Any] = {"role": m.role, "content": m.content}
    if m.tool_call_id is not None:
        msg["tool_call_id"] = m.tool_call_id
    if m.tool_calls:
        msg["tool_calls"] = m.tool_calls
    return msg


def _format_v0_tool_instructions(tools: list[dict[str, Any]]) -> str:
    """Render OpenAI tool schemas as a compact JSON tool-calling protocol for v0."""
    lines = [
        "TOOL CALLING PROTOCOL:",
        "You have access to the local tools listed below.",
        "To invoke 1 to 3 targeted tools, reply ONLY with a valid JSON object (no prose, no markdown fences):",
        '{"tool_calls": [{"name": "<tool_name>", "arguments": {<arguments>}}]}',
        (
            "After you receive tool results, either invoke more tools using the same JSON format "
            "or provide your final answer strictly in the format requested by the user prompt "
            '(without a "tool_calls" key).'
        ),
        "",
        "AVAILABLE TOOLS:",
    ]
    for schema in tools:
        fn = schema.get("function", {})
        name = fn.get("name", "")
        if not name:
            continue
        desc = (fn.get("description") or "").strip().splitlines()[0][:180]
        params = fn.get("parameters", {})
        props = params.get("properties", {})
        required = set(params.get("required", []))
        arg_parts: list[str] = []
        for pname, pspec in props.items():
            ptype = pspec.get("type", "any")
            enum_vals = pspec.get("enum")
            if enum_vals:
                ptype = "|".join(str(v) for v in enum_vals[:6])
            req_mark = "*" if pname in required else ""
            arg_parts.append(f"{pname}{req_mark}:{ptype}")
        sig = ", ".join(arg_parts)
        lines.append(f"- {name}({sig}): {desc}")
    return "\n".join(lines)


def _strip_code_fences(text: str) -> str:
    """Remove leading/trailing markdown code fences if present."""
    stripped = text.strip()
    m = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", stripped, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else stripped


def _extract_v0_tool_calls(content: str, allowed_tools: set[str]) -> list[dict[str, Any]]:
    """Parse structured JSON tool calls emitted by v0 under the tool protocol."""
    if not content or not allowed_tools:
        return []

    decoder = json.JSONDecoder()
    sources: list[str] = [_strip_code_fences(content), content]
    for match in re.finditer(r"```(?:json)?\s*\n(.*?)\n```", content, re.DOTALL | re.IGNORECASE):
        sources.append(match.group(1).strip())

    parsed: dict[str, Any] | None = None
    for src in sources:
        pos = 0
        while True:
            idx = src.find("{", pos)
            if idx == -1:
                break
            try:
                obj, _end = decoder.raw_decode(src, idx)
            except json.JSONDecodeError:
                pos = idx + 1
                continue
            if isinstance(obj, dict) and (
                "tool_calls" in obj
                or "tool_call" in obj
                or (obj.get("name") in allowed_tools and "arguments" in obj)
            ):
                parsed = obj
                break
            pos = idx + 1
        if parsed is not None:
            break

    if not isinstance(parsed, dict):
        return []

    raw_calls: list[dict[str, Any]] = []
    if isinstance(parsed.get("tool_calls"), list):
        raw_calls = [c for c in parsed["tool_calls"] if isinstance(c, dict)]
    elif isinstance(parsed.get("tool_call"), dict):
        raw_calls = [parsed["tool_call"]]
    elif parsed.get("name") in allowed_tools:
        raw_calls = [parsed]

    normalized: list[dict[str, Any]] = []
    for idx, call in enumerate(raw_calls):
        maybe_fn = call.get("function")
        fn_block: dict[str, Any] = maybe_fn if isinstance(maybe_fn, dict) else call
        name = str(fn_block.get("name") or "")
        if name not in allowed_tools:
            continue
        args = fn_block.get("arguments", {})
        if isinstance(args, str):
            args_str = args
        else:
            args_str = json.dumps(args if isinstance(args, dict) else {})
        normalized.append(
            {
                "id": str(call.get("id") or f"v0_call_{idx + 1}"),
                "type": "function",
                "function": {"name": name, "arguments": args_str},
            }
        )
    return normalized


class ProviderClient:
    """Stateless Chat Completions & v0 Platform client with budget enforcement.

    Parameters
    ----------
    profile:
        Cấu hình provider (endpoint, model, timeout, v.v.)
    budget:
        Bộ theo dõi ngân sách dùng chung. Nếu là ``None``, sẽ không thực hiện kiểm tra ngân sách.
    """

    def __init__(
        self,
        profile: ProviderProfile,
        budget: BudgetManager | None = None,
    ) -> None:
        self.profile = profile
        self.budget = budget
        self._key: str | None = None
        self._v0_sessions: dict[str, tuple[str, int]] = {}
        self._v0_created_chat_ids: list[str] = []

    def _get_key(self) -> str:
        if self._key is None:
            self._key = load_api_key(self.profile.api_key_env)
        return self._key

    def _is_v0_platform(self) -> bool:
        if self.profile.protocol == ProviderProtocol.V0_PLATFORM_API:
            return True
        host = (urlparse(self.profile.base_url).hostname or "").lower()
        return host == "api.v0.dev" and not self.profile.base_url.rstrip("/").endswith(
            "/chat/completions"
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._get_key()}",
            "Content-Type": "application/json",
        }
        for key, value in (self.profile.headers or {}).items():
            if key.lower() in ("authorization", "content-type"):
                continue
            headers[key] = value
        return headers

    def _post_with_retry(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        api_key = self._get_key()
        payload = _redact_data(payload, api_key)
        resp = None
        attempts = max(1, self.profile.max_retries + 1)
        for attempt in range(attempts):
            try:
                with _make_http_client(self.profile.timeout_seconds) as client:
                    resp = client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429 and attempt < attempts - 1:
                    retry_after = exc.response.headers.get("retry-after")
                    try:
                        wait = float(retry_after) if retry_after else 20.0 * (attempt + 1)
                    except (TypeError, ValueError):
                        wait = 20.0 * (attempt + 1)
                    time.sleep(min(wait, 120.0))
                    continue
                raise ProviderError(
                    _redact_data(
                        f"HTTP {exc.response.status_code} from {self.profile.id}: "
                        f"{exc.response.text[:500]}",
                        api_key,
                    )
                ) from exc
            except httpx.RequestError as exc:
                raise ProviderError(
                    _redact_data(f"Request failed for {self.profile.id}: {exc}", api_key)
                ) from exc
        assert resp is not None
        data: dict[str, Any] = _redact_data(resp.json(), api_key)
        return data

    def _v0_chats_url(self) -> str:
        base = self.profile.base_url.rstrip("/")
        if base.endswith("/chats"):
            return base
        if base.endswith("/v1"):
            return f"{base}/chats"
        return f"{base}/v1/chats"

    def delete_v0_chat(self, chat_id: str) -> bool:
        """Best-effort delete of a remote v0 chat (``DELETE /v1/chats/{chatId}``)."""
        url = f"{self._v0_chats_url()}/{chat_id}"
        headers = self._build_headers()
        try:
            with _make_http_client(min(self.profile.timeout_seconds, 30)) as client:
                resp = client.delete(url, headers=headers)
                return resp.status_code < 400
        except httpx.HTTPError:
            return False

    def cleanup_v0_chats(self) -> int:
        """Delete all v0 chats created by this client instance. Returns deleted count."""
        deleted = 0
        for chat_id in list(self._v0_created_chat_ids):
            if self.delete_v0_chat(chat_id):
                deleted += 1
                self._v0_created_chat_ids.remove(chat_id)
        self._v0_sessions.clear()
        return deleted

    def _chat_v0_platform(
        self,
        messages: list[ChatMessage],
        *,
        use_model: str,
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResponse:
        """Send a turn via Vercel v0 Platform API v1 (``/v1/chats``)."""
        system_parts = [m.content for m in messages if m.role == "system" and m.content]
        if tools:
            system_parts.append(_format_v0_tool_instructions(tools))
        system_text = "\n\n".join(system_parts).strip()

        non_system = [m for m in messages if m.role != "system"]
        if not non_system:
            raise ValueError("At least one non-system message is required.")

        first_user = next(
            (m.content for m in non_system if m.role == "user"), non_system[0].content
        )
        raw_session_key = f"{messages[0].content if messages else ''}\n---\n{first_user}"
        session_key = hashlib.sha256(raw_session_key.encode("utf-8")).hexdigest()[:24]

        def _format_slice(items: list[ChatMessage]) -> str:
            if len(items) == 1 and items[0].role == "user":
                return items[0].content
            blocks: list[str] = []
            for item in items:
                if item.role == "user":
                    blocks.append(f"[USER]\n{item.content}")
                elif item.role == "assistant":
                    if item.tool_calls:
                        blocks.append(f"[ASSISTANT TOOL_CALLS]\n{json.dumps(item.tool_calls)}")
                    elif item.content:
                        blocks.append(f"[ASSISTANT]\n{item.content}")
                elif item.role == "tool":
                    call_ref = f" ({item.tool_call_id})" if item.tool_call_id else ""
                    blocks.append(f"[TOOL RESULT{call_ref}]\n{item.content}")
            return "\n\n".join(blocks)

        chats_url = self._v0_chats_url()
        headers = self._build_headers()
        existing = self._v0_sessions.get(session_key)
        reuse_chat_id: str | None = None
        if existing and len(non_system) > existing[1]:
            reuse_chat_id = existing[0]
            delta = [m for m in non_system[existing[1] :] if m.role != "assistant"]
            user_prompt = _format_slice(delta) if delta else _format_slice(non_system[-1:])
            url = f"{chats_url}/{reuse_chat_id}/messages"
            payload: dict[str, Any] = {
                "message": user_prompt,
                "responseMode": "sync",
                "modelConfiguration": {
                    "modelId": use_model,
                    "imageGenerations": False,
                    "thinking": False,
                },
            }
            if system_text:
                payload["system"] = system_text
        else:
            user_prompt = _format_slice(non_system)
            url = chats_url
            payload = {
                "message": user_prompt,
                "chatPrivacy": "private",
                "responseMode": "sync",
                "modelConfiguration": {
                    "modelId": use_model,
                    "imageGenerations": False,
                    "thinking": False,
                },
            }
            if system_text:
                payload["system"] = system_text

        data = self._post_with_retry(url, payload, headers)

        chat_id = str(data.get("id") or reuse_chat_id or "")
        if chat_id:
            if chat_id not in self._v0_created_chat_ids:
                self._v0_created_chat_ids.append(chat_id)
            # Record non_system count + 1 for the assistant turn just produced
            self._v0_sessions[session_key] = (chat_id, len(non_system) + 1)

        assistant_msg: dict[str, Any] = {}
        for entry in reversed(data.get("messages") or []):
            if isinstance(entry, dict) and entry.get("role") == "assistant":
                assistant_msg = entry
                break

        content = str(assistant_msg.get("content") or data.get("text") or "")
        finish_reason = str(assistant_msg.get("finishReason") or "stop")
        model_cfg = data.get("modelConfiguration") or {}
        resp_model = str(model_cfg.get("modelId") or use_model)

        allowed_tools = {
            str(t.get("function", {}).get("name", "")) for t in (tools or []) if isinstance(t, dict)
        } - {""}
        parsed_tool_calls = _extract_v0_tool_calls(content, allowed_tools) if tools else []
        if parsed_tool_calls:
            finish_reason = "tool_calls"
        elif chat_id and self.profile.metadata.get("ephemeral_chats"):
            self.delete_v0_chat(chat_id)
            if chat_id in self._v0_created_chat_ids:
                self._v0_created_chat_ids.remove(chat_id)
            self._v0_sessions.pop(session_key, None)

        return ChatResponse(
            content=content,
            tool_calls=parsed_tool_calls,
            usage={},
            model=resp_model,
            finish_reason=finish_reason,
            raw=data,
        )

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
    ) -> ChatResponse:
        """Gửi một yêu cầu chat completion.

        Raises
        ------
        BudgetExhausted
            Nếu yêu cầu vượt quá mức trần ngân sách.
        ProviderError
            Khi xảy ra lỗi HTTP hoặc lỗi ở cấp độ phản hồi.
        """
        use_model = (
            model
            or self.profile.default_model
            or (self.profile.models[0] if self.profile.models else None)
        )
        if not use_model:
            raise ValueError("No model specified and profile has no default_model or models.")

        # Kiểm tra trước ngân sách
        if self.budget:
            self.budget.check()

        if self._is_v0_platform():
            return self._chat_v0_platform(
                messages,
                use_model=use_model,
                tools=tools if tool_choice != "none" else None,
            )

        payload: dict[str, Any] = {
            "model": use_model,
            "messages": [_serialize_openai_message(m) for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        api_key = self._get_key()
        payload = _redact_data(payload, api_key)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        for key, value in (self.profile.headers or {}).items():
            if key.lower() in ("authorization", "content-type"):
                continue
            headers[key] = value

        url = f"{self.profile.base_url.rstrip('/')}/chat/completions"

        resp = None
        attempts = max(1, self.profile.max_retries + 1)
        for attempt in range(attempts):
            emit_model_event(
                "call",
                "running",
                f"Calling {self.profile.id} / {use_model} (attempt {attempt + 1})",
                provider=self.profile.id,
                model=use_model,
            )
            try:
                with _make_http_client(self.profile.timeout_seconds) as client:
                    resp = client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                break
            except httpx.HTTPStatusError as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider {self.profile.id} returned HTTP {exc.response.status_code}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                code = exc.response.status_code
                if code in (429, 499, 502, 503, 504) and attempt < attempts - 1:
                    # Rate limits, gateway-closed (499) and transient gateway failures;
                    # other errors are final.
                    import time as _time

                    retry_after = exc.response.headers.get("retry-after")
                    backoff = 30.0 if code in (429, 499) else 5.0 * (attempt + 1)
                    try:
                        wait = float(retry_after) if retry_after else backoff
                    except (TypeError, ValueError):
                        wait = backoff
                    _time.sleep(min(wait, 120.0))
                    continue
                raise ProviderError(
                    _redact_data(
                        f"HTTP {exc.response.status_code} from {self.profile.id}: {exc.response.text[:500]}",
                        api_key,
                    )
                ) from exc
            except httpx.RequestError as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider request failed: {type(exc).__name__}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                raise ProviderError(
                    _redact_data(f"Request failed for {self.profile.id}: {exc}", api_key)
                ) from exc
            except (OSError, ValueError, TypeError) as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider transport could not start: {type(exc).__name__}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                raise ProviderError("Provider transport could not start") from exc
        assert resp is not None

        try:
            data = _redact_data(resp.json(), api_key)
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            reasoning = _message_text(message.get("reasoning_content") or message.get("reasoning"))
            content = _message_text(message.get("content")) or reasoning
        except (ValueError, TypeError, AttributeError, IndexError) as exc:
            emit_model_event(
                "call",
                "failed",
                "Provider returned an invalid response",
                provider=self.profile.id,
                model=use_model,
                usage={},
            )
            raise ProviderError("Provider returned an invalid response") from exc

        # Parse response (some reasoning gateways put the answer in
        # `reasoning_content`/`reasoning` and leave `content` empty).
        chat_resp = ChatResponse(
            content=content if isinstance(content, str) else "",
            tool_calls=message.get("tool_calls") or [],
            usage=data.get("usage") or {},
            model=data.get("model") or use_model,
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
            reasoning=reasoning,
        )

        # Ghi nhận mức sử dụng
        if self.budget and chat_resp.usage:
            input_tokens = chat_resp.usage.get("prompt_tokens", 0)
            output_tokens = chat_resp.usage.get("completion_tokens", 0)
            total_tokens = chat_resp.usage.get("total_tokens", input_tokens + output_tokens)
            usage = ProviderUsage(
                provider_id=self.profile.id,
                model=use_model,
                timestamp=datetime.now(UTC),
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=total_tokens,
                cost_usd=0.0,
                succeeded=True,
                run_id="",
            )
            self.budget.record(usage)

        # ponytail: call-level progress, not a token-by-token provider stream.
        explanation = reasoning or chat_resp.content
        text = f"Response from {self.profile.id} / {chat_resp.model}"
        if explanation:
            text += "\nReturned explanation/response:\n" + explanation[:8000]
        requested = [
            str(call.get("function", {}).get("name", "unknown"))
            for call in chat_resp.tool_calls
            if isinstance(call, dict)
        ]
        if requested:
            text += "\nRequested tools: " + ", ".join(requested)
        emit_model_event(
            "call",
            "completed",
            text,
            provider=self.profile.id,
            model=chat_resp.model,
            usage=chat_resp.usage,
        )
        return chat_resp


class ProviderError(Exception):
    """Lỗi HTTP hoặc lỗi phản hồi ở cấp độ provider."""
