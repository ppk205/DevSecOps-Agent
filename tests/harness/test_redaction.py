"""Redaction keeps real code intact while masking key-shaped values."""

from __future__ import annotations

import json

import pytest

from vulnscan.providers.credentials import redact, redact_json, redact_value

KEY = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"


def test_redact_keeps_java_identifiers() -> None:
    for value in [
        "token.isEmpty()",
        "import io.jsonwebtoken.Claims;",
        "apiEndpointUrl",
        "+    if (tokenService.verify(jwt)) {",
        "task_candidates",
        "tokenizer.json",
    ]:
        assert redact(value) == value


@pytest.mark.parametrize(
    "secret",
    [
        KEY,
        "sk-" + "Z" * 32,
        "ghp_" + "a" * 36,
        "github_pat_" + "b" * 30,
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "xoxb-" + "1" * 20,
    ],
)
def test_redact_masks_key_shapes(secret: str) -> None:
    redacted = redact(f"x={secret};")
    assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_redact_masks_bearer_header() -> None:
    token = "abcdefghijklmnopqrstuvwxyz0123"
    redacted = redact(f"Authorization: Bearer {token}")
    assert token not in redacted
    assert "Bearer [REDACTED]" in redacted


def test_redact_masks_loaded_env_key_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXTURE_API_KEY", "plain-value-without-prefix")
    assert "plain-value-without-prefix" not in redact("echo plain-value-without-prefix")


def test_redact_json_never_breaks_json() -> None:
    value = {"code": "\tokHttpClientBuilderInstance x;", "k": KEY, "n": [1, None, "\tok"]}
    out = json.loads(redact_json(value))
    assert out["code"] == value["code"]
    assert out["n"] == value["n"]
    assert KEY not in out["k"]


def test_redact_value_is_a_deep_copy() -> None:
    value = {"a": [KEY, {"b": "token.isEmpty()"}], "n": 3}
    out = redact_value(value)
    assert out is not value
    assert out["a"] is not value["a"]
    assert out["a"][1]["b"] == "token.isEmpty()"
    assert KEY not in out["a"][0]
    assert value["a"][0] == KEY


def test_gate_event_with_tab_code_survives_log(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from vulnscan.harness.audit import SessionLog

    log = SessionLog(tmp_path / "s.jsonl")
    log.append({"type": "gate", "payload": {"code": "\tokHttpClientBuilderInstance"}})
    assert log.events()[0]["payload"]["code"] == "\tokHttpClientBuilderInstance"


def test_provider_round_trip_keeps_code() -> None:
    import httpx

    from vulnscan.harness.messages import Message
    from vulnscan.harness.providers import BUILTIN_PROFILES, ChatCompletionsTransport

    reply_diff = "+    if (tokenService.verify(jwt)) {"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {
                                        "name": "propose_fix",
                                        "arguments": json.dumps({"diff": reply_diff}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

    profile = BUILTIN_PROFILES["ollama"].model_copy(update={"api_key_env": ""})
    transport = ChatCompletionsTransport(
        profile, "fixture", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    reply = transport.complete("review", [Message("user", "token.isEmpty()")], [])
    assert "token.isEmpty()" in seen[0]
    assert reply.message.tool_calls[0].arguments["diff"] == reply_diff
