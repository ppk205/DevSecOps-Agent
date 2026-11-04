"""Real provider parsing and AI pipeline with synthetic HTTP responses only."""

import os
import sys
from json import dumps, loads
from pathlib import Path

import httpx

from tests.platform import rpc_fixture
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core import rpc
from vulnscan.infra import envfile
from vulnscan.providers import profile_store
from vulnscan.providers.client import ProviderClient


def main():
    db_path = Path(sys.argv[sys.argv.index("--db-path") + 1])
    original_envfile = envfile.EnvFile

    class FixtureEnvFile(original_envfile):
        def __init__(self):
            super().__init__(db_path.parent / ".env")

    envfile.EnvFile = FixtureEnvFile
    rpc.EnvFile = FixtureEnvFile
    profile = ProviderProfile(
        id="offline-native",
        label="Offline native test",
        protocol="openai_compatible",
        base_url="https://offline.invalid/v1",
        api_key_env="OFFLINE_NATIVE_API_KEY",
        models=["fixture-model"],
        default_model="fixture-model",
        max_retries=0,
    )
    unavailable = bool(os.environ.get("DEVSECOPS_FIXTURE_AI_UNAVAILABLE"))

    def load_profile(identifier, base=None):
        if unavailable or identifier != profile.id:
            raise FileNotFoundError("offline provider unavailable")
        return profile

    profile_store.load_profile = load_profile
    profile_store.list_profiles = lambda base=None: [] if unavailable else [profile]
    profile_store.default_profile = lambda base=None: None if unavailable else profile
    rpc.load_profile = load_profile
    rpc.list_profiles = profile_store.list_profiles
    # Modules may already have bound their profile loader during imports.
    from vulnscan.ai import laya_verify, review
    from vulnscan.reporting import final_report

    review.load_profile = load_profile
    final_report.load_profile = load_profile
    laya_verify.laya_verify_candidates = lambda candidates, **kwargs: [
        {**candidate, "laya_status": "skipped", "laya_skip_reason": "offline fixture"}
        for candidate in candidates
    ]
    ProviderClient._get_key = lambda self: "synthetic-offline-credential"
    if not unavailable:
        os.environ[profile.api_key_env] = "synthetic-offline-credential"

    class FixtureHTTP:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, *, json: dict, headers):
            request = httpx.Request("POST", url)
            if os.environ.get("DEVSECOPS_FIXTURE_AI_FAIL"):
                raise httpx.ConnectError("offline fixture failure", request=request)
            messages = json["messages"]
            system = " ".join(m.get("content", "") for m in messages if m["role"] == "system")
            reasoning = "Fixture explanation: inspect cited source and preserve uncertainty."
            if "security hunter" in system:
                content = '[{"title":"Fixture candidate","file":"Example.java","line":1,"cwe":"CWE-89","severity":"low","rationale":"Fixture candidate needs review","evidence":"class Example {}"}]'
                message = {"content": content, "reasoning_content": reasoning}
            elif json.get("tools") and not any(m["role"] == "tool" for m in messages):
                message = {
                    "content": "",
                    "reasoning_content": reasoning,
                    "tool_calls": [
                        {
                            "id": "fixture-inspect",
                            "type": "function",
                            "function": {
                                "name": "inspect_code",
                                "arguments": '{"file_path":"Example.java","start_line":1,"end_line":1}',
                            },
                        }
                    ],
                }
            elif len(messages) == 1:
                message = {
                    "content": "# Fixture AI report\n\nEvidence needs human review.",
                    "reasoning_content": reasoning,
                }
            else:
                if any(m["role"] == "tool" for m in messages):
                    assert all(m.get("tool_call_id") for m in messages if m["role"] == "tool")
                    assert any(m.get("tool_calls") for m in messages if m["role"] == "assistant")
                message = {
                    "content": '{"proposed_status":"unresolved","confidence":0.4,"rationale":"Fixture explanation: evidence needs human review."}',
                    "reasoning_content": reasoning,
                }
            if os.environ.get("DEVSECOPS_FIXTURE_CVSS"):
                try:
                    proposal = loads(message.get("content", ""))
                except ValueError:
                    proposal = None
                if isinstance(proposal, dict) and "proposed_status" in proposal:
                    proposal["cvss_vector"] = (
                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    )
                    proposal["assumptions"] = [
                        "Fixture assumption requires independent verification"
                    ]
                    proposal["base_score"] = 1.0  # Must never become the recorded score.
                    message["content"] = dumps(proposal)
            payload = {
                "choices": [{"message": message, "finish_reason": "stop"}],
                "model": json["model"],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            }
            return httpx.Response(200, json=payload, request=request)

    # Replacing this transport prevents all real HTTP calls in the fixture process.
    import vulnscan.providers.client as client_module

    client_module.httpx.Client = FixtureHTTP
    os.environ["DEVSECOPS_FIXTURE_NATIVE_HUNT"] = "1"
    rpc_fixture.main()


if __name__ == "__main__":
    main()
