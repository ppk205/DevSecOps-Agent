"""Model hunt pipeline: repo-exploration schemas, jailed handlers, hunt loop."""

from vulnscan.agent.tools import TOOL_NAME_SET, TOOL_SCHEMAS
from vulnscan.ai.review import build_tool_handlers


def _schema(name):
    return next(t for t in TOOL_SCHEMAS if t["function"]["name"] == name)


class TestExploreSchemas:
    def test_list_files_schema_registered(self):
        assert "list_files" in TOOL_NAME_SET
        schema = _schema("list_files")
        params = schema["function"]["parameters"]
        assert "dir" in params["properties"]
        assert "glob" in params["properties"]
        desc = schema["function"]["description"].lower()
        assert "read-only" in desc
        assert "jail" in desc

    def test_grep_code_schema_registered(self):
        assert "grep_code" in TOOL_NAME_SET
        schema = _schema("grep_code")
        params = schema["function"]["parameters"]
        assert "pattern" in params["required"]
        assert "glob" in params["properties"]
        assert "max_hits" in params["properties"]
        desc = schema["function"]["description"].lower()
        assert "read-only" in desc
        assert "jail" in desc


def _snapshot(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "LoginServlet.java").write_text(
        "import java.sql.*;\n"
        "public class LoginServlet {\n"
        "  public void doPost() {\n"
        '    String q = "SELECT * FROM users WHERE name = \'" + req + "\'";\n'
        "    stmt.executeQuery(q);\n"
        "  }\n"
        "}\n"
    )
    (src / "Safe.java").write_text("public class Safe {}\n")
    return tmp_path


class TestExploreHandlers:
    def test_list_files_lists_fixture_files(self, tmp_path):
        handlers = build_tool_handlers(str(_snapshot(tmp_path)), [])
        result = handlers["list_files"]({"dir": "src", "glob": "*.java"})
        assert "error" not in result
        assert "src/LoginServlet.java" in result["files"]
        assert "src/Safe.java" in result["files"]

    def test_list_files_escape_returns_error(self, tmp_path):
        handlers = build_tool_handlers(str(_snapshot(tmp_path)), [])
        result = handlers["list_files"]({"dir": "../escape", "glob": "*.java"})
        assert "error" in result

    def test_grep_finds_planted_string(self, tmp_path):
        handlers = build_tool_handlers(str(_snapshot(tmp_path)), [])
        result = handlers["grep_code"]({"pattern": "executeQuery\\("})
        assert "error" not in result
        assert any(h["file"] == "src/LoginServlet.java" and h["line"] == 5 for h in result["hits"])

    def test_grep_max_hits_clamped_to_50(self, tmp_path):
        root = _snapshot(tmp_path)
        (root / "src" / "Noisy.java").write_text("x.executeQuery(y);\n" * 60)
        handlers = build_tool_handlers(str(root), [])
        result = handlers["grep_code"]({"pattern": "executeQuery", "max_hits": 500})
        assert "error" not in result
        assert len(result["hits"]) == 50


class TestHunt:
    def test_fake_client_two_vuln_hunt(self, tmp_path):
        import json as _json

        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        vulns = [
            {
                "title": "SQL injection in login",
                "file": "src/LoginServlet.java",
                "line": 5,
                "cwe": "CWE-89",
                "severity": "high",
                "rationale": "request input concatenated into query",
                "evidence": "stmt.executeQuery(q);",
            },
            {
                "title": "Empty POST handler lacks auth check",
                "file": "src/Safe.java",
                "line": 1,
                "cwe": "CWE-862",
                "severity": "medium",
                "rationale": "no authorization check present",
                "evidence": "public class Safe {}",
            },
        ]

        def _call(name, args, call_id):
            return {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": _json.dumps(args)},
            }

        script = [
            ChatResponse(
                content="",
                tool_calls=[_call("list_files", {"dir": "src", "glob": "*.java"}, "c1")],
                usage={"total_tokens": 10},
            ),
            ChatResponse(
                content="",
                tool_calls=[_call("inspect_code", {"file_path": "src/LoginServlet.java"}, "c2")],
                usage={"total_tokens": 20},
            ),
            ChatResponse(content=_json.dumps(vulns), tool_calls=[], usage={"total_tokens": 30}),
        ]

        class _ScriptedClient:
            def __init__(self):
                self.calls = 0

            def chat(self, messages, **kwargs):
                self.calls += 1
                return script.pop(0)

        result = hunt_vulns(snapshot_root=str(tmp_path), client=_ScriptedClient(), model="m")
        assert result["status"] == "completed"
        assert len(result["candidates"]) == 2
        for cand in result["candidates"]:
            for field in ("title", "file", "line", "cwe", "severity", "rationale", "evidence"):
                assert field in cand
        assert result["candidates"][0]["file"] == "src/LoginServlet.java"
        assert result["rounds"] == 3

    def test_closing_call_fallback_when_tools_yield_no_content(self, tmp_path):
        import json as _json

        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        vuln = {
            "title": "SQL injection in login",
            "file": "src/LoginServlet.java",
            "line": 5,
            "cwe": "CWE-89",
            "severity": "high",
            "rationale": "request input concatenated into query",
            "evidence": "stmt.executeQuery(q);",
        }

        def _call(name, args, call_id):
            return {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": _json.dumps(args)},
            }

        script = [
            ChatResponse(
                content="",
                tool_calls=[_call("list_files", {"dir": "src", "glob": "*.java"}, "c1")],
                usage={"total_tokens": 10},
            ),
            # Reasoning-only gateway: empty content, no tool calls -> loop ends.
            ChatResponse(content="", tool_calls=[], usage={"total_tokens": 20}),
            # Closing no-tools call returns the JSON list.
            ChatResponse(content=_json.dumps([vuln]), tool_calls=[], usage={"total_tokens": 30}),
        ]

        class _ScriptedClient:
            def __init__(self):
                self.calls = 0
                self.saw_no_tools_call = False

            def chat(self, messages, **kwargs):
                self.calls += 1
                if "tools" not in kwargs:
                    self.saw_no_tools_call = True
                return script.pop(0)

        client = _ScriptedClient()
        result = hunt_vulns(snapshot_root=str(tmp_path), client=client, model="m")
        assert result["status"] == "completed"
        assert len(result["candidates"]) == 1
        assert result["candidates"][0]["cwe"] == "CWE-89"
        assert client.saw_no_tools_call is True

    def test_closing_call_includes_sink_sweep(self, tmp_path):

        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        seen_prompts: list[str] = []
        script = [
            ChatResponse(content="", tool_calls=[], usage={"total_tokens": 10}),
            ChatResponse(content="[]", tool_calls=[], usage={"total_tokens": 20}),
        ]

        class _ScriptedClient:
            def chat(self, messages, **kwargs):
                if "tools" not in kwargs:
                    seen_prompts.append(messages[-1].content)
                return script.pop(0)

        hunt_vulns(snapshot_root=str(tmp_path), client=_ScriptedClient(), model="m")
        assert seen_prompts and "Sink sweep" in seen_prompts[0]
        assert "src/LoginServlet.java" in seen_prompts[0]

    def test_provider_error_returns_failed(self, tmp_path):
        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ProviderError

        class _BoomClient:
            def chat(self, messages, **kwargs):
                raise ProviderError("gateway down")

        result = hunt_vulns(snapshot_root=str(tmp_path), client=_BoomClient(), model="m")
        assert result["status"] == "failed"
        assert result["candidates"] == []
