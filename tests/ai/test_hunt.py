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

    def test_fast_path_parses_opening_json_without_tools(self, tmp_path):
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

        class _ScriptedClient:
            def __init__(self):
                self.calls = 0
                self.used_tools = False

            def chat(self, messages, **kwargs):
                self.calls += 1
                if "tools" in kwargs:
                    self.used_tools = True
                return ChatResponse(
                    content=_json.dumps([vuln]), tool_calls=[], usage={"total_tokens": 10}
                )

        client = _ScriptedClient()
        result = hunt_vulns(snapshot_root=str(tmp_path), client=client, model="m")
        assert result["status"] == "completed"
        assert result["rounds"] == 1
        assert len(result["candidates"]) == 1
        assert client.used_tools is False
        assert client.calls == 1

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


class TestDetectFamilies:
    def test_known_families_in_stable_order(self):
        from vulnscan.ai.hunt import detect_families

        assert detect_families(["a.php", "b.java", "c.py", "d.ts"]) == [
            "java",
            "javascript",
            "python",
            "php",
        ]

    def test_unknown_extension_falls_back_to_generic(self):
        from vulnscan.ai.hunt import detect_families

        assert detect_families(["main.go", "README.md"]) == ["generic"]
        assert detect_families(["a.java", "main.go"]) == ["java", "generic"]

    def test_empty_inventory_still_hunts_generic(self):
        from vulnscan.ai.hunt import detect_families

        assert detect_families([]) == ["generic"]

    def test_cap_respected(self):
        from vulnscan.ai.hunt import detect_families

        assert detect_families(["a.java", "b.py", "c.php", "d.js"], cap=2) == [
            "java",
            "javascript",
        ]


class TestDedupeCandidates:
    def test_exact_duplicates_collapse(self):
        from vulnscan.ai.hunt import dedupe_candidates

        items = [
            {"file": "a.java", "line": 5, "cwe": "CWE-89"},
            {"file": "a.java", "line": 5, "cwe": "CWE-89"},
            {"file": "a.java", "line": 6, "cwe": "CWE-89"},
            {"file": "a.java", "line": 5, "cwe": "CWE-79"},
        ]
        out = dedupe_candidates(items)
        assert len(out) == 3

    def test_empty_safe(self):
        from vulnscan.ai.hunt import dedupe_candidates

        assert dedupe_candidates([]) == []


class TestHuntAll:
    def test_multi_pass_merges_and_dedupes(self, tmp_path):
        import json as _json

        from vulnscan.ai.hunt import hunt_all
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        (tmp_path / "src" / "app.py").write_text("import os\nos.system(cmd)\n")
        vuln_java = {
            "title": "SQLi",
            "file": "src/LoginServlet.java",
            "line": 5,
            "cwe": "CWE-89",
            "severity": "high",
            "rationale": "r",
            "evidence": "stmt.executeQuery(q);",
        }
        vuln_py = {
            "title": "CMDi",
            "file": "src/app.py",
            "line": 2,
            "cwe": "CWE-78",
            "severity": "high",
            "rationale": "r",
            "evidence": "os.system(cmd)",
        }

        class _FamilyClient:
            def chat(self, messages, **kwargs):
                first = messages[0].content if hasattr(messages[0], "content") else ""
                if "Python" in first:
                    return ChatResponse(content=_json.dumps([vuln_py]), tool_calls=[], usage={})
                return ChatResponse(content=_json.dumps([vuln_java]), tool_calls=[], usage={})

        result = hunt_all(
            snapshot_root=str(tmp_path),
            client=_FamilyClient(),
            model="m",
            families=["java", "python"],
            logic_pass=False,
        )
        assert result["status"] == "completed"
        assert [p["family"] for p in result["passes"]] == ["java", "python"]
        assert len(result["candidates"]) == 2

    def test_logic_pass_default_on(self, tmp_path):
        from vulnscan.ai.hunt import hunt_all
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)

        class _EmptyClient:
            def chat(self, messages, **kwargs):
                return ChatResponse(content="[]", tool_calls=[], usage={})

        result = hunt_all(
            snapshot_root=str(tmp_path),
            client=_EmptyClient(),
            model="m",
            families=["java"],
        )
        assert [p["family"] for p in result["passes"]] == ["java", "logic"]


class TestDeepHunt:
    def test_deep_continues_after_fast_path(self, tmp_path):
        import json as _json

        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        first = {
            "title": "SQLi",
            "file": "src/LoginServlet.java",
            "line": 5,
            "cwe": "CWE-89",
            "severity": "high",
            "rationale": "r",
            "evidence": "stmt.executeQuery(q);",
        }
        second = {
            "title": "XSS",
            "file": "src/LoginServlet.java",
            "line": 6,
            "cwe": "CWE-79",
            "severity": "high",
            "rationale": "r2",
            "evidence": "out.println(q);",
        }

        def _call(name, args, call_id):
            return {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": _json.dumps(args)},
            }

        script = [
            ChatResponse(content=_json.dumps([first]), tool_calls=[], usage={}),
            ChatResponse(
                content="",
                tool_calls=[_call("grep_code", {"pattern": "println"}, "c1")],
                usage={},
            ),
            ChatResponse(content=_json.dumps([first, second]), tool_calls=[], usage={}),
        ]

        class _DeepClient:
            def chat(self, messages, **kwargs):
                if kwargs.get("tools"):
                    return script.pop(0)
                return script.pop(0)

        result = hunt_vulns(snapshot_root=str(tmp_path), client=_DeepClient(), model="m", deep=True)
        assert result["status"] == "completed"
        assert result["rounds"] > 1
        assert len(result["candidates"]) == 2

    def test_shallow_unchanged(self, tmp_path):
        import json as _json

        from vulnscan.ai.hunt import hunt_vulns
        from vulnscan.providers.client import ChatResponse

        _snapshot(tmp_path)
        first = {
            "title": "SQLi",
            "file": "src/LoginServlet.java",
            "line": 5,
            "cwe": "CWE-89",
            "severity": "high",
            "rationale": "r",
            "evidence": "stmt.executeQuery(q);",
        }

        class _ShallowClient:
            def chat(self, messages, **kwargs):
                return ChatResponse(content=_json.dumps([first]), tool_calls=[], usage={})

        result = hunt_vulns(snapshot_root=str(tmp_path), client=_ShallowClient(), model="m")
        assert result["status"] == "completed"
        assert result["rounds"] == 1
        assert len(result["candidates"]) == 1
