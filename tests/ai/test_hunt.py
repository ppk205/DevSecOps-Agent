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
