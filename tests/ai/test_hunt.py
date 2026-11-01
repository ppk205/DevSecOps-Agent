"""Model hunt pipeline: repo-exploration schemas, jailed handlers, hunt loop."""

from vulnscan.agent.tools import TOOL_NAME_SET, TOOL_SCHEMAS


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
