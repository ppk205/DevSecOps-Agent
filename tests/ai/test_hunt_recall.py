"""Hunt recall matcher: (file, line ±3) vs native baseline — offline tests."""

from vulnscan.ai.recall import match_candidates_to_native, norm_path, recall_report


def _native():
    return [
        {"file": "a/Login.java", "line": 50, "rule_id": "java-sql-concatenation"},
        {"file": "a/Login.java", "line": 100, "rule_id": "java-xss-response-writer"},
        {"file": "b/app.js", "line": 10, "rule_id": "js-debug-leftover"},
    ]


class TestNormPath:
    def test_backslash_and_dot_prefix(self):
        assert norm_path(".\\a\\Login.java") == "a/Login.java"
        assert norm_path("./a/Login.java") == "a/Login.java"

    def test_empty_safe(self):
        assert norm_path("") == ""


class TestMatch:
    def test_exact_and_tolerance_hits(self):
        candidates = [
            {"file": "a/Login.java", "line": 51},  # +1 -> match
            {"file": "b/app.js", "line": 13},  # +3 -> match (boundary)
        ]
        match = match_candidates_to_native(candidates, _native())
        assert match["matched"] == 2
        assert match["total_native"] == 3
        assert abs(match["recall"] - 2 / 3) < 1e-9

    def test_outside_tolerance_misses(self):
        match = match_candidates_to_native([{"file": "a/Login.java", "line": 54}], _native())
        assert match["matched"] == 0
        assert match["recall"] == 0.0

    def test_wrong_file_misses(self):
        match = match_candidates_to_native([{"file": "a/Other.java", "line": 50}], _native())
        assert match["matched"] == 0

    def test_one_candidate_matches_one_native_only(self):
        candidates = [{"file": "a/Login.java", "line": 50}]
        match = match_candidates_to_native(candidates, _native())
        assert match["matched"] == 1
        assert match["precision"] == 1.0

    def test_empty_native_recall_zero(self):
        match = match_candidates_to_native([{"file": "a.java", "line": 1}], [])
        assert match["recall"] == 0.0
        assert match["matched"] == 0

    def test_by_rule_breakdown(self):
        candidates = [{"file": "a/Login.java", "line": 50}]
        match = match_candidates_to_native(candidates, _native())
        assert match["by_rule"]["java-sql-concatenation"] == {"total": 1, "matched": 1}
        assert match["by_rule"]["java-xss-response-writer"] == {"total": 1, "matched": 0}

    def test_report_mentions_recall(self):
        match = match_candidates_to_native([{"file": "a/Login.java", "line": 50}], _native())
        assert "33.3%" in recall_report(match)
