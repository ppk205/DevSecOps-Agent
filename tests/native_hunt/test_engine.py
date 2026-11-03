"""Native taint-hunt engine: taint flow, sanitizer kill, confidence, skip, missing input."""

from __future__ import annotations

from pathlib import Path

from vulnscan.native_hunt import MAX_FILE_BYTES, load_rules, scan_file, scan_snapshot
from vulnscan.native_hunt.taint import Rule, Sanitizer


def _sqli_rule() -> Rule:
    return Rule(
        id="t-sqli",
        cwe="CWE-89",
        attack="sqli",
        severity="high",
        sources=[r"request\.(args|form)"],
        sinks=[r"\.execute\s*\("],
        sanitizers=[],
    )


def _xss_rule(prevent: list[str] | None = None) -> Rule:
    return Rule(
        id="t-xss",
        cwe="CWE-79",
        attack="xss",
        severity="high",
        sources=[r"request\.args"],
        sinks=[r"\brender\s*\("],
        sanitizers=[Sanitizer(pattern=r"escape\s*\(", prevent=prevent if prevent else ["xss"])],
    )


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_load_rules_ported_pack() -> None:
    rules = load_rules("python")
    assert {r.id for r in rules} >= {"py-sql-injection", "py-command-injection"}
    assert all(isinstance(r, Rule) and r.sinks for r in rules)
    assert all(r.sources for r in rules)  # ported packs get family default sources


def test_load_rules_taint_pack() -> None:
    rules = load_rules("generic")
    assert [r.id for r in rules] == ["gen-code-exec"]
    assert rules[0].sources and rules[0].sinks


def test_load_rules_unknown_family_is_empty() -> None:
    assert load_rules("no-such-family") == []


def test_taint_direct_and_propagated(tmp_path: Path) -> None:
    target = _write(
        tmp_path / "vuln.py", 'u = request.args.get("q")\ncursor.execute("SELECT " + u)\n'
    )
    findings = scan_file(target, [_sqli_rule()])
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.line, finding.confidence) == ("t-sqli", 2, "High")
    assert finding.source_line == 1


def test_confidence_high_medium_weak(tmp_path: Path) -> None:
    rule = _sqli_rule()
    direct = _write(tmp_path / "d.py", 'cursor.execute(request.args.get("q"))\n')
    assert scan_file(direct, [rule])[0].confidence == "High"
    one_hop = _write(tmp_path / "m.py", 'a = request.args.get("q")\nb = a\ncursor.execute(b)\n')
    assert scan_file(one_hop, [rule])[0].confidence == "Medium"
    two_hop = _write(
        tmp_path / "w.py", 'a = request.args.get("q")\nb = a\nc = b\ncursor.execute(c)\n'
    )
    assert scan_file(two_hop, [rule])[0].confidence == "Weak"


def test_sink_only_rule_reports_weak(tmp_path: Path) -> None:
    rule = Rule(id="t-eval", cwe="CWE-95", attack="code", severity="medium", sinks=[r"\beval\s*\("])
    target = _write(tmp_path / "e.py", "eval(data)\n")
    findings = scan_file(target, [rule])
    assert len(findings) == 1
    assert (findings[0].confidence, findings[0].source_line) == ("Weak", None)


def test_sanitizer_kills_propagated_taint(tmp_path: Path) -> None:
    target = _write(tmp_path / "s.py", 'u = request.args.get("q")\nv = escape(u)\nrender(v)\n')
    assert scan_file(target, [_xss_rule()]) == []


def test_sanitizer_at_sink_line_suppresses(tmp_path: Path) -> None:
    target = _write(tmp_path / "s.py", 'u = request.args.get("q")\nrender(escape(u))\n')
    assert scan_file(target, [_xss_rule()]) == []


def test_sanitizer_wrong_attack_keeps_finding(tmp_path: Path) -> None:
    rule = _sqli_rule()
    rule.sanitizers = [Sanitizer(pattern=r"escape\s*\(", prevent=["xss"])]
    target = _write(
        tmp_path / "v.py", 'u = request.args.get("q")\nv = escape(u)\ncursor.execute(v)\n'
    )
    findings = scan_file(target, [rule])
    assert len(findings) == 1


def test_clean_reassignment_kills_taint(tmp_path: Path) -> None:
    target = _write(
        tmp_path / "v.py", 'u = request.args.get("q")\nu = "static"\ncursor.execute(u)\n'
    )
    assert scan_file(target, [_sqli_rule()]) == []


def test_scan_snapshot_skips_oversized(tmp_path: Path) -> None:
    _write(tmp_path / "vuln.py", 'u = request.args.get("q")\ncursor.execute("SELECT " + u)\n')
    (tmp_path / "bundle.py").write_bytes(b"x = 1\n" * ((MAX_FILE_BYTES // 6) + 10))
    result = scan_snapshot(tmp_path, ["python"])
    assert any(f.file == "vuln.py" for f in result.findings)
    assert "bundle.py" in result.skipped
    assert "bundle.py" not in result.scanned
    assert "vuln.py" in result.scanned


def test_missing_inputs_yield_empty_results(tmp_path: Path) -> None:
    assert scan_file(tmp_path / "absent.py", [_sqli_rule()]) == []
    result = scan_snapshot(tmp_path / "absent-dir", ["python"])
    assert result.findings == [] and result.scanned == [] and result.skipped == []


def test_typed_declaration_taints_var_not_type(tmp_path) -> None:
    from vulnscan.native_hunt import load_rules, scan_file

    target = tmp_path / "T.java"
    target.write_text(
        "String user = req.getParameter(\"u\");\n"
        "ResultSet rs = st.executeQuery(\"SELECT '\" + user + \"'\");\n",
        encoding="utf-8",
    )
    findings = scan_file(target, load_rules("java"))
    assert any(
        f.rule_id == "java-sql-concatenation" and f.line == 2 for f in findings
    )


def test_minified_and_longline_files_skipped(tmp_path) -> None:
    from vulnscan.native_hunt import load_rules, scan_file, scan_snapshot

    rules = load_rules("javascript")
    mini = tmp_path / "a.min.js"
    mini.write_text("eval(x);\n", encoding="utf-8")
    big = tmp_path / "b.js"
    big.write_text("var s = '" + "x" * 5000 + "';\neval(s);\n", encoding="utf-8")
    assert scan_file(mini, rules) == []
    assert scan_file(big, rules) == []
    res = scan_snapshot(tmp_path, ["javascript"])
    assert res.findings == []
    assert len(res.skipped) == 2


def test_entry_param_and_call_propagation(tmp_path) -> None:
    from vulnscan.native_hunt import load_rules, scan_file

    target = tmp_path / "C.java"
    target.write_text(
        "public AttackResult completed(@RequestParam(value = \"u\") String userId) {\n"
        "    return injectableQuery(userId);\n"
        "}\n"
        "public AttackResult injectableQuery(String accountName) {\n"
        "    String query = \"SELECT * WHERE name = '\" + accountName + \"'\";\n"
        "    ResultSet r = st.executeQuery(query);\n"
        "    return null;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = scan_file(target, load_rules("java"))
    assert any(
        f.rule_id == "java-sql-concatenation" and f.line == 6 for f in findings
    )
