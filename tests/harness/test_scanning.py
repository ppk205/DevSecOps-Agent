"""Harness scan tool tests: sink rules, literal filtering, inventory, routes."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnscan.harness.scanning import extract_candidates, inventory, lookup_route
from vulnscan.harness.workspace import Candidate, Workspace

SOURCES = {
    "web/Sql.java": 'class Sql { void a(Statement s, String n){\n s.executeQuery("SELECT * FROM u WHERE n=\'" + n + "\'");\n s.executeQuery("SELECT 1"); } }',
    "web/Cmd.java": "class Cmd { void a(String c) throws Exception { Runtime.getRuntime().exec(c); } }",
    "web/Out.java": 'class Out { void a(HttpServletResponse r, String n) throws Exception {\n r.getWriter().write(n);\n r.getWriter().write("ok"); } }',
    "web/Rnd.java": "class Rnd { int a(){ return new Random().nextInt(); } }",
    "web/Sec.java": 'class Sec { boolean a(String s){ return "dev-secret-key-change-me".equals(s); } }',
    "web/Dbg.java": 'class Dbg { void a(PrintWriter out, String otp){ out.write("{\\"debugOtp\\":\\"" + otp + "\\"}"); } }',
    "filters/F.java": 'class F implements Filter { boolean pub(String p){ return p.equals("/api/admin/dashboard"); } }',
    "web/admin/Users.java": '@WebServlet(urlPatterns = {"/api/admin/users"})\nclass Users extends HttpServlet { }',
    "web/admin/Guarded.java": '@WebServlet(urlPatterns = {"/api/admin/x"})\nclass Guarded extends HttpServlet { void d(HttpServletRequest q){ q.getSession().getAttribute("role"); } }',
    "x.jsp": '<p><%= request.getParameter("q") %></p>',
}


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    for rel, text in SOURCES.items():
        if rel.endswith(".java"):
            p = tmp_path / "src/main/java" / rel
        else:
            p = tmp_path / "src/main/webapp" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return Workspace.open(tmp_path)


def kinds(cands: list[Candidate]) -> set[tuple[str, str, str]]:
    return {(Path(c.file).stem, c.kind, c.cwe) for c in cands}


def test_each_sink_rule_fires(ws: Workspace) -> None:
    k = kinds(extract_candidates(ws))
    assert {
        ("Sql", "sql_concat", "CWE-89"),
        ("Cmd", "command", "CWE-78"),
        ("Out", "servlet_xss", "CWE-79"),
        ("Rnd", "weak_random", "CWE-330"),
        ("Sec", "hardcoded_secret", "CWE-798"),
        ("Dbg", "debug_disclosure", "CWE-200"),
        ("F", "public_admin_path", "CWE-306"),
        ("Users", "missing_role_check", "CWE-862"),
        ("x", "jsp_xss", "CWE-79"),
    } <= k
    assert not any(stem == "Guarded" and kind == "missing_role_check" for stem, kind, _ in k)


def test_literal_arguments_are_not_candidates(ws: Workspace) -> None:
    cands = extract_candidates(ws)
    sql = [c.line for c in cands if c.kind == "sql_concat" and c.file.endswith("Sql.java")]
    out = [c.line for c in cands if c.kind == "servlet_xss" and c.file.endswith("Out.java")]
    assert sql == [2] and out == [2]


def test_ids_are_stable_and_filters_apply(ws: Workspace) -> None:
    a = [c.id for c in extract_candidates(ws)]
    assert a == [c.id for c in extract_candidates(ws)]
    assert {c.cwe for c in extract_candidates(ws, classes=["CWE-89"])} == {"CWE-89"}
    assert {Path(c.file).name for c in extract_candidates(ws, paths=["**/*.jsp"])} == {"x.jsp"}


def test_inventory_and_lookup_route(ws: Workspace) -> None:
    inv = {i["path"]: i for i in inventory(ws, ["**/*.java", "**/*.jsp"])}
    assert inv["src/main/webapp/x.jsp"]["kind"] == "jsp"
    assert len(str(inv["src/main/java/web/Sql.java"]["sha256"])) == 64
    r = lookup_route(ws, "/api/admin/users")
    servlets = r["servlets"]
    assert isinstance(servlets, list) and servlets[0]["class"] == "Users"
    assert r["auth_check"] is False


def test_lookup_route_reports_filter_match_basis(ws: Workspace) -> None:
    assert lookup_route(ws, "Users")["filter_match"] == "servlet_pattern"
    assert lookup_route(ws, "/api/admin/users")["filter_match"] == "request_url"


JVA = Path(__file__).resolve().parents[2] / "JVA-bookstore"


@pytest.mark.skipif(not JVA.is_dir(), reason="JVA-bookstore checkout not present")
def test_jva_bookstore_manual_review_cases_are_candidates() -> None:
    k = {(Path(c.file).name, c.cwe) for c in extract_candidates(Workspace.open(JVA))}
    assert {
        ("AdminUsersServlet.java", "CWE-862"),
        ("AdminServlet.java", "CWE-798"),
        ("JwtFilter.java", "CWE-306"),
        ("AuthServlet.java", "CWE-200"),
        ("ShipperApiServlet.java", "CWE-862"),
    } <= k
