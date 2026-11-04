"""Native-hunt packs for Go, Ruby, and C#: Vuln fires, Safe stays silent.

One batched ``scan_snapshot`` covers every fixture; each Vuln file must
raise exactly its pack's rule set and no rule from another family may
fire on any file (suffix-gated packs + generic only).
"""

from __future__ import annotations

from pathlib import Path

from vulnscan.native_hunt import FAMILY_EXTENSIONS, load_rules, scan_file, scan_snapshot

FIXTURES = Path(__file__).resolve().parent / "fixtures"

GO_EXPECTED = {
    "go-sql-concatenation",
    "go-command-injection",
    "go-reflected-xss",
    "go-path-traversal",
    "go-ssrf",
    "go-open-redirect",
    "go-template-injection",
    "go-weak-hash",
    "go-insecure-random",
    "go-tls-verify-off",
    "go-deserialization-gob",
    "go-xxe",
    "go-log-injection",
}

RUBY_EXPECTED = {
    "rb-sql-concatenation",
    "rb-command-injection",
    "rb-reflected-xss",
    "rb-path-traversal",
    "rb-ssrf",
    "rb-open-redirect",
    "rb-code-injection-eval",
    "rb-deserialization",
    "rb-xxe",
    "rb-weak-hash",
    "rb-insecure-random",
    "rb-tls-verify-none",
    "rb-template-injection",
}

CSHARP_EXPECTED = {
    "cs-sql-concatenation",
    "cs-command-injection",
    "cs-reflected-xss",
    "cs-path-traversal",
    "cs-ssrf",
    "cs-open-redirect",
    "cs-ldap-injection",
    "cs-xpath-injection",
    "cs-xxe",
    "cs-weak-hash",
    "cs-deserialization",
    "cs-insecure-random",
    "cs-header-injection",
    "cs-code-injection",
}

# File suffix -> rule-id prefix expected on findings for that file.
PREFIX_BY_SUFFIX = {
    ".go": "go-",
    ".rb": "rb-",
    ".erb": "rb-",
    ".cs": "cs-",
    ".cshtml": "cs-",
    ".razor": "cs-",
}


def test_family_extensions_cover_new_languages() -> None:
    assert FAMILY_EXTENSIONS["go"] == frozenset({".go"})
    assert FAMILY_EXTENSIONS["ruby"] == frozenset({".rb", ".erb"})
    assert FAMILY_EXTENSIONS["csharp"] == frozenset({".cs", ".cshtml", ".razor"})


def test_batched_vuln_fires_safe_silent_no_cross_language() -> None:
    result = scan_snapshot(FIXTURES, ["go", "ruby", "csharp"])

    by_file: dict[str, set[str]] = {}
    for finding in result.findings:
        by_file.setdefault(finding.file, set()).add(finding.rule_id)

    assert by_file.get("go/Vuln.go", set()) == GO_EXPECTED
    assert by_file.get("ruby/Vuln.rb", set()) == RUBY_EXPECTED
    assert by_file.get("csharp/Vuln.cs", set()) == CSHARP_EXPECTED

    assert by_file.get("go/Safe.go", set()) == set()
    assert by_file.get("ruby/Safe.rb", set()) == set()
    assert by_file.get("csharp/Safe.cs", set()) == set()

    # Template views are scanned through their family extensions.
    assert "ruby/View.erb" in result.scanned
    assert "csharp/View.cshtml" in result.scanned

    # No finding may carry another family's rule prefix (generic has none).
    for finding in result.findings:
        suffix = Path(finding.file).suffix
        assert finding.rule_id.startswith(PREFIX_BY_SUFFIX[suffix]), finding


def test_go_walrus_assignment_taints(tmp_path: Path) -> None:
    target = tmp_path / "v.go"
    target.write_text(
        'name := r.URL.Query().Get("n")\n'
        'w.Write([]byte("hello " + name))\n',
        encoding="utf-8",
    )
    findings = scan_file(target, load_rules("go"))
    assert any(f.rule_id == "go-reflected-xss" for f in findings)

    clean = tmp_path / "c.go"
    clean.write_text(
        'if (a == r.URL.Query().Get("n")) {\n'
        '    w.Write([]byte("static"))\n'
        "}\n",
        encoding="utf-8",
    )
    assert scan_file(clean, load_rules("go")) == []


def test_csharp_fromquery_entry_param_taints(tmp_path: Path) -> None:
    target = tmp_path / "C.cs"
    target.write_text(
        "public IActionResult Greet([FromQuery] string who) {\n"
        '    Response.Write("Hi " + who);\n'
        "}\n",
        encoding="utf-8",
    )
    findings = scan_file(target, load_rules("csharp"))
    assert any(f.rule_id == "cs-reflected-xss" for f in findings)


def test_ruby_sanitizer_kills_command(tmp_path: Path) -> None:
    target = tmp_path / "v.rb"
    target.write_text(
        "qq = params[:qq]\n"
        'system("ls", Shellwords.escape(qq))\n',
        encoding="utf-8",
    )
    assert scan_file(target, load_rules("ruby")) == []
