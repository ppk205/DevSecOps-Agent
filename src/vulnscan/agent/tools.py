"""Các định nghĩa công cụ đã đăng ký cho vòng lặp điều tra có giới hạn.

Các công cụ tương thích với OpenAI function-calling. Agent chỉ có thể gọi
các công cụ đã đăng ký này — không thực thi code tùy ý, không truy cập shell, không
có thông tin xác thực provider. Mỗi công cụ trả về một dict được đưa ngược lại dưới dạng
tool message.
"""

from __future__ import annotations

from typing import Any

# Định nghĩa schema công cụ theo định dạng OpenAI function-calling
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "inspect_code",
            "description": (
                "Read source code at a file path and optional line range. "
                "Returns the requested lines with context."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative or absolute path to the source file.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-indexed).",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (inclusive).",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_route",
            "description": (
                "Look up Servlet routes, filters, and URL mappings for a class or pattern. "
                "Uses the source index built from web.xml and annotations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Class name, URL pattern, or annotation to search for.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_evidence",
            "description": (
                "Retrieve scanner observations, context evidence, and "
                "policy references for a finding ID."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding to look up evidence for.",
                    },
                },
                "required": ["finding_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_coverage",
            "description": (
                "Check ACC-07 coverage records: which files were analyzed, "
                "which were skipped, and per-CWE capability."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cwe": {"type": "string", "description": "Optional CWE to filter coverage by."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_verification",
            "description": (
                "Propose a verification procedure for a finding. Returns a "
                "procedure definition with security property, test steps, "
                "and expected outcomes for both vulnerable and fixed variants."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "The finding to verify."},
                    "verification_level": {
                        "type": "string",
                        "enum": ["static", "junit", "sandbox"],
                        "description": "Level of verification to propose.",
                    },
                },
                "required": ["finding_id", "verification_level"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "List files in the scan snapshot matching a glob. "
                "Read-only, jailed to the snapshot, no shell. "
                "max_hits capped at 50 server-side."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dir": {
                        "type": "string",
                        "description": "Directory inside the snapshot to list (repo-relative, default '.').",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Filename glob to match (default '*.java').",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_code",
            "description": (
                "Search snapshot source with a regex, returning file:line hits. "
                "Read-only, jailed to the snapshot, no shell. "
                "max_hits capped at 50 server-side."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression to search for.",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Filename glob to restrict the search (default '*.java').",
                    },
                    "max_hits": {
                        "type": "integer",
                        "description": "Maximum hits to return (default 20, capped at 50).",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_semgrep_scan",
            "description": (
                "Run Semgrep AST/pattern static analysis on a file or directory inside "
                "the scan snapshot across any of the 7 supported language families "
                "(java, javascript, python, php, go, cpp, csharp). Jailed to the snapshot; "
                "returns compact, token-optimized findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Repo-relative file or directory path to scan (default '.').",
                    },
                    "ruleset": {
                        "type": "string",
                        "description": (
                            "Optional ruleset pack (e.g. 'java', 'python', 'p/owasp-top-ten')."
                        ),
                    },
                    "cwe": {
                        "type": "string",
                        "description": "Optional CWE filter (e.g. 'CWE-89', 'CWE-79').",
                    },
                    "language": {
                        "type": "string",
                        "enum": ["java", "javascript", "python", "php", "go", "cpp", "csharp"],
                        "description": "Optional language family hint.",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum findings returned (default 15, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_codeql_scan",
            "description": (
                "Run CodeQL deep inter-procedural dataflow and taint tracking across "
                "supported language families (java, javascript, python, go, cpp, csharp). "
                "Jailed to the snapshot; returns compact findings or explicit status if "
                "CodeQL CLI is unavailable."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Optional repo-relative path to filter findings by (default '.').",
                    },
                    "query_suite": {
                        "type": "string",
                        "description": (
                            "Optional CodeQL query suite (e.g. 'java-security-extended.qls')."
                        ),
                    },
                    "cwe": {
                        "type": "string",
                        "description": "Optional CWE filter (e.g. 'CWE-89').",
                    },
                    "language": {
                        "type": "string",
                        "enum": ["java", "javascript", "python", "php", "go", "cpp", "csharp"],
                        "description": "Optional language family to analyze.",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum findings returned (default 15, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_owasp_scan",
            "description": (
                "Run OWASP Dependency-Check (with automatic OSV.dev fallback) to extract "
                "known CVEs from third-party dependency manifests across all 7 language "
                "families (pom.xml, package-lock.json, requirements.txt, composer.lock/json, "
                "go.mod, conanfile.txt, vcpkg.json, *.csproj). Jailed to the snapshot."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "manifest_path": {
                        "type": "string",
                        "description": "Optional repo-relative path to a specific manifest file.",
                    },
                    "min_cvss": {
                        "type": "number",
                        "description": "Optional minimum CVSS score filter (e.g. 7.0 for High/Critical).",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum CVEs returned (default 15, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_scan",
            "description": (
                "Run Gitleaks secret detection to uncover hard-coded API keys, tokens, "
                "private keys, and credentials across all 7 language stacks and optional "
                "git history. Jailed to the snapshot; secrets are redacted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Repo-relative file or directory path to scan (default '.').",
                    },
                    "scan_git_history": {
                        "type": "boolean",
                        "description": "If true, inspect git commit history in addition to working files.",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum secret findings returned (default 15, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_config_audit",
            "description": (
                "Run deep Java bytecode analysis (SpotBugs + FindSecBugs) or IaC/container "
                "configuration audit (Trivy on Dockerfile, Kubernetes, Terraform, CI YAML). "
                "Jailed to the snapshot."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Repo-relative file or directory path to audit (default '.').",
                    },
                    "check_type": {
                        "type": "string",
                        "enum": ["auto", "bytecode", "iac_config"],
                        "description": "Audit mode: 'bytecode' (SpotBugs), 'iac_config' (Trivy), or 'auto'.",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum findings returned (default 15, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_scanner_findings",
            "description": (
                "Query and filter consolidated findings from pre-existing scan results and "
                "in-session scanner calls without re-running tools. Saves time and tokens."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Filter by tool name ('semgrep', 'codeql', 'owasp', 'gitleaks', 'spotbugs', 'trivy', or 'all').",
                    },
                    "cwe": {
                        "type": "string",
                        "description": "Optional CWE filter (e.g. 'CWE-89').",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional substring filter on source file path.",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Minimum severity threshold.",
                    },
                    "max_items": {
                        "type": "integer",
                        "description": "Maximum findings returned (default 20, capped at 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_scanner_rule",
            "description": (
                "Look up the definition, CWE mapping, OWASP category, and remediation "
                "guidance for a scanner rule ID (Semgrep, CodeQL, Trivy, SpotBugs, OSV)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "The scanner rule identifier to explain.",
                    },
                    "tool": {
                        "type": "string",
                        "description": "Optional scanner tool name.",
                    },
                },
                "required": ["rule_id"],
            },
        },
    },
]

TOOL_NAME_SET: set[str] = {t["function"]["name"] for t in TOOL_SCHEMAS}

SCANNER_TOOL_NAME_SET: set[str] = {
    "run_semgrep_scan",
    "run_codeql_scan",
    "run_owasp_scan",
    "run_secret_scan",
    "run_config_audit",
    "query_scanner_findings",
    "explain_scanner_rule",
}
