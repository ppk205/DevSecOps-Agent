"""Registered tool definitions for the bounded investigation loop.

Tools are OpenAI function-calling compatible.  The agent may only invoke
these registered tools — no arbitrary code execution, no shell access, no
provider credentials.  Each tool returns a dict that is injected back as
a tool message.
"""

from __future__ import annotations

from typing import Any

# Tool schemas in OpenAI function-calling format
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
]

TOOL_NAME_SET: set[str] = {t["function"]["name"] for t in TOOL_SCHEMAS}
