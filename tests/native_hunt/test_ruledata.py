"""Native hunt rule packs must be valid, complete ports of the Semgrep rules.

Each ``src/vulnscan/native_hunt/rules/<language>.json`` file is a regex port
of ``src/vulnscan/scanners/rules/<language>.yml``: it must parse as JSON,
carry every required key per rule, hold only compilable regexes, keep rule
ids unique across all packs, meet the minimum rule counts, and cover every
core attack class per language.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "src" / "vulnscan" / "native_hunt" / "rules"

# language -> minimum rule count (java 12, others 10 each).
MIN_COUNTS = {
    "java": 12,
    "javascript": 10,
    "python": 10,
    "php": 10,
    "go": 10,
    "ruby": 10,
    "csharp": 10,
}

REQUIRED_KEYS = {"id", "languages", "severity", "message", "cwe", "attack", "patterns"}

REQUIRED_ATTACKS = {
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "ssrf",
    "xxe",
    "deserialization",
}

ID_PREFIXES = {
    "java": "java-",
    "javascript": "js-",
    "python": "py-",
    "php": "php-",
    "go": "go-",
    "ruby": "rb-",
    "csharp": "cs-",
}


def load_pack(language: str) -> dict:
    with open(RULES_DIR / f"{language}.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("language", sorted(MIN_COUNTS))
def test_pack_is_valid_json_with_language_key(language: str) -> None:
    pack = load_pack(language)
    assert pack["language"] == language
    assert isinstance(pack["rules"], list)
    assert pack["rules"], f"{language}.json holds no rules"


@pytest.mark.parametrize("language, minimum", sorted(MIN_COUNTS.items()))
def test_pack_meets_minimum_rule_count(language: str, minimum: int) -> None:
    assert len(load_pack(language)["rules"]) >= minimum


@pytest.mark.parametrize("language", sorted(MIN_COUNTS))
def test_rules_carry_required_keys(language: str) -> None:
    for rule in load_pack(language)["rules"]:
        assert REQUIRED_KEYS <= set(rule), f"{rule.get('id')}: missing keys"


@pytest.mark.parametrize("language", sorted(MIN_COUNTS))
def test_rule_field_shapes(language: str) -> None:
    for rule in load_pack(language)["rules"]:
        assert rule["severity"] in {"ERROR", "WARNING"}, rule["id"]
        assert re.fullmatch(r"\d+", str(rule["cwe"])), rule["id"]
        assert isinstance(rule["languages"], list) and rule["languages"], rule["id"]
        assert isinstance(rule["message"], str) and rule["message"].strip(), rule["id"]
        assert isinstance(rule["attack"], str) and rule["attack"].strip(), rule["id"]
        assert isinstance(rule["patterns"], list) and rule["patterns"], rule["id"]
        for pattern in rule["patterns"]:
            assert isinstance(pattern, str) and pattern.strip(), rule["id"]
        prefix = ID_PREFIXES[language]
        assert str(rule["id"]).startswith(prefix), rule["id"]


@pytest.mark.parametrize("language", sorted(MIN_COUNTS))
def test_patterns_compile(language: str) -> None:
    for rule in load_pack(language)["rules"]:
        for pattern in rule["patterns"]:
            re.compile(pattern)


def test_ids_unique_across_packs() -> None:
    seen: dict[str, str] = {}
    for language in MIN_COUNTS:
        for rule in load_pack(language)["rules"]:
            assert rule["id"] not in seen, f"{rule['id']} in {language} and {seen.get(rule['id'])}"
            seen[rule["id"]] = language


@pytest.mark.parametrize("language", sorted(MIN_COUNTS))
def test_pack_covers_required_attacks(language: str) -> None:
    attacks = {rule["attack"] for rule in load_pack(language)["rules"]}
    assert REQUIRED_ATTACKS <= attacks, f"{language}: missing {REQUIRED_ATTACKS - attacks}"
