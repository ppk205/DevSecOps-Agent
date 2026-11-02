"""Matching rules for the experiment: one item, one credit."""

from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path

import pytest

from vulnscan.experiment.groundtruth import (
    GTItem,
    Row,
    load_equivalence,
    load_gt,
    match,
)

GT_HEADER = "id,file,line_start,line_end,cwe,kind,origin,cvss_vector,labeller_a,labeller_b,agreed\n"


def write_gt(path: Path, rows: list[str]) -> Path:
    path.write_text(GT_HEADER + "".join(row + "\n" for row in rows), encoding="utf-8")
    return path


def item(
    item_id: str = "g1",
    file: str = "src/A.java",
    start: int = 10,
    end: int = 10,
    cwe: str = "CWE-89",
    kind: str = "vuln",
    agreed: bool = True,
) -> GTItem:
    return GTItem(
        id=item_id,
        file=file,
        line_start=start,
        line_end=end,
        cwe=cwe,
        kind=kind,  # type: ignore[arg-type]
        origin="builtin",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        labeller_a="A",
        labeller_b="B",
        agreed=agreed,
    )


def row(
    line: int = 10,
    file: str = "src/A.java",
    cwe: str = "CWE-89",
    config: str = "S2",
    run: int = 1,
) -> Row:
    return Row(
        config=config,
        run=run,
        file=file,
        line=line,
        cwe=cwe,
        severity="high",
        cvss_vector=None,
        stage="proposed",
        source_id=f"{config}-{run}-{line}",
    )


def test_exact_match_is_tp() -> None:
    result = match([row()], [item()], {})
    assert len(result.tp) == 1 and not result.fp and not result.fn


def test_line_window() -> None:
    assert match([row(line=13)], [item()], {}, window=3).tp
    assert not match([row(line=14)], [item()], {}, window=3).tp
    assert match([row(line=14)], [item()], {}, window=3).fp


def test_cwe_equivalence_is_explicit() -> None:
    gt = [item(cwe="CWE-862")]
    assert match([row(cwe="CWE-639")], gt, {}).fp
    assert match([row(cwe="CWE-639")], gt, {"CWE-639": frozenset({"CWE-639", "CWE-862"})}).tp


def test_one_gt_item_matched_once_per_config() -> None:
    result = match([row(line=10), row(line=11)], [item()], {})
    assert len(result.tp) == 1
    assert len(result.duplicates) == 1
    assert not result.fp
    assert not result.fn


def test_safe_site_hit_is_fp_and_unhit_is_tn() -> None:
    safe = item(item_id="s1", file="src/Safe.java", cwe="CWE-89", kind="safe")
    hit = match([row(file="src/Safe.java", cwe="CWE-89")], [safe], {})
    assert hit.fp and not hit.tn
    clean = match([row(file="src/Other.java")], [safe], {})
    assert clean.tn == [safe] and len(clean.fp) == 1


def test_unagreed_items_ignored() -> None:
    result = match([], [item(agreed=False)], {})
    assert not result.fn and not result.tp


def test_load_gt_reads_exact_fields_and_normalises_paths(tmp_path: Path) -> None:
    path = write_gt(
        tmp_path / "gt.csv",
        ["g1,.\\src\\A.java,10,12,CWE-89,vuln,builtin,,A,B,true"],
    )
    items = load_gt(path)
    assert items[0].file == "src/A.java"
    assert (items[0].line_start, items[0].line_end) == (10, 12)
    assert items[0].agreed is True


def test_load_equivalence_is_symmetric(tmp_path: Path) -> None:
    path = tmp_path / "eq.csv"
    path.write_text("cwe,equivalent\nCWE-639,CWE-862\n", encoding="utf-8")
    table = load_equivalence(path)
    assert "CWE-862" in table["CWE-639"]
    assert "CWE-639" in table["CWE-862"]


def test_shipped_equivalence_table_loads() -> None:
    root = Path(__file__).resolve().parents[2]
    table = load_equivalence(root / "experiment/ground-truth/cwe-equivalence.csv")
    assert table and all(cwe.startswith("CWE-") for cwe in table)


def test_missing_column_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("id,file\n", encoding="utf-8")
    try:
        load_gt(path)
    except ValueError as exc:
        assert "missing columns" in str(exc)
    else:  # pragma: no cover - the assert above is the test
        raise AssertionError("expected ValueError")


def test_csv_module_round_trip(tmp_path: Path) -> None:
    path = write_gt(tmp_path / "gt.csv", ["g1,src/A.java,1,1,CWE-79,vuln,builtin,,A,B,no"])
    with path.open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 1


def test_empty_run_has_false_negatives_and_true_negatives() -> None:
    result = match([], [item(), item(item_id="s", kind="safe", start=50)], {})
    assert [i.id for i in result.fn] == ["g1"]
    assert [i.id for i in result.tn] == ["s"]


def test_stages_are_independent_matching_groups() -> None:
    result = match([row(), replace(row(), stage="after_g5")], [item()], {})
    assert len(result.tp) == 2 and not result.duplicates


@pytest.mark.parametrize("bad", ["maybe", "true"])
def test_invalid_or_unattributed_agreement_is_rejected(tmp_path: Path, bad: str) -> None:
    path = write_gt(tmp_path / "gt.csv", [f"g,src/A.java,1,1,CWE-89,vuln,builtin,,,B,{bad}"])
    with pytest.raises(ValueError):
        load_gt(path)
