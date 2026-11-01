"""Citation checking and CVSS v4.0 scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnscan.harness.evidence import check_citations, score_cvss4
from vulnscan.harness.workspace import Hop, Workspace


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    (tmp_path / "A.java").write_text(
        'a\nString n = req.getParameter("n");\nb\nstmt.executeQuery(sql + n);\n'
    )
    return Workspace.open(tmp_path)


def test_good_path_has_no_errors(ws: Workspace) -> None:
    assert (
        check_citations(
            ws,
            [
                Hop("A.java", 2, 'req.getParameter("n")'),
                Hop("A.java", 4, "executeQuery(sql + n)"),
            ],
        )
        == []
    )


@pytest.mark.parametrize(
    "hop,msg",
    [
        (Hop("B.java", 1, "x"), "file not in target"),
        (Hop("A.java", 99, "x"), "line out of range"),
        (Hop("A.java", 4, "Runtime.exec"), "code not found near line"),
        (Hop("../etc", 1, "x"), "file not in target"),
    ],
)
def test_bad_hops_are_reported(ws: Workspace, hop: Hop, msg: str) -> None:
    assert msg in check_citations(ws, [hop])[0]


def test_empty_path_is_an_error(ws: Workspace) -> None:
    assert check_citations(ws, []) == ["no source-to-sink path cited"]


def test_cvss4_score_and_invalid_vector() -> None:
    assert score_cvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    with pytest.raises(ValueError):
        score_cvss4("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
