"""A repo may nest its project under a parent directory; test detection must
not depend on the checkout root. Regression for ComicReaderSite: files under
``Comic/src/test/`` leaked into the scan inventory while Semgrep reported no
coverage for them, so reconcile failed the gate with "missing coverage" even
though the scan produced zero findings.
"""

from __future__ import annotations

import pytest

from vulnscan.core.scan_service import _is_scanned_source


@pytest.mark.parametrize(
    "path,scanned",
    [
        # Nested project root (regression): test files anywhere are excluded.
        ("Comic/src/test/java/reader/site/Comic/TestDb.java", False),
        ("Comic/src/test/java/reader/site/Comic/dao/BookmarkDAOTest.java", False),
        ("Comic/src/test/java/reader/site/Comic/util/RateLimiterTest.java", False),
        ("Comic/src/it/java/x/ITCase.java", False),
        ("Comic/src/e2e/java/x/E2ECase.java", False),
        # Standard Maven layout still excluded.
        ("src/test/java/x/AuthTest.java", False),
        # Production sources stay in the inventory, including a servlet whose
        # class name merely starts with "Test" (TestEmailServlet is real).
        ("Comic/src/main/java/reader/site/Comic/web/TestEmailServlet.java", True),
        ("Comic/src/main/java/reader/site/Comic/dao/BookmarkDAO.java", True),
        ("src/main/java/web/AuthServlet.java", True),
        ("web/src/main/java/App.java", True),
        # A test *helper* in production sources is not a test file.
        ("comicsite/src/main/java/TestHelper.java", True),
        # Non-source files are never scanned.
        ("Comic/src/main/resources/application.properties", False),
    ],
)
def test_is_scanned_source_excludes_tests_anywhere(path: str, scanned: bool) -> None:
    assert _is_scanned_source(path) is scanned
