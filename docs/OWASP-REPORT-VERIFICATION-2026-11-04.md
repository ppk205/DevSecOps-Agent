# OWASP report verification — 2026-11-04

Scope: SRS FR-61 report content and FR-68 shared services. The working branch is
`feat/native-workflow-notifications`; verification ran after base `1a59e3b`.
This is a reporting change, not a detection or vulnerability-accuracy evaluation.

## Implemented output

HTML, Markdown, text and Word exports contain an OWASP Top 10:2025/CWE section.
JSON and SARIF contain matching structured data. The final narrative adds the
same deterministic section after model output or its fallback. Mappings come
from a bundled snapshot of the ten official category-specific CWE lists.
Primary and secondary normalized CWE labels participate. A category counts each
finding once; per-CWE rows retain their own finding references and actual status
counts. Unclassified and unlisted labels stay unmapped. An empty category is not
a passed test or proof of coverage.

Model-authored OWASP Markdown sections are replaced by the computed section.
Fallback finding titles are preserved, including titles containing “OWASP Top
10”. An incomplete model code fence is closed before the new section. The
deterministic narrative also now prints canonical CWE identifiers without the
previous duplicate `CWE-` prefix. No finding status, validation decision, CVSS
score, scanner configuration or scan gate is changed by this reporting logic.

## Executed checks

All new records are under
[`evidence/owasp-report-2026-11-04`](../evidence/owasp-report-2026-11-04/).

| Check | Actual result | Retained record |
| --- | --- | --- |
| Reporting tests | 54 passed, including the real native EXE/JSONL export path | Included in `focused.log` |
| Focused reporting, notification and native AI regression set | 92 passed | `focused.log`, `focused.json` |
| Required whole Ruff lint | Passed | `ruff.log` |
| Required whole Ruff formatting | Failed: 12 existing files require formatting | `format.log` |
| Required whole mypy | Failed: four existing errors in three files | `mypy.log` |
| Reporting mypy, linux/darwin/win32 | Four files passed on each platform setting | `mypy-reporting-*.log` |
| Required whole pytest | 783 passed, 15 failed, 191 setup errors, 1 skipped | `pytest.log`, `pytest.json` |
| Native build script | Passed; built Windows binary matches the EXE used in tests | `native-build.log`, `native-build.json` |
| Mapping source comparison | All ten bundled lists, names, URLs and source hashes match the retained extraction | `reference-and-preview.json`, `official-cwe-mapping.json` |

The full-suite failed test names match the prior notification verification:
`baseline-comparison.json` records no new or removed failures. Remaining failures
include existing fix verification, native report parity/dashboard rendering,
adapter fixtures and dependent UI workflows. The 191 scanner-fixture setup errors
remain. Mypy errors concern Windows subprocess constants, optional torch typing
and the OSV adapter return type. These are not passing repository-wide checks.

No Go source changed. The native build used `ci/build_native.py` with locked
modules, local SDK/cache settings and module network fetching disabled. Go vet
and package tests were not repeated for this Python reporting change. The native
integration test ran on Windows; Linux/macOS type checks are not runtime tests
on those systems.

## Source and regression evidence

The initial regression test failed because `reporting.owasp` did not exist.
Subsequent controls failed on missing export metadata/sections and final narrative
integration. Additional cases established that fallback finding titles must not
be stripped and an incomplete model code fence must not hide the new section.
Those cases pass in the final focused set.

OWASP's public category pages were fetched read-only during implementation. Only
their mapped CWE IDs, category titles, source URLs and source hashes were
retained. Application report generation and regression tests use the bundled
mapping and make no lookup requests. Category membership follows each page's
“List of Mapped CWEs”, not the overview's aggregate counts. The extracted snapshot
contains 249 category/CWE memberships. This is reference-data size, not a scan
finding or security-coverage measurement.

Tests cover primary/secondary labels, one count per category, repeated scanner
observations, status partitions, unmapped CWEs, empty reports, all export formats,
HTML/Markdown escaping, protected structured metadata and model/error/empty
narrative paths. Existing notification and native AI regression tests also pass.
Model HTTP responses and scanner findings are synthetic in integration tests.
No live model call, notification send, model download, full target scan or
held-out detection evaluation was performed for this change.

## Synthetic preview

[Open the HTML preview](../evidence/owasp-report-2026-11-04/synthetic-preview/report-preview.html)
or [read the Markdown preview](../evidence/owasp-report-2026-11-04/synthetic-preview/report-preview.md).
The same folder includes JSON, SARIF and text examples. A Word preview was also
generated locally and remains outside version control. These are synthetic
demonstrations, not a scan of the owner's source. The preview labels this in its
metadata. File hashes are recorded in `reference-and-preview.json`.

Previously exported reports and evidence were preserved. Existing runs can be
exported again to obtain the new section without rerunning scanners. No essay,
dependency, credential file, commit or repository history was changed for this
reporting task. See [OWASP-REPORTING.md](OWASP-REPORTING.md) for usage and sources.
