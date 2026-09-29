# v0.2.0 verification record

SRS trace: sections 3–6, FR-70–FR-74, DR-09–DR-10, IR-14–IR-16 and QR-21–QR-23.

| Check | Local evidence |
| --- | --- |
| Windows Python 3.11 | 237 tests passed; JUnit and module coverage generated |
| Linux Python 3.11 | 237 tests passed |
| Linux Python 3.12 | 237 tests passed |
| Linux Python 3.13 | 237 tests passed |
| Quality | Ruff lint/format and strict mypy across all application modules passed |
| Workflow definitions | Actionlint 1.7.7 passed |
| Packaging | Wheel and source archive built; clean wheel install, version entrypoint, Textual import, web templates and versioned rules verified |
| Source archive boundary | Explicit allowlist excludes local target checkouts, essay files and virtual environments |
| Real fast profile | Safe Java fixture passed with exit 0; vulnerable fixture failed the policy with exit 1 |
| Real cancellation | Cancelling a container scan returned 130 and preserved completed scanner evidence and reports |
| Real full profile | Passed with all required scanners complete: safe fixture exit 0; vulnerable fixture exit 1 |

Runtime verification logs live under `artifacts/verification/` and are excluded
from source control. `full-state.json` records the full-profile worker's completion
and exit code; `full-profile.log` records scanner stages. An interrupted run or an
earlier failure is not counted as passing evidence. Scanner reports are retained
under `artifacts/integration/<run-id>/`.

The full profile uses Maven 3.9.9 / Java 17, SpotBugs 4.10.4, FindSecBugs 1.14.0
and Dependency-Check 13.0.0. The latter avoids the long-reference-URL schema failure
encountered with the original 12.1.0 pin. FindSecBugs 1.14.0 fixes the Java 11 invokedynamic warning found by the vulnerable fixture. KEV data comes from CISA's official public mirror after the primary endpoint returned HTTP 403. Advisory initialization runs without
target mounts and persists its cache; target builds get only a read-only mount
and a private database copy. Scanner results record the database SHA-256.

GitHub-hosted jobs, macOS execution, branch-protection configuration, and publishing
an actual GitHub release require the repository workflow environment. No tag,
release, PyPI package or GHCR image was published during local implementation.
