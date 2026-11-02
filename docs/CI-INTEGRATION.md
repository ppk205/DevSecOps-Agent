# Scanning in GitHub Actions

The main analysis path is the human-gated `devsec chat` harness. CI tests it
with fake providers and Laya backends. The composite Action and scanner fixture
jobs run the separate baseline pipeline; they do not run a live model session.

The Ubuntu composite Action installs the Python package from its own checked-out
revision and uses locked Python dependencies, Semgrep 1.178.0, Gitleaks 8.24.2,
SpotBugs 4.10.4 with FindSecBugs 1.14.0, Dependency-Check 13.0.0,
and the packaged 0.2.0 Java rule set. The rule-pack version is independent of the
application version. It never uses Semgrep `--config auto`. Bundled rules cover
SQL concatenation, command execution, XSS, path traversal, XML parsing,
deserialization, cryptography, random APIs, TLS bypasses and permissive CORS.
This is a bounded rule set. Full scans add
FindSecBugs and dependency analysis.

Copy [the PR workflow](examples/security-pr.yml) into `.github/workflows/`.
For trusted branches, copy [the scheduled workflow](examples/security-scheduled.yml).
Replace `RELEASE_COMMIT_SHA` in each example with the full published commit SHA
you reviewed. The current source package is 0.3.0; these edits do not publish a
release or establish that a matching remote tag exists.

| Input | Default | Meaning |
| --- | --- | --- |
| `checkout-path` | `.` | Clean Git working tree to scan |
| `profile` | `fast` | `fast`: Semgrep/Gitleaks; `full`: also isolated Maven, SpotBugs/FindSecBugs, Dependency-Check |
| `config` | empty | Versioned JSON configuration file |
| `fail-on` | `high` | Minimum severity: critical, high, medium, low, info, none |
| `output-directory` | runner temporary directory | Sanitized evidence destination, preferably outside the checkout |

Outputs: `run-id`, `scan-status`, `gate-result`, `summary-path`, `sarif-path`.
Reports and a job summary are uploaded before the gate returns. The gate returns
0 for a completed passing scan, 1 for findings at/above the threshold, 2 for
configuration/execution/required scanner/coverage failures, and 130 for cancellation.
Unknown severities are listed explicitly. Unprocessed and unresolved findings count;
only a recorded independent rejection excludes a finding. Missing scanners never pass.
`none` disables only the severity gate, not execution or coverage checks.

Full scans build the target in a container. The build receives an isolated source
snapshot, temporary home, bounded CPU/memory/process count, no host environment
credentials, and scoped mounts. Maven and Dependency-Check require network access.
Dependency-Check initializes from the official NVD 2.0 bulk feeds without requiring an API key. KEV enrichment uses [CISA's official public mirror](https://github.com/cisagov/kev-data), preserving KEV coverage when the cisa.gov feed rejects automated requests. A separate trusted updater persists advisory data under the artifact root; target builds receive only a read-only cache mount and work on a private copy. A database checksum is retained with each scanner result. Advisory database update failures are scan failures, not clean results. The current
Java rules deliberately declare JSP analysis unsupported; reports retain that limitation.
Full runs can take substantially longer while advisory databases initialize.

The Action supports Ubuntu x64 initially. The Python CLI and Go TUI support Windows,
macOS and Linux; individual scanner binaries still need platform support.

SARIF upload is optional and independent of the gate. Repositories with Code
Scanning enabled may add a SHA-pinned `github/codeql-action/upload-sarif` step,
`if: always()`, passing `steps.security.outputs.sarif-path`, and grant
`security-events: write` only to that job. Availability differs by repository;
see [GitHub's SARIF documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).
Never run contributor target builds through privileged `pull_request_target`.

# Development and releases

Install uv 0.12.17, then run:

```sh
uv sync --locked --extra dev --extra scanners
uv run --no-sync python ci/check_lock_exports.py
uv run --no-sync python -m ruff check src tests ci
uv run --no-sync python -m ruff format --check src tests ci
uv run --no-sync python -m mypy src/vulnscan
uv run --no-sync python -m pytest tests --junitxml=junit.xml --cov=vulnscan --cov-report=xml --cov-report=term-missing
uv run --no-sync python ci/package_smoke.py
```

Linux real fast checks: install the `scanners` extra and Gitleaks 8.24.2 on PATH,
then `uv run --no-sync python ci/fixture_scan.py`. For full checks, build
`uv run --no-sync python ci/build_image.py`, then
run `uv run --no-sync python ci/fixture_scan.py --full`. These fixtures are tracked and
copied into temporary clean Git repositories; expected policy outcomes are asserted.

The workflows retain their reusable `ref` input for exact-commit release checks.
PR and main checks use the event commit; **Required checks** also supports manual
dispatch. PR updates cancel older checks for that PR. Reusable release checks
have a separate concurrency group from the release workflow itself.

| Job | Required behavior |
| --- | --- |
| `quality` | Compare all shipped exports to `uv.lock`; Ruff on `src tests ci`; strict mypy for Linux/macOS/Windows |
| `harness` | Fake-provider and fake-Laya regression tests on Linux/Windows/macOS Python 3.11; gates, secrets, confinement and fix verification |
| `web-ui` | Node 24 with the committed lock file: `npm ci`, `npm run lint` (tsc), `npm test` (vitest) and `npm run build` for the PIT WALL SPA |
| `native` | Go 1.27.1 vet/tests with read-only modules, including the chat client; build native binary; run all platform and CLI tests on each OS |
| `tests` | Every Python test area on Linux Python 3.11–3.13 and Windows/macOS Python 3.11 |
| `package` | Build wheel/sdist once, install into a fresh environment, check installed chat/assets/CVSS, cross-compile native release assets |
| `action-smoke` | Exercise the local Action and real safe/vulnerable fast baseline fixtures |
| `required` (`CI required`) | Fail if any preceding job failed, was skipped or was cancelled |

Configure branch protection to require **CI required**; changing workflow files
does not change repository settings. Harness, native and full Python jobs retain
JUnit and module coverage on failure. Baseline jobs upload sanitized evidence,
excluding advisory database caches. No new global coverage minimum is imposed.

CI installs from the lock with `uv sync --locked`, then uses `uv run --no-sync`
to retain dev/scanner extras. Model downloads are disabled and no provider
secrets are supplied. The shared `ci/smoke_installed.py` checks the installed
wheel, Action environment and scanner image without contacting a provider.
Both CLI aliases must refuse unattended G0; the installed gatekeeper must
refuse unattended G6. This does not claim live model or live Laya verification.

Package smoke selects the exact project version from `pyproject.toml` when
choosing the wheel and source archive. Older files in a local `dist/` directory
are preserved and cannot silently substitute for the current build.

Action revisions were checked against the upstream releases and pinned to full
commit SHAs in workflows, the composite Action and examples:

| Action | Reviewed release |
| --- | --- |
| checkout | [7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) |
| setup-python | [7.1.0](https://github.com/actions/setup-python/releases/tag/v7.1.0) |
| setup-go | [7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0) |
| upload-artifact | [7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) |
| download-artifact | [8.0.2](https://github.com/actions/download-artifact/releases/tag/v8.0.2) |

Full baseline scans run on a schedule, manually, and before publishing a release.
Their image builds and target builds remain contained as described above.
The initial advisory cache may need network access and time to initialize.

Release distribution is GitHub only. Update `pyproject.toml` and `CHANGELOG.md`
through a PR, merge to main, then dispatch **GitHub release** from main with the
exact `X.Y.Z`. The workflow freezes main, checks version agreement, runs all checks
and full integration against that commit, builds one wheel/sdist set, and publishes
`vX.Y.Z` with SHA-256 checksums. Tags never move and uploaded assets never overwrite.
A matching rerun may finish a draft release; any different commit or asset aborts.
Reruns reuse the dispatch commit even if main advances. No PyPI/GHCR or moving major tags are published.

The workflow layout follows GitHub's [reusable workflow contracts](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
and [secure workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use):
actions use immutable SHAs, checkouts do not retain credentials, and only the
publish job has `contents: write`. SRS trace: FR-72–74 and QR-22–23.

## Local validation of this CI refresh (2026-11-01)

| Check | Observed result |
| --- | --- |
| Ruff check and format check on `src tests ci` | Passed; 218 files already formatted |
| Strict mypy for Linux, macOS and Windows | Passed for 122 application source files |
| Frozen requirements-export comparison | All three exports match `uv.lock` |
| CI contract tests | 17 passed |
| Full Python suite with the built native binary | 547 passed, 1 skipped, 2 warnings |
| Go vet and tests on a clean source copy | Passed |
| Current wheel/sdist build and fresh hash-locked wheel installation | Passed for 0.3.0; assets, CVSS, both aliases and gate refusal checked |

The Python suite used host access for Semgrep's Windows certificate store and
a fresh temporary directory outside the checkout. Its skip is the existing
unavailable-Semgrep test because the binary is installed. The warnings concern
Starlette's httpx deprecation and terminal echo control in an empty-key test.

The first fresh-install attempt was blocked by sandbox network restrictions.
A host retry then exposed the old archive-selection bug by installing a local
0.2.0 wheel instead of the newly built 0.3.0 wheel. Exact-version selection was
added and the fresh installation passed. The initial checkout-wide Go vet also
found an existing, ignored `artifacts/tui-verification/native_probe_test.go`
that cannot compile alone. A clean copy of `cmd`, `internal`, `go.mod` and
`go.sum` passed both Go checks without deleting those local artifacts.

GitHub-hosted jobs, the composite Action's Ubuntu installation, and full Docker
integration were not executed locally. Their YAML and policy contracts were
checked; this does not claim a successful remote workflow run. No live provider
call, model download, release publication or branch-protection change was made.
