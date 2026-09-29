# Scanning in GitHub Actions

The Ubuntu composite Action installs the Python package from its own checked-out
revision and uses locked Python dependencies, Semgrep 1.178.0, Gitleaks 8.24.2,
SpotBugs 4.10.4 with FindSecBugs 1.14.0, Dependency-Check 13.0.0,
and the packaged 0.2.0 Java rule set. It never uses Semgrep `--config auto`. The bundled initial rules cover SQL query
concatenation, `Runtime.exec` calls and weak message digests; this is a bounded
rule set, not a claim of coverage for every Java weakness. Full scans add
FindSecBugs and dependency analysis.

Copy [the PR workflow](examples/security-pr.yml) into `.github/workflows/`.
For trusted branches, copy [the scheduled workflow](examples/security-scheduled.yml).
`ppk205/DevSecOps-Agent@v0.2.0` becomes available after a maintainer publishes that
release; a commit SHA can be used before or after publication.

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

The Action supports Ubuntu x64 initially. The Python CLI/TUI supports Windows,
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
uv sync --frozen --extra dev
uv run --frozen ruff check src tests
uv run --frozen ruff format --check src tests
uv run --frozen mypy src/vulnscan
uv run --frozen pytest --junitxml=junit.xml --cov=vulnscan --cov-report=xml --cov-report=term-missing
uv run --frozen python ci/package_smoke.py
```

Linux real fast checks: install the `scanners` extra and Gitleaks 8.24.2 on PATH,
then `uv run python ci/fixture_scan.py`. For full checks, build
`uv run python ci/build_image.py`, then
run `uv run python ci/fixture_scan.py --full`. These fixtures are tracked and
copied into temporary clean Git repositories; expected policy outcomes are asserted.

The required-check workflow runs every test area on Linux Python 3.11–3.13 and
Windows/macOS Python 3.11, plus quality, package installation and real fast scans.
Configure repository branch protection to require these job checks; workflow files
alone cannot set repository protection. Module coverage and JUnit remain available
when tests fail; no new global coverage minimum is imposed. Full scans run on a
schedule, manually, and as a dependency of publishing a release.

Release distribution is GitHub only. Update `pyproject.toml` and `CHANGELOG.md`
through a PR, merge to main, then dispatch **GitHub release** from main with the
exact `X.Y.Z`. The workflow freezes main, checks version agreement, runs all checks
and full integration against that commit, builds one wheel/sdist set, and publishes
`vX.Y.Z` with SHA-256 checksums. Tags never move and uploaded assets never overwrite.
A matching rerun may finish a draft release; any different commit or asset aborts.
Reruns reuse the dispatch commit even if main advances. No PyPI/GHCR or moving major tags are published.
