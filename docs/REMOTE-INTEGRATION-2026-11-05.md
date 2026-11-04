# Remote integration — 2026-11-05

Branch: `feat/integrate-latest-remote-20261104`. The date in the branch name
records when preparation started. Verification finished on 2026-11-05.

## Inputs and history

The two newest origin branch tips were selected by tip commit date, excluding
symbolic HEAD. A final fetch confirmed that the selected tips had not advanced.

| Remote branch | Selected commit | Tip date |
| --- | --- | --- |
| `my_tool_call` | `d082435ba9ec5958ae30e4da113fdb48a88447e6` | 2026-11-04 21:47:42 +07:00 |
| `lane-hunt-recall` | `1cab83db91570fc790aced053e6f2bb3c5615064` | 2026-11-04 21:45:45 +07:00 |

The new branch starts from local `03c5533`, retaining the native-universal
merge, workflow/notification work and validator/CVSS/OWASP changes. Existing
pending Go/Ruby/C# coverage fixes were copied into the isolated worktree and
committed as `dd8e459`. Merge `23f5363` records the recall lane; `1fe2050`
records the newest scan-service tip. The newest `my_tool_call` already contains
the recall and native-universal lanes, so the second merge introduces history
without duplicating their content. No textual merge conflict occurred.

The original checkout remains on `feat/native-workflow-notifications`, with its
nine pending tracked files preserved byte-for-byte. Local settings, credentials,
unrelated notes and runtime artifacts were not copied into the commit set.

## Integration corrections

The merged Go scanner fixtures contain deliberately conflicting sample programs
and undefined target dependencies. `go vet ./...` and `go test ./...` first
tried to compile them and failed. Build-exclusion tags now keep those sample
files out of the application's Go compilation. The native analyzer still reads
them; paired vulnerable/safe controls and actual single-language scans pass.

Launcher fallback tests previously depended on the host PATH and active virtual
environment. They now isolate those inputs where PATH fallback is expected.
Failure diagnostics no longer print the process environment. Verification
processes exclude credential-like environment names. Initial inherited-
environment diagnostics are local-only, not shared verification evidence.

The native adapter and shared language inventory include Go/Ruby/C#; Semgrep
records those units as unsupported under its bundled rules. The merged hunt
pipeline adds bounded broad/concern passes, sweep excerpts and updated caps.
Go/Ruby/C# still have no dedicated model-hunt passes. Historical figures in
`HUNT-RECALL.md` were not rerun and are not current detection-accuracy evidence.

## Verification environment

Checks run from a separate worktree with an isolated Python interpreter that
loads this worktree's source and the already installed dependency directory.
Existing Node dependencies are reused through a local junction. No packages,
Go modules or models were downloaded. Go module network fetching was disabled.
Native tests use the worktree's newly built executable and Python environment.

Fresh shareable records are under
[`evidence/remote-integration-2026-11-05`](../evidence/remote-integration-2026-11-05/).
The earlier local diagnostic folder is explicitly excluded from version control.

| Check | Actual result | Record |
| --- | --- | --- |
| Focused recall, language coverage, validation, CVSS, reporting, notifications and native AI | 296 passed; one external-target fixture deselected | `focused.log` |
| Whole Go vet and tests | Passed | `go-vet.log`, `go-test.log` |
| Native build script | Passed for Windows amd64, Linux amd64/arm64 and macOS amd64/arm64; default Windows build also passed | `native-build*.json`, `native-assets.json` |
| Dashboard tests | 79 passed across 20 files | `web-tests.log` |
| Dashboard type check and production build | Passed | `web-lint.log`, `web-build.log` |
| Required whole Ruff lint | Passed | `ruff.log` |
| Required whole Ruff formatting | Failed: 12 existing files require formatting | `format.log` |
| Whole mypy and linux/darwin/win32 checks | Two existing errors in two files for each run | `mypy*.log` |
| Required whole pytest | 901 passed, 14 failed, 191 setup errors, 1 skipped | `pytest.log` |
| Original pending files | All nine original working-file byte hashes match | `original-checkout-preserved.json` |
| Merge inputs | Selected source SHAs and original checkout snapshot | `integration-inputs.json` |

The full-suite failure names introduce no new failures relative to the earlier
validator/CVSS run; see `baseline-comparison.json`. The fix-verification roundtrip
passed in this environment with the existing scanner tool directory on PATH;
its application implementation was not changed. Remaining failures concern
legacy native report parity/dashboard rendering, adapter/service fixtures and
dependent UI workflows. The external Semgrep fixture setup errors remain.
Mypy errors concern optional torch typing and the OSV adapter return type. These
are not passing repository-wide checks.

The focused deselection is the existing test requiring a local `D:/livesqli`
target. The whole pytest run did not deselect it. No test result was manufactured
to hide unavailable target/tool coverage.

Native runtime verification was on Windows only. Cross-builds and platform
type checks are not Linux/macOS runtime verification. No live provider call,
notification send, model download, full target scan or held-out accuracy
evaluation was used. Existing validator/CVSS status ownership, source isolation,
credential boundaries and optional-AI defaults were retained.

SRS trace: FR-01/10 for source/language intake, FR-70/71 for the shared workflow,
FR-50/53 for validation/scoring preservation, and QR-21/23 for UI/check boundaries.
