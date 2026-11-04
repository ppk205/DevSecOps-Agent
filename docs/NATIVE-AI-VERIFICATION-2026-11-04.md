# Native AI integration verification

Date: 2026-11-04. Branch: `my_tool_call`, uncommitted working tree.

The native EXE now invokes the existing Python AI pipeline when Hunt, AI review
or AI report is selected. Activity displays returned explanations and tool
outcomes; finding details load the matching retained assessment. Native defaults
remain deterministic. The implementation adds no framework, provider SDK or
dependency.

This record covers offline execution and Windows UI behavior. Scanner
observations and HTTP replies in the AI fixture are synthetic. They do not
establish vulnerability accuracy, model quality or live provider availability.
No paid provider call, user-source upload or model download was used for this
verification. Laya verification was explicitly skipped in the AI fixture.

## Execution evidence

The manual terminal run selected Hunt and the `offline-native` fixture profile,
reviewed the effective model, and started through the Go-to-Python bridge.
Activity displayed returned explanation text and an `inspect_code` tool outcome.
Opening the finding showed its retained rationale and model proposal separately
from the finding status. The synthetic run completed and retained its report.
The [saved UI record](../evidence/native-ai-integration-r3-2026-11-04/offline-ui-run.json)
contains the actual call, assessment and usage records from that run. Any finding
status in this record comes from synthetic observations and is test output.

The automated EXE tests cover Hunt, review/report, selected models, tool-call IDs,
retry, missing providers, HTTP failure and defaults with a keyed profile present.
Provider tests cover separate returned explanation fields, redaction and unknown
usage. UI/storage tests cover retained rationale, run/finding isolation, usage
presentation, scanner-subset review and small-terminal key entry.

## Check results

| Check | Actual outcome | Retained output |
| --- | --- | --- |
| Focused AI/provider/credential/EXE checks | 131 passed | [Focused AI log](../evidence/native-ai-integration-r3-2026-11-04/focused-ai.txt) |
| Launch and source-input regressions | 84 passed; 3 unrelated parity cases deselected | [Input regression log](../evidence/native-ai-integration-r3-2026-11-04/launch-source-regressions.txt) |
| Ruff lint on `src tests ci` | Passed | [Ruff lint](../evidence/native-ai-integration-r3-2026-11-04/ruff-check.txt) |
| Ruff format on `src tests ci` | Failed: 14 existing files need formatting | [Ruff format](../evidence/native-ai-integration-r3-2026-11-04/ruff-format.txt) |
| Whole application mypy | Failed: 4 errors in 3 existing files | [Mypy output](../evidence/native-ai-integration-r3-2026-11-04/mypy.txt) |
| Focused provider/loop typing with imported modules skipped | Passed for the 4 explicitly checked files; partial typing coverage | [Focused typing](../evidence/native-ai-integration-r3-2026-11-04/mypy-provider-focus.txt) |
| Go application vet and tests (`./cmd/... ./internal/...`) | Passed | [Vet](../evidence/native-ai-integration-r3-2026-11-04/go-vet-application.txt), [tests](../evidence/native-ai-integration-r3-2026-11-04/go-test-application.txt) |
| Go whole-tree vet and tests (`./...`) | Failed on the existing generated `artifacts/tui-verification` test package | [Vet](../evidence/native-ai-integration-r3-2026-11-04/go-vet-all.txt), [tests](../evidence/native-ai-integration-r3-2026-11-04/go-test-all.txt) |
| Native platform build script | Passed for the script's Windows, Linux and macOS targets; runtime verified on Windows only | [Build output](../evidence/native-ai-integration-r3-2026-11-04/native-platform-builds.txt), [exit results](../evidence/native-ai-integration-r3-2026-11-04/go-results.json) |
| Full pytest | 728 passed, 15 failed, 191 setup errors, 1 skipped | [Full test output](../evidence/native-ai-integration-r3-2026-11-04/pytest-full.txt) |

The remaining full-suite failed test names match the pre-AI run. They include
external-tool fix verification, scanner coverage fixtures, legacy native/Python
report parity, native dashboard rendering, shared-service fixture failures and
dependent terminal/web workflows. The setup errors come from the external
Semgrep fixture runs. The complete traces are retained above; this is not a
passing repository-wide verification.

The remaining mypy errors concern Windows subprocess constants, optional Torch
typing and an existing OSV adapter return type. The new AI comparison/report
typing errors found during the first check were corrected before the final run.
A Windows capture issue in the first full test run was corrected by explicitly
decoding native test output as UTF-8.

[Verification metadata](../evidence/native-ai-integration-r3-2026-11-04/verification-metadata-corrected.json)
records the base commit, source hashes and failure-name comparison. Earlier dated
evidence folders remain intact, including the interrupted initial test log. The
corrected comparison honors the older PowerShell log's UTF-16 byte-order mark;
the initial comparison record is retained alongside the correction.

## Limits and skipped work

- Live provider authentication, connectivity and response quality were not
  tested. The fixture replaces HTTP transport and uses test-owned credentials.
- Returned text is shown as calls finish. Token-by-token streaming and complete
  prompt/wire transcripts are not implemented.
- Missing provider usage stays unknown. Price estimation is not configured;
  monetary cost is unavailable and the monetary-budget requirement remains
  partially implemented.
- A synchronous request already in flight can wait until its provider timeout
  on cancellation. Later calls are stopped, and already persisted progress is
  retained.
- Linux/macOS runtime checks, model inference/downloads, full target scans and
  independent detection/model-accuracy evaluation were skipped for this change.

## Requirements trace

FR-48 covers investigation and rationale; FR-49 covers reported usage and its
remaining price-estimation gap; FR-50 preserves validator ownership; FR-70/71 and
DR-09 cover execution, retry and retained UI data; IR-11/12/13 cover profile
selection and trace limits; QR-21 covers responsive keyboard use and bounded
layouts. See [the native usage guide](NATIVE-MIGRATION.md#ai-support) and
[the test plan](TEST-PLAN.md#native-ai-acceptance-2026-11-04).
