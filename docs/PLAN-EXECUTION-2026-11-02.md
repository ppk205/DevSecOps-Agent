# Remaining-plan execution record

Branch: `feat/go-chat-tui`, based on the existing `feat/human-gated-harness`
work. The owner approved a combined implementation before merge checkpoints,
the planned rule updates, parallel agents, and commit/push/PR delivery.
Essay work was explicitly excluded.

Publication: GitHub CLI has no authenticated account in this environment.
The owner chose a pushed branch and PR-creation link instead of CLI sign-in;
PR creation and GitHub-hosted checks remain with the owner.

## Plan coverage

| Plan | Software delivered | Remaining operator work |
| --- | --- | --- |
| Human-gated harness | Existing implementation retained; consent, interruption, durable review state and resume integrated with clients | Live-provider smoke with an operator |
| Stabilize/merge | Existing merge, redaction and B7 consent retained; helper/filter-match cleanup already present; CI and exports aligned with new client | GitHub required checks on the published PR |
| Go chat TUI | SessionHost/RPC, added models, reliable bridge, start/key forms, chat, dialogs/diff viewer, baseline comparison, launch wiring and Textual removal | Manual real-terminal keyboard/mouse acceptance |
| Web remote | Multi-client gates, login/CSRF, event replay, listener/headless CLI, SPA route, transcript/model/gate/pending controls | Live browser acceptance; SPA packaging is still outside this implementation |
| Local triggers | Interactive-local G0 exception, pending queues, opt-in hooks, watcher, client banners/auto-start, patch export | Optional real-project hook rollout by the operator |
| Experiment | Ground truth/matching, source normalisers, metrics/tables/charts, B6, fix evaluation, related-work table and runbook | Independent labels; fixture/JVA trials; provider prices and consent; CodeQL/Copilot/Semgrep exports; optional R1 replication |

The original checkboxes also include historical test-first steps, manual
measurements, publication and owner merge steps. They have not all been
checked merely because corresponding source files exist.

## Approved corrections

- G0 auto-approval is limited to local, interactive, auto-mode sessions;
  G5/G6 remain human-only. G7 accepts edits. Dialog Enter requires an explicit
  selection. Web dangerous approvals require host-checked confirmation words.
- Added aliases own keys; locality comes from the base URL. `model_protocol`
  distinguishes the model API protocol from the `devsec-chat/1` envelope.
- S1 disables harness Laya through `mode: "off"`, not the baseline-only
  `enabled` field. Skipped routing is recorded and G3/G4 still apply.
- Hook discovery includes root commits and NUL-delimited filenames. A custom
  `core.hooksPath` is explicitly refused.

## Verification actually run

All Python commands use `.venv\Scripts\python.exe`.

| Check | Observed result |
| --- | --- |
| `-m ruff check src tests ci` | Passed |
| `-m ruff format --check src tests ci` | Passed; 270 files already formatted |
| `-m mypy src/vulnscan` | Passed; 141 source files |
| `-m pytest -q -p no:cacheprovider --basetemp C:\Users\Admin\AppData\Local\Temp\opencode\p3` | 977 passed, 1 skipped, 2 warnings |
| `uv lock --check --offline` | Passed |
| `ci/check_lock_exports.py` | All three exports match `uv.lock` |
| `ci/build_native.py --go .tools/go/bin/go.exe` | Passed |
| `go vet ./...`, `go test ./...` in a clean Go source copy | Passed |
| Real Go→Python recorded-transport test in the source checkout | Passed, including gates and restart |
| `npm ci`, `npm run lint`, `npm test`, `npm run build` in `web-ui/` | Passed; 101 tests in 21 files |
| `ci/package_smoke.py` | Wheel/sdist built and a fresh hash-locked wheel installation passed; unattended G0/G6 refused |

The checkout's untracked, ignored
`artifacts/tui-verification/native_probe_test.go` cannot compile standalone
(`fakeAPI`, `Model`, `New` are undefined), so checkout-wide Go discovery fails.
Full Go package checks used a clean copy of `cmd`, `internal`, `go.mod` and
`go.sum`; the real Go→Python integration test was additionally run in the
original checkout. The scratch probe was preserved.

Pytest's default temporary directory was inaccessible on this machine. The
successful full runs used fresh directories under the approved OpenCode temp
root, outside the checkout. The remaining skip is the existing missing-binary
case when its scanner is present. The Python warnings concern Starlette's
httpx transition and an existing empty-key getpass test. The locked npm
installation reported dependency advisories; dependency upgrades were not
part of this plan. Frontend tests also emitted existing React Router/Node
warnings, and Vite reported its existing mixed-import chunk warning.

Local full-test and package logs are under
`.tools/ci-logs/remaining-plans-2026-11-02/`. These are verification logs, not
experiment measurements.

## Not measured or implemented

No live provider experiment, real Laya inference, full WSL scanner experiment,
CodeQL/Copilot/Semgrep-platform upload, manual browser/terminal acceptance,
or independently labelled ground truth was produced in this run. Those
steps need the operators and inputs specified by the runbook. No existing
evidence or essay files were changed.

Provider token streaming, prompt caching, `/compact`, `check_dependency`, Laya
fine-tuning, and bundled SPA assets remain unimplemented. Whole model replies
are intentional in the approved client design; browser SSE streams host events.
