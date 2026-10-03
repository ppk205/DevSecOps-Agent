# TUI review

Reviewed commit `88e21d62a4ddab688d6e0ea20ba612347c91484b` on 2026-10-02.
Reference requested by the user: the interaction experience of Codex or Claude
Code. This review uses that as a design preference for a clear task workspace;
it does not claim feature parity with either product.

**Original verdict: changes needed.** The native interface has confirmed action-targeting,
review, diagnostic and keyboard-navigation problems. The migration improved
bounded data access and worker isolation, but those checks did not establish
that users can comfortably complete the terminal workflow.

## Implementation (2026-10-03)

The review is implemented in both terminal interfaces. The default launcher
opens the Textual Workspace, preserving the newer repository URL, pinned commit,
clone-cache and hidden API-key controls from GitHub main. `DEVSECOPS_NATIVE=go`
opens the rebuilt native Workspace for local checkouts; `DEVSECOPS_NATIVE=python`
selects Python throughout the session. The `devsec` alias is retained.

| Finding | Resolution | Regression evidence |
| --- | --- | --- |
| R1 | History retry/export resolve the highlighted row; other views name the opened run. Empty/active retry targets are guarded. | Native workflow tests; Python keyboard two-run tests |
| R2 | Focused review readers expose scrolling, effective summaries and optional raw manifests. | Keyboard review/scroll/start tests at 80x24 and 75x26 |
| R3 | Terminal errors include corrective actions and retained report paths, including when reopening saved activity. | Native failure-result test; Python completion and stored-activity tests |
| R4 | Cursor movement preserves reviews; changes to scan values invalidate them. | Native pending-review regression; blocked Python review/cursor test |
| R5 | Ctrl+1 through Ctrl+5 navigate during editing; readers have explicit focus and back controls; Ctrl+K lists actions. | Keyboard workflows and action-menu tests |
| R6 | Native frame budgeting covers all views; advanced fields scroll into view; both interfaces show a minimum-size message. | Native 80x24/75x26/60x20 bounds checks and small-size checks; Python resize tests |
| R7 | Saved activity queries only run-scoped events/diagnostics; live activity is isolated from historical inspection. | Native/Python stored-activity and cross-run event tests |

Workspace contains checkout/profile, Review/Start and expandable advanced
options. Profiles, thresholds, yes/no values and export formats use typed
choices. Ctrl+Space completes local directories in a background task. Findings
show title, severity/CWE, recorded review status, scanner/rule, location,
retained snippet and evidence references; raw JSON is available separately.
No snippet or validation outcome is inferred from unavailable data.

Live Activity shows the run, elapsed time, stage events and retained finding
count. Final errors and reports remain inspectable after restart. Readers
preserve their own run identity while another scan executes.

Acceptance tests are in [native workflow tests](../internal/tui/workflow_test.go),
[stored native activity tests](../internal/service/activity_test.go),
[Python keyboard workflow tests](../tests/tui/test_workflow.py),
[Python evidence presentation tests](../tests/tui/test_presentation.py) and
[stored Python activity tests](../tests/platform/test_activity.py).
The workflow guide is [NATIVE-MIGRATION.md](NATIVE-MIGRATION.md).

SRS trace: FR-70/71 governs actions and presentation; DR-09/IR-16 governs
run-scoped retained activity; QR-01/05 governs honest evidence summaries;
QR-16 governs corrective failure messages; QR-21 governs focus, resize,
background reads and cancellation.

### Final verification

- After integrating GitHub main: **346 Python tests passed**, 75% aggregate
  Python coverage. The two warnings are the existing Starlette/HTTPX
  test-client deprecation and getpass's nonterminal fallback in an empty-value
  CLI test.
- Go unit tests and vet passed. Python lint, formatting and strict mypy passed.
- Native keyboard tests cover typed controls, long review scrolling, evidence,
  export targets, saved diagnostics, first-event/history isolation and quitting
  while cancelling at a small terminal size. Python Pilot workflows exercise
  real keys at 80x24 and 75x26.
- A Windows PTY fixture session completed review, scan, evidence inspection and
  clean quit. Native builds succeeded for Windows amd64, Linux amd64/arm64 and
  macOS amd64/arm64.
- Wheel/source build and a fresh wheel installation with hash-pinned runtime
  dependencies passed, including both `devsec` and `devsecops-agent` entry
  points. Dependency-lock validation passed. The workspace environment was
  synchronized from the frozen lock to install the `devsec` alias locally.

The implementation was rebased on the newer URL scan/API-key/alias commits.
Source commit/cache edits participate in review invalidation, key saving runs
in a worker with hidden values, and native/Python parity is checked with the
same explicit Laya configuration in both advisory modes. The default Python
launch retains the complete URL and credentials workflow; explicit native
mode retains the local-checkout TUI.

Verification used offline scanner fixtures and retained evidence. Real scanner
integration, GPU training and Linux/macOS runtime checks were not repeated for
this UI change; the existing cross-platform CI configuration remains in place.

## Original review scope and evidence

- Reviewed the native TUI, its launcher and service result handling, the Python
  fallback, and the TUI tests against SRS sections 3, 5 and 6.
- Ran a real Windows terminal session with an isolated database and the offline
  fixture adapter. Completed checkout review, a fixture scan, finding inspection
  and clean exit. The configuration preview showed only three JSON lines in the
  80-column terminal, with no working review-scroll key.
- Ran the existing Go TUI tests and all five Python TUI tests. They passed.
- Used eight temporary native diagnostic probes to check individual interaction
  defects, plus a Python Pilot probe confirming the action-targeting issue in
  the fallback. These probes assert the observed defects; their passing results
  do not mean that the behavior is acceptable.
- Measured model output at 80x24, 75x26, 60x20 and 110x42. Saved plain terminal
  snapshots and probe source/logs under ignored `artifacts/tui-review/`.
- Production application code is unchanged. Temporary probes were removed from
  the source tree after the review. No real scanner or model inference was used.

## Findings

### R1 — P1: Retry and Export can target a different run from the highlighted row

**Location:** [native actions](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L445),
[captured retry target](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L198),
[history activation](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L503),
[Python actions](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/src/vulnscan/tui/app.py#L508).

Open run A, return to Overview, move the history cursor to run B, then use
Ctrl+T or Ctrl+O. Both actions use `selected`, which still identifies A. On a
fresh launch, Retry also does nothing until a run has been opened with Enter.
The caption says to retry the selected run without explaining this distinction.

The native probe recorded run 1 for both actions while run 2 was highlighted.
The Python Pilot probe confirmed the same mismatch. This is an inherited issue
in the fallback and is also present in the new native interface.

**Correction:** Resolve actions invoked from Overview from the highlighted
history row. Actions elsewhere should explicitly identify their target run.
Disable an action when no valid target exists.

**SRS trace:** FR-70/71, QR-07. The requested retry/export must operate on the
run the interface identifies to the user.

### R2 — P1: The required configuration review cannot be scrolled

**Location:** [review contents](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L314),
[keyboard dispatch](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L576),
[review rendering](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L657).

Review writes the full configuration and checkout manifest into `m.review`,
but no input path forwards messages to that viewport. Down, PgDown and Ctrl+D
leave its scroll offset at zero. Tab only cycles the setup fields.

In the live 80-column session the preview displayed `{`, `"configuration": {`
and `"allow_dirty": false`. The status nevertheless reported that the settings
were reviewed and allowed the scan to start. A 31-line diagnostic preview at a
three-line viewport height also remained at offset zero.

**Correction:** Give the review an explicit focus/scroll path and show a compact
human-readable summary first: checkout, commit, file count, profile, scanners,
limits, dirty-content policy, threshold, advisory mode and output location.
Keep the manifest available as expandable details.

**SRS trace:** FR-71, QR-21. Effective settings review and keyboard access must
work together.

### R3 — P1: Some terminal scan errors disappear from the native TUI

**Location:** [completion handler](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L348),
[report failure results](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/service/scan.go#L417),
[Python completion handler](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/src/vulnscan/tui/app.py#L608).

`finishedMsg` renders run ID, status, gate and exit code, but ignores the
returned `errors` list. Report export failures are appended to that list after
the ordinary stage events, so their cause can be absent from the progress log.
The diagnostic result `report export failed: disk full` rendered only a failed
status and exit 2. The Python fallback writes returned errors into its log.

**Correction:** Persistently display terminal errors with their stage, cause
and corrective action. Display available report paths and partial-result state.

**SRS trace:** QR-16, FR-71, IR-15. This is a native diagnostic regression.

### R4 — P2: Moving the text cursor can discard a valid pending review

**Location:** [generation invalidation](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L576),
[response guard](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L235).

Press Ctrl+E, then Left before the checkout review returns. The field value
and signature are unchanged, but the code increments `reviewGeneration` for
every key delivered to an input. It discards the matching review response and
leaves the status at `Reviewing checkout…`. Ctrl+S then requires another review.

**Correction:** Invalidate review results only when relevant values change.
Provide an explicit pending/invalid/error state for the review action.

**SRS trace:** FR-71, QR-21.

### R5 — P2: Focus rules make navigation and evidence inspection hard to discover

**Location:** [form navigation](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L465),
[number-key guards](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L491),
[evidence input dispatch](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L592),
[footer](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L671).

In Setup, five Tabs wrap back to Checkout; in Settings, Tab also stays inside
the form. Pressing the header's `5` key while editing Setup inserts `5` into
the checkout. Reaching Allow dirty from Setup therefore requires Esc, 5, the
appropriate field edits, Esc and 2 to return to Setup. The documented
"outside text editing" condition has no explicit leave-editing control that
preserves the current tab.

In Findings, Down moves the table cursor and PgDown changes the result page.
Only the undocumented Ctrl+D/Ctrl+U bindings reach the evidence viewport's
vertical scrolling. There is no visible evidence focus or scroll hint. The
required facts often sit below the first few serialized JSON fields.

**Correction:** Establish explicit focus for the form, table and detail panes.
Show context-dependent key hints, a consistent back action and an action menu
for the existing operations. Keep navigation keys separate from field editing.

**SRS trace:** FR-71, QR-21. The behavior matches parts of the keyboard document,
but the document does not make the workflow discoverable in the application.

### R6 — P2: The native layout exceeds common terminal bounds

**Location:** [resize handler](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L219),
[view construction](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L628).

At 75x26 the footer is 77 display cells wide. At 60x20 Setup emits 21 lines and
Settings emits 22, so content or footer controls cannot all remain visible.
The five-scanner availability line is 122 cells wide even in the 80-column
snapshot. Updating component widths does not bound the enclosing layout.

**Correction:** Budget the whole screen, wrap availability and hints, and use
responsive panes or scrollable forms. For unsupported sizes, show a clear
minimum-size message rather than clipped controls.

**SRS trace:** QR-21. The existing resize test switches panes and invokes Export
programmatically; it does not assert that the rendered controls fit or can be
reached after resizing.

### R7 — P2: Progress does not follow the historical run being inspected

**Location:** [history selection](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L503),
[Progress rendering](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/internal/tui/app.go#L662),
[Python saved-progress handling](https://github.com/ppk205/DevSecOps-Agent/blob/88e21d62a4ddab688d6e0ea20ba612347c91484b/src/vulnscan/tui/app.py#L425).

Opening a historical run fetches findings only. Progress continues to render
the in-memory `m.log` from the last scan in the session; after restart it has
no saved events. The probe opened historical run A and still saw run B's log.
The native TUI API has no operation for loading saved stage events. The Python
fallback loads the selected run's status and events from storage.

**Correction:** Separate active-scan activity from inspected-run activity,
label both with the public run ID, and load stored events for historical runs.

**SRS trace:** FR-71, DR-09, IR-16, QR-06. This is a native history-inspection
regression.

## Design changes for the requested interaction style

The interface currently distributes one scan across Setup, Settings, Progress
and Findings. The native migration also replaced descriptive Select widgets
and buttons with free-text fields and shortcuts. Both implementations still
present finding evidence as serialized schema data. These choices increase
the amount a user has to remember and interpret.

Use one primary scan workspace:

1. Show the current checkout and profile, with an obvious Review/Start action.
   Put threshold, limits, dirty-content consent and advisory options in an
   expandable advanced section of that same workflow.
2. Show a readable activity timeline: current stage/tool, status, elapsed time,
   partial finding count, blockers and the next available action. Separate this
   from full raw logs.
3. Open a finding with title, severity, CWE, scanner/rule, file and line, source
   excerpt, verification state and explanation. Keep raw JSON as optional details.
4. Make keyboard commands discoverable through an action menu and contextual
   hints. Offer typed choices for profiles, thresholds, yes/no values and export
   formats. Path completion would reduce checkout-entry friction.
5. Keep history as a clearly identified run picker, with retry/export actions
   tied to that run and a visible route back to the current scan.

These are proposals for presenting the existing FR-70/71 operations. The SRS
does not yet define conversational task submission, agent permissions or
general autonomous coding behavior. If those are intended, specify their
behavior and boundaries before implementing them.

## Required verification before declaring the TUI ready

- With two runs, move the history cursor and verify Retry/Export target the
  highlighted run in both implementations.
- Complete setup, review every relevant setting, start, inspect evidence,
  export and quit using only actual keyboard events, without programmatically
  assigning panes, inputs or button presses.
- Review long configurations and evidence using advertised controls. Move the
  cursor while review is pending and verify a valid response still applies.
- Return a report failure and verify its cause and recovery action remain
  visible. Reopen saved failed and completed runs and inspect their own events.
- Test rendered bounds and access to controls at 80x24 and 75x26, and verify
  deliberate behavior at smaller sizes. Test resizing during each main workflow.
- Keep the existing large-finding performance, cancellation, stale-response,
  process-exclusion and partial-evidence checks.

Fix R1–R3 first, then R4–R7 and the main workspace flow. Backend test success
should remain a separate gate from terminal workflow acceptance.
