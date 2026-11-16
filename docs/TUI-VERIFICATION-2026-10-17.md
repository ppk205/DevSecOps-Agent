# TUI verification and first-launch dependency review

Date: 2026-10-17  
Source reviewed: `8750f5b` (current checkout). TUI-change review baseline:
`88e21d6`, the commit covered by the earlier `TUI-REVIEW.md`.

## Verdict

**The default TUI is not completely unresponsive, but its initial focus makes
ordinary typing appear ineffective. The native Go TUI also has reproducible
API-key input defects. First-launch dependency auto-installation is absent.**

This was a verification/review pass, not an implementation pass. Application
and launcher code were not changed; automatic installation has **not** been
implemented. The proposed bootstrap contract is documented below.

## Why interaction appears broken

### 1. Default Python TUI starts with focus on the tab bar

The launcher defaults to Python/Textual for `tui`. Although Workspace is the
initial pane, focus is `ContentTabs()`, not the checkout input. Typing immediately
after startup does not change the repository field. This was reproduced at
80x24, 75x26 and 120x40, and independently in a real Windows PTY.

Pressing **Ctrl+N** focuses the checkout; typing then works. **Ctrl+K** opens the
action menu, and **Ctrl+Q** exits. This initial-focus behavior is a first-use
usability gap, not proof that all input handling is broken or a violation of an
explicit requirement to autofocus the checkout. The keyboard workflow tests begin
with Ctrl+N, which bypasses this startup problem.

Source: `src/vulnscan/tui/app.py:208`, `on_mount`, `initialized`, `action_setup`.
Suggested usability improvement: explicitly focus the primary checkout control after
initial Workspace layout without stealing focus from a user who has navigated
elsewhere during initialization.

### 2. Native Ctrl+K does not save during API-key entry

In the Go TUI, press Ctrl+K to enter key input, type a variable name, Tab to its
hidden value, then use the displayed Ctrl+K save shortcut. The handler requires
`!m.keyInput`, so it skips saving precisely while key entry is active. The probe
observed a populated name/value, no save command and zero `EnvSet` calls.

Source: `internal/tui/controls.go:244`.
Recommended correction: handle the advertised save action during key entry,
or expose an explicit, reachable save control and accurate hints.

### 3. New scan leaves hidden API-key capture active

While entering a native key value, press Ctrl+N and type a new checkout. The
interface visually enters checkout editing, but `navigate` never clears
`keyInput` or blurs the key widgets. `handleInput` still routes characters to the
hidden key value. A probe typed `Z`: the checkout stayed unchanged and the hidden
value gained a character. A source-built native binary reproduced the same
behavior in a Windows PTY.

Source: `internal/tui/controls.go:131-138`, `handleInput`.
Recommended correction: make key-entry focus exclusive and clear it when
navigating to ordinary scan controls.

### 4. Digits in native API keys activate view shortcuts

With key entry active, typing the value `abc1def` navigates to History at `1`
and leaves the value at `abc`. The plain `1`-`5` shortcut guard excludes normal
editing/searching, but does not exclude `keyInput`. This prevents entering many
ordinary API keys correctly; it is independent of the save-shortcut defect.

Source: `internal/tui/controls.go:310-311`.
Recommended correction: do not dispatch unmodified view shortcuts from a text
or secret input context.

### 5. Expanded native options hide the active key input

At 80x24 and 75x26, expanding Advanced options pushes the API-key fields below
the viewport. Entering key mode does not scroll to them: viewport positioning
uses the last scan-control `focusedLine`, not the active key field. The focused
name is visible with Advanced collapsed but invisible with it expanded. At
120x40 there is enough room, explaining why larger-window checks miss this.

Source: `internal/tui/view.go:153-173`.
Recommended correction: include key fields in focus/viewport accounting.

## Dependency and environment findings

| Check | Verified result |
| --- | --- |
| Python runtime | Workspace venv uses Python 3.11.15 |
| TUI dependency | Textual 1.0.0 is installed |
| Semgrep | Available through the application's venv-aware adapter lookup, despite not being on the caller's PATH |
| Gitleaks | Unavailable; the default Fast profile requires it |
| SpotBugs / Dependency-Check | Unavailable; required by Full rather than Fast |
| Docker | Not on PATH; Full's isolated build needs a usable container runtime |
| CodeQL | Unavailable; experimental and not a default Fast requirement |
| Git / Java / Maven | Found on PATH |
| Local installation version | Installed Python metadata and the existing `bin/devsecops-agent-go.exe` report 0.2.0; source metadata is 0.3.0 |

Missing scanners do **not** explain the initial inability to type: input worked
after refocusing. They **do** block a successful scan. Startup currently probes
availability and displays an installation hint; it never installs the tools.
Missing base Python packages can prevent launch even earlier because the CLI
imports Typer/SQLAlchemy before running any application startup logic.

The installed-version mismatch is a local environment observation, not a newly
proven source regression. Native source was separately compiled to
`artifacts/tui-verification/devsecops-agent-go.exe` for the PTY checks; the existing
binary was not overwritten.

## Requested automatic installation: proposed acceptance contract

The current SRS permits dependency/tool installation under C-01 but does not
require automatic first-launch setup. The smallest proposed extension is to
state under FR-71 that interactive startup checks required runtime and selected
profile dependencies, installs missing supported dependencies, then opens a
usable workspace; failures remain visible and retryable. This is a proposal,
not an implemented requirement or a completed fix.

An implementation should meet these conditions:

1. **Bootstrap before application imports.** Use a lightweight entry point that
   can run without Textual, Typer or SQLAlchemy. Check Python >=3.11, create/reuse
   an application-owned venv and install the project and locked runtime packages.
2. **Install only what is missing for the selected profile.** Fast needs Semgrep
   and Gitleaks. Full additionally needs its Java/Maven/container prerequisites,
   SpotBugs/FindSecBugs and Dependency-Check. Use supported platform-specific
   installers or provide an actionable blocker when automatic setup is not safe.
3. **Respect dependency integrity.** Reuse the applicable pinned locks/tool
   versions, verify downloads, avoid shell-built commands, and do not silently
   elevate privileges or replace global Python packages.
4. **Keep startup interactive.** Display setup progress and failures, allow
   cancellation, serialize concurrent setup, and re-probe actual executables
   after installation. Do not use a single 'installed once' marker as proof.
5. **Avoid unnecessary installs.** Subsequent healthy launches do not reinstall.
   Missing dependencies are detected again if deleted. Optional Laya/training
   models and experimental CodeQL are not downloaded merely to open the TUI.
6. **Handle offline and automated use deliberately.** Offline setup failure must
   explain what is missing rather than appearing hung. CI/noninteractive mode
   must have an explicit, reproducible setup policy rather than unexpected
   background downloads.

Required tests: empty environment; partially installed environment; offline
launch; failed/hash-invalid download; unsupported platform; cancelled and
concurrent setup; removed dependency after first launch; healthy second launch;
Fast versus Full; no automatic model download; launch followed by actual typing
without an extra focus shortcut.

## Verification performed

- `tests/tui`, `tests/cli/test_launcher.py`, `tests/cli/test_env_commands.py`:
  **33 passed, 1 warning**, in 44.60 seconds. Existing scanner-fixture workflows
  cover review, scan, evidence, export, restart, resize and cancellation.
- `go test ./internal/tui ./cmd/devsecops-agent`: **passed**, using the existing
  offline module/build caches under `.tools`.
- Three Python startup-size probes reproduced the focus issue and verified
  Ctrl+N input and Ctrl+K menu behavior.
- Four native diagnostic probes reproduced the save, focus-state, numeric-key
  and viewport defects. These probes **assert the observed defects**; passing
  probes do not mean the product behavior is correct.
- Real Windows PTY sessions checked default Python startup/refocus/menu/quit
  and source-built native key entry/save failure/new-scan capture/quit. Only
  dummy input was used; no API key was saved.
- Adapter capability checks recorded the missing scanner tools above.

Evidence and reproducible probes:

- [Python test results](../artifacts/tui-verification-python.xml)
- [Python startup observations](../artifacts/tui-verification/python-probe-results.json)
- [Python probe source](../artifacts/tui-verification/python_probe.py)
- [Native diagnostic results](../artifacts/tui-verification/native-probe-results.txt)
- [Native probe source](../artifacts/tui-verification/native_probe_test.go)
- [Native test overlay](../artifacts/tui-verification/go-overlay.json)
- [Dependency observations](../artifacts/tui-verification/dependencies.json)

Artifacts are local and gitignored. No production code was modified. No real
scanner run, paid AI call, model download, package installation or privileged
installation was performed. Network access is restricted in this environment;
an initial Go test attempt with an empty module cache could not download modules,
so verification was repeated successfully against the populated offline cache.

## Immediate workaround

Use the default Python interface in an actual terminal rather than an IDE output
pane or redirected process:

```powershell
$env:DEVSECOPS_NATIVE = 'python'
.\.venv\Scripts\devsec.exe tui
```

Press **Ctrl+N**, then **Ctrl+A**, enter a local checkout or repository URL, and
use **Ctrl+E** to review before **Ctrl+S**. Keep the terminal at least 60x18.
Use the Python API Keys tab instead of the native key controls until corrected.
Gitleaks still needs to be installed for a successful Fast scan; this review did
not add an automatic installer.

## Requirements trace

- SRS section 2, C-01/C-04: local execution, permitted dependency installation,
  Python/native compatibility.
- SRS section 3, [FR-71](SRS.md#L389-L399): keyboard-accessible Workspace,
  action discovery and effective review.
- SRS section 3, FR-72: selected scanners must succeed; missing tools cannot
  silently yield a passing gate.
- SRS section 5, IR-14: terminal versus nonterminal invocation behavior.
- SRS section 6, [QR-21](SRS.md#L537-L543): keyboard-only operation, supported
  terminal sizes and responsive workers; QR-22: locked dependencies/tools.

The earlier `TUI-REVIEW.md` describes previous verification. It does not
establish that these later native API-key changes or current local dependencies
are ready.
