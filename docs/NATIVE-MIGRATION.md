# Native application and Python compatibility

The Go application implements the TUI, configuration resolution, SQLite reads,
the deterministic native scan lifecycle and local HTTP handlers. Hunt, AI review
or AI-report settings route execution through the existing Python `ScanService`
over the owned JSONL bridge. Scanner adapters, isolation, provider transports,
report rendering and model inference remain Python components. The Go interface
displays progress and reads the shared persisted results for either execution path.

These libraries retain the existing scan and report contracts. Python remains
usable as a complete fallback. No detached service is started. Closing the
owned bridge requests cancellation and waits for evidence persistence.

The native-language integration joins Go/Ruby/C# files to source inventory,
`LanguageKind` and the native-hunt adapter. Semgrep reports those units as
unsupported with its bundled rules. Model hunt still has no dedicated passes
for them. The hunt-recall branch adds bounded broad/concern passes to the Python
pipeline; its historical recall figures were not rerun for this merge. See
[the integration record](REMOTE-INTEGRATION-2026-11-05.md).

Outbound notifications (FR-75) also use the owned Python bridge. Native scans
persist their final result before invoking the shared notification completion
handler. AI-enabled scans already reach it through ScanService. F6 opens event
preferences; F7 reviews the selected run's retained deliveries. Both screens use
Up/Down navigation and explicit Enter actions. Network operations run outside
the TUI update/render loop. Notification failure does not fail a scan. See
[NOTIFICATIONS.md](NOTIFICATIONS.md) for setup and delivery limits.

## Build and launch

Install Go 1.27.1 and the existing Python project environment. From the project
root:

```powershell
.venv/Scripts/python.exe ci/build_native.py
.venv/Scripts/devsecops-agent.exe tui
```

This workspace also has a local SDK under `.tools/go`; its build command is:

```powershell
.venv/Scripts/python.exe ci/build_native.py --go .tools/go/bin/go.exe
```

The build creates `bin/devsecops-agent-go.exe` on Windows or
`bin/devsecops-agent-go` elsewhere. Existing console commands discover that
binary automatically for operations with native parity. The default `tui` and
`scan-run` launch through Python to preserve its advanced source and credential
controls. Set `DEVSECOPS_NATIVE=go` to select the native interface explicitly.
Both interfaces accept repository URLs and local folders. Native `scan-run`, history, cancel, retry, export and
`serve` use the same SQLite database and retained report data.

Report exports include the shared OWASP Top 10:2025/CWE cross-reference in
human formats and JSON/SARIF metadata. Native export reaches the Python report
generator over the existing bridge. No native rebuild is needed for this
reporting-only addition. See [OWASP-REPORTING.md](OWASP-REPORTING.md).

AI review also uses the shared corrected validator and CVSS v4.0 scorer. Valid
model vectors produce computed Base/contextual scores in retained assessments;
model confidence and raw detections do not establish independent verification.
Source assumptions stay unverified. See [VALIDATOR-CVSS.md](VALIDATOR-CVSS.md).

For a released binary, rename the platform asset to `devsecops-agent-go`
(`.exe` on Windows) and put it on PATH. Install the matching Python wheel.
`DEVSECOPS_PYTHON` selects the Python interpreter; the console launcher sets it
to its own interpreter automatically. `DEVSECOPS_GO_BINARY` selects a specific
native binary.

Direct launches from `bin` or another working directory discover the application
environment beside the executable or in its parent directory before searching
the caller's directory. Windows uses `.venv/Scripts/python.exe` or
`venv/Scripts/python.exe`; Linux/macOS use `.venv/bin/python`,
`.venv-linux/bin/python` or `venv/bin/python`. The launcher then checks
`VIRTUAL_ENV` and PATH (`python3` first on Linux/macOS, `python` first on Windows).
An explicit `DEVSECOPS_PYTHON` takes precedence. Python interpreter symlinks stay
inside their virtual-environment path. Both CLI forwarding and the service bridge
use the selected environment's source import path when available, replacing a
foreign `PYTHONPATH`. The caller's working directory is preserved.

The native executable still requires the matching Python application and its
dependencies; copying the executable alone does not bundle Python.

To use Python throughout a session:

```powershell
$env:DEVSECOPS_NATIVE = 'python'
.venv/Scripts/devsecops-agent.exe tui
```

The native application keeps the existing command names and exit statuses:
0 passed, 1 threshold exceeded, 2 configuration/execution failure, 130
cancelled. Scanner and coverage failures take precedence over threshold
results. Missing tools remain explicit.

## AI support

Native defaults are deterministic, with AI review and AI report disabled. A saved
key does not change these defaults. Python `ScanConfig` still defaults to Hunt.
The native EXE exposes these settings:

| Setting | Effect |
| --- | --- |
| Scan mode: Hunt | Runs model hunt, investigation/validation and final narrative through Python. |
| Provider profile | Choose an added profile or leave automatic selection for review. |
| Model override | Use the entered model; otherwise use the profile default or its first model. |
| AI review / AI report in Advanced | Enables those stages independently in deterministic mode. |
| Maximum AI findings | Bounds the findings selected for AI review. |
| Laya | Controls local advisory routing separately from provider-backed AI support. |

Hunt displays the provider/model controls in Workspace. Advanced offers separate
review/report switches in deterministic mode. Provider choices expose aliases,
models and key set/missing status. They never return key values. Register an
endpoint with the existing `provider-add` command and save its referenced key
through masked key entry or `env set`; use a Chat Completions-compatible profile.
Profiles and `EnvFile` use the same project-root lookup from `bin`.

Ctrl+E resolves the effective provider/model, shows availability and describes
source transfer before Ctrl+S starts execution. If no provider is available,
model stages are explicitly skipped. HTTP/provider failures remain visible and
preserve baseline findings. IndependentValidator retains status ownership.
Retries reuse the saved AI configuration and execution path.

Direct native CLI examples, using an already configured profile:

```text
devsecops-agent-go scan-run --checkout ./project --mode hunt --provider my-provider --model your-model --json
devsecops-agent-go scan-run --checkout ./project --ai-review --ai-report --provider my-provider --max-ai-findings 2 --json
```

The native boolean options can be cleared with `--ai-review=false` and
`--ai-report=false`. The Python console commands retain their existing syntax.

Activity shows call start/failure/completion, returned text and completed or
rejected tool steps. Calls retain provider/model identity and reported usage.
Finding details load the matching assessment from that run and show its rationale
and model proposal separately from the finding's validation status. These details
also remain available after reopening history. Unknown token counts stay unknown;
monetary pricing is not configured and cost is shown as unavailable.

Changing a locally loaded saved key refreshes subsequent scans. Process-injected
credentials still take precedence. Current calls retain their existing client.
Source snapshots and registered read-only model tools retain their path and
permission limits; the UI does not add write or shell tools.

`providers/events.py` provides a per-run observer. Progress uses the existing
version-1 event envelope with `model_call` and `model_tool` stage names. Provider
text is redacted before persistence/display; visible tool activity includes names
and outcomes, not credentials. Model replies preserve returned explanation fields
alongside final content, and investigation messages retain tool-call IDs.

Limits: updates occur as calls finish, not token by token. Only text returned by
the provider can be shown. Full prompt/wire transcripts and provider price
estimation are not implemented. Cancellation stops subsequent calls; a synchronous
request already in flight can take up to its configured provider timeout to end.
The owned-child shutdown deadline can terminate an unresponsive worker, retaining
the progress already persisted. Live provider connectivity is separate from the
offline verification in [the verification record](NATIVE-AI-VERIFICATION-2026-11-04.md).

## Source input

The native TUI, Textual TUI, CLI and web source flows use the shared Python
resolver. Review identifies a repository URL, a local Git checkout, or a local
folder without a verifiable Git revision. Starting a reviewed native scan uses
the resolved folder, repository identity and actual commit from that review.

| Input | Behavior |
| --- | --- |
| Existing absolute or relative folder | Scan the local folder; quotes around paths with spaces are accepted. |
| `file://` folder URI | Decode the URI into a local folder path. |
| `./folder`, `../folder`, drive or UNC path | Always a local path. Missing or inaccessible folders report an error. |
| `owner/repo` | Use an existing local folder first; otherwise expand to a GitHub repository URL. |
| HTTPS, HTTP, SSH or Git clone URL | Resolve to a cached clone and record its actual commit. |
| `github.com/owner/repo` or supported host shorthand | Expand to an HTTPS clone URL. |
| Plain source folder, empty Git repository, or unavailable Git | Local scans record `no-revision`, an explanation, unknown cleanliness and per-file hashes. |
| Empty input, file, malformed URL or URL containing credentials | Report an input error. Select a folder or a valid clone URL. |

Trailing URL slashes and matching outer quotes are normalized. GitHub tree/blob
links are rejected with a request for the repository URL. Git is required for
remote cloning and commit verification. A cached repository can instead be
selected by its local folder path when Git is unavailable. Explicit commit pins
and CI source checks cannot be satisfied by an unversioned folder.

Unversioned enumeration excludes credential files such as `.env`, version-control
metadata, environment/dependency caches and application runtime output. Symlink
escapes, unreadable directories and file-limit violations fail intake. A later
file-hash change fails source consistency checks; `no-revision` never means the
folder was verified clean.

An untracked or ignored folder inside another Git repository uses its own file
hashes; it does not inherit an unrelated parent commit. A tracked project
subfolder retains the parent repository's real revision.

New remote cache folders include a URL-derived suffix so different owners or
hosts with the same repository name remain separate. Existing cache folders are
reused only when their Git origin matches the requested URL. Cache symlinks are
rejected. Native `scan-run --workdir <folder>` selects the clone cache; the TUI
uses `harness` under the caller's working directory. No target is force-reset.

The legacy web form accepts a local folder in its main repository field and
allows a blank commit. Its separate checkout field is an optional local override.

SRS trace: FR-01/10 define source identity and no-revision inputs; FR-70/71 define
shared execution and review; QR-16/20 define errors and platform support.

## Keyboard workflow

The application opens in Workspace with checkout/profile controls and an
expandable Advanced section containing all scan options. History, Activity,
Findings and Reports remain views of the same run workflow. Review presents
effective values and either a verified commit or explicit revision limits before
starting. Details use retained
source excerpts and recorded status; unavailable evidence remains explicit.
The Python workspace also retains repository URLs, pinned commit and clone-cache
controls in Advanced options, and a separate API Keys tab with hidden values.

The native interface uses Up/Down to move between controls, including leaving a
single-line text field. Enter edits text or activates a control. Left/Right
switches views outside editing and focused readers; on a typed choice it changes
the value, and inside a text field it moves the cursor. Up/Down scrolls focused
readers and navigates table rows. Tab remains an optional focus shortcut. The
Python fallback keeps Textual's input, Select and focus behavior.

| Key | Operation |
| --- | --- |
| Ctrl+N | Open Workspace and focus the checkout |
| Ctrl+K | Open the action menu |
| Up / Down | Move between native form fields and actions; move between key-entry fields |
| Left / Right | Switch native views, cycle a focused choice, or move a text cursor while editing |
| Tab / Shift+Tab | Optional alternative form navigation; standard Textual focus navigation |
| Enter / Esc | Begin/end text editing or activate/back out of a reader |
| Ctrl+Space | Complete checkout directory names without blocking navigation |
| Ctrl+E | Review effective configuration and checkout |
| Ctrl+S | Start the reviewed scan |
| Ctrl+1–5 | Open History, Workspace, Activity, Findings or Reports, including while editing |
| 1–5 | Native view shortcuts while outside text editing |
| Ctrl+R | Open and refresh History |
| Enter | Open a selected run or finding |
| / | Search findings; Enter returns to table navigation |
| Up/Down, PgUp/PgDown | Scroll a focused review, activity or evidence reader |
| V | Toggle readable/raw details in review or evidence |
| PgUp / PgDown | Native result pages while the finding table is focused |
| Ctrl+T | Retry the highlighted History run, or the explicitly opened run elsewhere |
| Ctrl+O | Export the highlighted/opened run using the current artifact directory and report format |
| Ctrl+X | Cancel the executing scan |
| Ctrl+Q | Quit; an active scan offers stay or cancel and quit |

Finding lists render at most 200 rows. Input is debounced by 150 ms. UI
updates never read configuration files, execute scanners, or query SQLite.
Responses carry generations so obsolete searches and historical selections
cannot overwrite the current view. Refreshing preserves the cursor.

Historical Activity reads saved events, report failures and artifact paths for
that run. Live activity remains separate when a historical run is inspected.
The native frame stays within the terminal bounds; both interfaces show a
resize message below 60 columns or 18 rows. Cancellation and quit still work
at smaller sizes.

## Storage and bridge

Migration 3 adds finding identities, searchable projections, a run finding
revision and indexes. It preserves existing integer primary keys and JSON
history. Changed findings are reconciled transactionally instead of deleting
the complete result set on every stage.

The bridge uses JSON-lines protocol version 1 over stdin/stdout, request IDs,
sequenced progress and structured failures. Requests and replies are bounded
at 8 MiB. Reports remain file artifacts. The Go engine acquires the existing
cross-process database lock through the owned Python child; Python and Go
cannot execute concurrent scans against that database.

Laya has a separate persistent child with inference deadlines, real batching,
actual checkpoint/device provenance and an input hash matching exactly what
the model received. The training guide is [LAYA-TRAINING.md](LAYA-TRAINING.md).

## Verification and release

```powershell
go vet ./...
go test ./...
.venv/Scripts/python.exe -m pytest
go test ./internal/tui -run '^$' -bench BenchmarkQR21Navigation -benchmem
```

Native parity tests compare findings, policy, stage order, history and retry
across Go and Python. Dashboard tests exercise routes, CSRF, status updates
and all exports. Python tests still cover the fallback interface. CI runs Go
checks on Windows, Linux and macOS and builds native release binaries alongside
the wheel and source distribution. Model downloads, GPU training and paid
calls are excluded from those checks.

Native AI integration tests run the EXE through the real bridge, provider parser,
investigation loop and persistence using synthetic HTTP responses. CI includes
`tests/platform/test_native_ai.py` in the native platform job. Synthetic scanner
observations and replies establish execution/visibility behavior, not detection
accuracy. See [NATIVE-AI-VERIFICATION-2026-11-04.md](NATIVE-AI-VERIFICATION-2026-11-04.md)
for the actual check results and remaining failures.

SRS trace: C-04 and IR-01 permit the implementation choices; FR-70/71 and
IR-16 define shared execution and progress; DR-01/09 define compatible storage;
QR-21 defines responsiveness, cancellation and partial evidence retention.
