# Native application and Python compatibility

The Go application implements the TUI, configuration resolution, SQLite
queries and incremental writes, scan lifecycle, finding grouping, coverage
reconciliation, policy decisions and local HTTP handlers. Scanner adapters,
container isolation, report/template rendering, model inference and research
utilities use the Python implementations through an owned child process.

These libraries retain the existing scan and report contracts. Python remains
usable as a complete fallback. No detached service is started. Closing the
owned bridge requests cancellation and waits for evidence persistence.

## Build and launch

For Windows and Linux/macOS setup, locked dependencies, compilation, Python
packages, and scanner prerequisites, see [Compile, build, and run](BUILD-AND-RUN.md).

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
`scan-run` launch through Python to preserve the newer repository URL and
credential workflows. Set `DEVSECOPS_NATIVE=go` to select the native local
checkout interface explicitly. Native `scan-run`, history, cancel, retry, export and
`serve` use the same SQLite database and retained report data.

For a released binary, rename the platform asset to `devsecops-agent-go`
(`.exe` on Windows) and put it on PATH. Install the matching Python wheel.
`DEVSECOPS_PYTHON` selects the Python interpreter; the console launcher sets it
to its own interpreter automatically. `DEVSECOPS_GO_BINARY` selects a specific
native binary.

To use Python throughout a session:

```powershell
$env:DEVSECOPS_NATIVE = 'python'
.venv/Scripts/devsecops-agent.exe tui
```

The native application keeps the existing command names and exit statuses:
0 passed, 1 threshold exceeded, 2 configuration/execution failure, 130
cancelled. Scanner and coverage failures take precedence over threshold
results. Missing tools remain explicit.

## Keyboard workflow

The application opens in Workspace with checkout/profile controls and an
expandable Advanced section containing all scan options. History, Activity,
Findings and Reports remain views of the same run workflow. Review presents
effective values and a verified commit before starting. Details use retained
source excerpts and recorded status; unavailable evidence remains explicit.
The Python workspace also retains repository URLs, pinned commit and clone-cache
controls in Advanced options, and a separate API Keys tab with hidden values.

The native interface focuses controls with Tab and uses Enter to edit text or
activate a control. Left/Right or Enter cycles typed choices. The Python
fallback uses Textual inputs, Select widgets and a collapsible Advanced section.

| Key | Operation |
| --- | --- |
| Ctrl+N | Open Workspace and focus the checkout |
| Ctrl+K | Native Workspace: enter/save an API key; elsewhere (and in Python): open the action menu |
| Tab / Shift+Tab | Move between visible fields and actions |
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

SRS trace: C-04 and IR-01 permit the implementation choices; FR-70/71 and
IR-16 define shared execution and progress; DR-01/09 define compatible storage;
QR-21 defines responsiveness, cancellation and partial evidence retention.
