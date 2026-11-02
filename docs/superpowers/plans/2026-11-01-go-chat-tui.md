# Go chat TUI as the main client — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `devsec tui` open a chat-first Go client that drives the human-gated harness over a new `devsec-chat/1` stdio protocol, move the baseline scanners behind a Baseline tab, and remove the Python TUI.

**Architecture:** Python gets a `SessionHost` that turns session-log entries into numbered events, plus a stdio adapter `vulnscan.harness.rpc`. Go gets a never-dropping `bridge.ChatSession` and a new `internal/chat` Bubble Tea model. That model embeds the existing `internal/tui` scan model as the Baseline tab. Gates stay enforced in Python (T1).

**Tech Stack:** Python 3.11 (threading, queue, uuid), Go 1.27.1 with `charm.land/bubbletea/v2`, `bubbles/v2` and `lipgloss/v2` (already in go.mod).

**Spec:** `docs/superpowers/specs/2026-11-01-chat-client-remote-triggers-design.md` Part A, §5, §6 and §7. Also `docs/ARCHITECTURE-MODIFICATION.md` and `AGENTS.md`.

**Precondition:** the plan `2026-11-01-stabilize-and-merge-main.md` has merged into `main`, and this work branches from it as `feat/go-chat-tui`.

## Global Constraints

- AGENTS T1: Go and UI code display and relay only. No gate logic in Go. Every decision is validated in Python.
- AGENTS H5 and T4 (as changed by this plan): Enter with no highlighted button, Esc, timeout, losing focus, closing the dialog or a closed pipe never approve; each yields `undecided`.
- AGENTS A2 and G1: no new Python or Go dependencies.
- AGENTS T9: layouts work at 80x24 and 75x26. Below 60x18, show a resize message.
- AGENTS T10 and K3: never display key values. Every event the host emits passes through `redact_value` (from project 1).
- Protocol: one JSON object per line, at most 8 MiB per line, and every line carries `"protocol": "devsec-chat/1"`.
- The G3 commands, plus `go vet ./...` and `go test ./...`, pass at the end of every task. Use the offline Go settings from `docs/BUILD-AND-RUN.md` §3.
- Commit subjects follow AGENTS R3 and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **The Python process dies while a G6 dialog is open.** The dialog closes, the gate is undecided, input is disabled, and a Restart button resumes from the JSONL. Pinned in Task 4 by `TestBrokenPipeLeavesGateUndecided`.
2. **The user presses Enter right after a G0 dialog appears.** Nothing happens, because the highlight starts on no button. Pinned in Task 5 by `TestEnterWithoutHighlightNeverAnswers`.
3. **A 2,000-line diff at G6 in an 80x24 terminal.** The buttons stay disabled until the last line has been shown, by wheel, PgDn or End. Pinned in Task 5 by `TestG6ButtonsUnlockOnlyAtDiffEnd`.
4. **A second message sent while a turn is still running.** An `error` event comes back, and the second message is not silently queued. Pinned in Task 1 by `test_second_message_while_busy_is_refused`.
5. **A cloud model is added without a key, or its key is later removed.** The start screen shows `my-deepseek · key missing` with a Set key button. It never shows a key value or an environment-variable name. Pinned in Task 6 by `TestStartScreenShowsKeyStatusNeverValue` and in Task 2b by `test_models_event_has_no_key_values_or_env_names`.

---

### Task 1: SessionHost and session-log listeners

**Files:**
- Modify: `src/vulnscan/harness/audit.py` (add `SessionLog.subscribe`)
- Modify: `src/vulnscan/harness/session.py` (add `Session.cancel`, and interrupt checks in `send`)
- Create: `src/vulnscan/harness/host.py`
- Test: `tests/harness/test_host.py`

**Interfaces:**
- Produces:
  - `SessionLog.subscribe(fn: Callable[[dict[str, Any]], None]) -> Callable[[], None]`. Listeners are called after the line is written. The returned function unsubscribes.
  - `Session.cancel() -> None`. When set, `send` stops before the next provider call or tool run and adds `Message("assistant", "Interrupted.")`. The flag clears at the start of the next `send`.
  - `SessionHost(session: Session, emit: Callable[[dict[str, Any]], None])`, with methods:
    - `submit(text: str) -> bool`: False, and emits `error`, if a turn is already running;
    - `interrupt() -> None`;
    - `wait_idle(timeout: float) -> bool`, used by tests;
    - `close() -> None`.
  - Events are `dict`s with the keys `type`, `seq` (int, starting at 1, increasing by 1) and `protocol="devsec-chat/1"`, plus the fields from spec §2.3. Every event passes through `redact_value` before `emit`.

- [ ] **Step 1: Write the failing tests** (use `ScriptedTransport` from `tests/harness/fakes.py` and `make_ctx` from `tests/harness/conftest.py`):
  ```python
  def test_turn_emits_ordered_events():
      # script: assistant tool_call(extract_candidates) -> assistant text "done"
      # Expect the type sequence: tool_call, tool_result, usage, text_delta, usage, done{completed},
      # with strictly increasing seq.

  def test_second_message_while_busy_is_refused():
      # The transport blocks on a threading.Event; submit("a") is True, submit("b") is False,
      # and the last event is error with message "a turn is already running".

  def test_interrupt_ends_turn_without_running_next_tool():
      # The first reply holds two tool calls. interrupt() is called from the first tool's run.
      # The second tool never runs, and done.reason == "interrupted".

  def test_events_are_redacted():
      # The assistant text contains "sk-ant-" + "x" * 24. No emitted event contains it.
  ```
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_host.py -q`
  Expected: FAIL (ImportError: host).
- [ ] **Step 3: Implement the subscribe hook, the cancel flag and `SessionHost`.**
  - Map log entries to events:
    - a `message` with role `assistant` and content → `text_delta`;
    - each tool call → `tool_call`;
    - role `tool` → `tool_result`, where `summary` is the first 120 characters of a one-line rendering;
    - `usage` → `usage` with running totals;
    - `gate` → `gate_result`.
  - The turn runs on a daemon thread. A `threading.Lock` guards the busy flag.
- [ ] **Step 4: Run the tests to confirm they pass.** Then run all of `tests/harness`.
  Expected: PASS.
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Add a session host that turns harness activity into numbered events"
  ```

### Task 2: bridge_asker and the `devsec-chat/1` stdio adapter

**Files:**
- Create: `src/vulnscan/harness/rpc.py`
- Modify: `src/vulnscan/harness/host.py` (add `bridge_asker` and `ready_event`; `models_event` comes from Task 2b)
- Test: `tests/harness/test_rpc.py`

**Interfaces:**
- Consumes: Task 1 `SessionHost`.
- Produces:
  - `bridge_asker(emit, replies: queue.Queue[dict[str, Any] | None]) -> Asker`. `None` in the queue means shutdown.
  - `serve(stdin: TextIO, stdout: TextIO) -> int`, the entry point for `python -m vulnscan.harness.rpc`. It handles `hello`, `start`, `user_message`, `permission_reply`, `interrupt` and `command`. Commands map to the same handlers as `ChatConsole.handle`: `/model`, `/mode`, `/cost`, `/review`, `/export`, `/resume`, `/clear`, `/help`.

- [ ] **Step 1: Write the failing tests.**
  ```python
  @pytest.mark.parametrize("reply", [
      {"choice": "yes_all"}, {"choice": "approve", "edits": []}, {"choice": ""}, None])
  def test_bridge_asker_invalid_or_closed_is_undecided(reply): ...
  #   For each case, the decision.choice is "undecided" and decision.approved is False.

  def test_bridge_asker_matches_request_id():
      # A reply with the wrong request_id is ignored; the right one decides.

  def test_serve_round_trip_over_pipes(tmp_path):
      # Start `python -m vulnscan.harness.rpc` as a subprocess with DEVSEC_CHAT_FAKE_TRANSPORT pointing
      # at a JSON script (test-only hook, read only when the variable is set).
      # Send: hello, start{local fake}, user_message.
      # Read until done. The event types include models, ready, permission_request (G0).
      # After the reply {"choice": "approve"}: text_delta, done.

  def test_stdin_eof_leaves_pending_gate_undecided(tmp_path):
      # Close stdin while G0 is pending; the session log records the G0 choice "undecided".
  ```
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_rpc.py -q`
  Expected: FAIL.
- [ ] **Step 3: Implement the asker and `serve`.**
  - `DEVSEC_CHAT_FAKE_TRANSPORT` is the only test hook. It builds `tests`-free `ScriptedTransport`-like replies from a JSON file, implemented in `rpc.py` as `_FileTransport`. Mark it `# ponytail: test-only transport, remove if a recorded-HTTP fixture replaces it`.
  - The GateKeeper is built with `bridge_asker` and `person="tui"`.
- [ ] **Step 4: Run the tests to confirm they pass.** Then run the G3 commands.
- [ ] **Step 5: Update AGENTS T2** (add `models`, `ready`, `gate_result` and the `model_*` commands, and name the protocol). Update the spec §4.1 events line. Commit.
  ```bash
  git commit -m "Serve harness sessions over the devsec-chat stdio protocol"
  ```

### Task 2b: Adding models, Hermes-style (keys belong to added models, not providers)

> **Independent:** this task is Python-only, apart from its later use in Task 6. It may ship first as its own PR (`feat/add-model`), because the experiment plan (`2026-11-02-experiment.md`) needs it before the rest of project 2.

**Files:**
- Create: `src/vulnscan/harness/models.py`
- Modify: `src/vulnscan/cli/main.py` (a new Python-handled command group `model`, added to the set in `main()` next to `chat`; `chat --model <alias>[:<id>]`; `--provider` kept as a deprecated alias for one release)
- Modify: `src/vulnscan/harness/rpc.py` (`models` event; `model_add`, `model_remove` and `model_key` commands; `start.model`)
- Modify: `src/vulnscan/harness/console.py` (`/model` lists added models; `/model add` runs the same wizard as the CLI)
- Test: `tests/harness/test_models.py`, `tests/cli/test_model_cli.py`

**Interfaces:**
- Consumes:
  - `BUILTIN_PROFILES` as the **templates**, with no new vendor table (A3);
  - `providers.profile_store` for `.providers/<alias>.json`;
  - `infra/envfile.EnvFile` for the key;
  - `is_local_base_url` from project 1 (`core/model_consent.py`).
- Produces:
  ```python
  @dataclass(frozen=True)
  class ModelEntry: alias: str; protocol: str; base_url: str; models: list[str]; default_model: str; local: bool; key_set: bool
  def add_model(alias: str, template: str | None, protocol: str, base_url: str, models: list[str], key: str | None,
                *, store: Path = Path(".providers"), env: EnvFile | None = None) -> ModelEntry
  def remove_model(alias: str, *, store: Path = Path(".providers"), env: EnvFile | None = None) -> None
  def set_key(alias: str, key: str, *, store: Path = Path(".providers"), env: EnvFile | None = None) -> None
  def list_models(*, store: Path = Path(".providers")) -> list[ModelEntry]
  def resolve_model(spec: str) -> tuple[ProviderProfile, str]   # "alias" or "alias:model-id"
  def models_event(entries: list[ModelEntry]) -> dict           # spec §2.3 `models`
  ```
   - The alias must match `^[a-z0-9-]{1,32}$`.
   - Owner-approved wire correction (2026-11-02): `model_add` uses `model_protocol` for the API protocol; top-level `protocol` remains `devsec-chat/1`. The Python `add_model(..., protocol=...)` API is unchanged. The `models` event also carries public `templates` metadata from the built-in profile table for client form prefills.
  - `api_key_env` is generated as `DEVSEC_KEY_` plus the upper-case alias with `-` replaced by `_`.
  - A key is required unless `is_local_base_url(base_url)` is true.
  - Neither the key nor the variable name ever appears in a return value, an event, a log line or an error message.
- CLI:
  - `devsec model add [--template deepseek]` runs the interactive wizard: template or Custom, then base URL (pre-filled), then model ids, then the key (masked with `getpass`; Enter skips for a local URL).
  - `devsec model list` prints `alias:model · local|cloud · key set|missing`.
  - `devsec model remove <alias>` and `devsec model key <alias>`.

- [ ] **Step 1: Write the failing tests.**
  ```python
  def test_add_cloud_model_stores_key_in_env_not_profile(tmp_path): ...
      # The profile JSON contains no key value. The .env holds DEVSEC_KEY_MY_DEEPSEEK.
      # The returned ModelEntry has key_set True.
  def test_cloud_model_without_key_is_refused(tmp_path): ...
  def test_local_model_needs_no_key(tmp_path): ...                 # base_url http://127.0.0.1:11434/v1
  def test_models_event_has_no_key_values_or_env_names(tmp_path): ...
      # json.dumps(models_event(...)) contains neither the key nor "DEVSEC_KEY_".
  def test_resolve_alias_and_alias_colon_model(tmp_path): ...
  def test_template_only_prefills(tmp_path): ...                   # the custom base_url wins over the template's
  def test_remove_deletes_profile_and_env_entry(tmp_path): ...
  def test_bad_alias_rejected(tmp_path): ...
  def test_legacy_provider_flag_still_works(tmp_path, monkeypatch): ...  # --provider ollama
  ```
  CLI: `test_model_add_wizard_masks_key`, using a scripted stdin; the captured output must not contain the key.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_models.py tests/cli/test_model_cli.py -q`
  Expected: FAIL.
- [ ] **Step 3: Implement.** Then run the G3 commands. Expected: all pass. `ci/smoke_installed.py` still works, through the legacy `--provider ollama`.
- [ ] **Step 4: Update the docs.**
  - README and BUILD-AND-RUN: the chat section shows `devsec model add` and `devsec chat --model <alias>`. The `env set DEEPSEEK_API_KEY` example is removed from the chat section.
  - AGENTS K2 and T7 (spec §6).
  - Spec §4.1: profiles are added models, and built-ins are templates.
  - CHANGELOG.
  Commit:
  ```bash
  git commit -m "Add models like Hermes with keys owned by each added model"
  ```

### Task 3: Go ChatSession (never drops events)

**Files:**
- Create: `internal/bridge/chat.go`, `internal/bridge/chat_test.go`

**Interfaces:**
- Produces:
  ```go
  type ChatEvent struct { Type string `json:"type"`; Seq int `json:"seq"`; Raw json.RawMessage `json:"-"` }
  type ChatMessage map[string]any
  func StartChat(python string, env []string) (*ChatSession, error)
  func (s *ChatSession) Events() <-chan ChatEvent
  func (s *ChatSession) Send(m ChatMessage) error
  func (s *ChatSession) Close()
  func (s *ChatSession) Err() error
  ```
  - `Send` adds `"protocol":"devsec-chat/1"`.
  - `Events` is fed by a reader goroutine through an internal slice queue, so it never drops anything.
  - After stdout ends, the channel closes and `Err()` is non-nil.
  - The module is `vulnscan.harness.rpc`. `DEVSECOPS_CHAT_MODULE` overrides it for tests, like `DEVSECOPS_RPC_MODULE`.

- [ ] **Step 1: Write the failing tests.** Use the Go helper-process pattern: the test binary re-executes itself as a fake host when `GO_CHAT_HELPER=1`.
  - `TestEventsNeverDropUnderBurst`: the helper writes 10,000 events, and the test receives all of them in order (by `seq`) while reading slowly.
  - `TestSendAddsProtocol`: the helper echoes the received line, and the test asserts it contains `"protocol":"devsec-chat/1"`.
  - `TestBrokenPipeClosesEventsWithError`: the helper exits after 3 events; the channel closes and `Err() != nil`.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `go test ./internal/bridge/ -run Chat`
  Expected: FAIL (undefined: StartChat).
- [ ] **Step 3: Implement `chat.go`.** Reuse `process.Configure` and the 8 MiB scanner buffer from `client.go`.
- [ ] **Step 4: Run the tests to confirm they pass.** Then run `go vet ./...` and `go test ./...`.
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Add a chat bridge session that never drops harness events"
  ```

### Task 4: Chat view (transcript, input, status line, hint bar, tabs, command menu)

**Files:**
- Create: `internal/chat/model.go`, `internal/chat/transcript.go`, `internal/chat/hints.go`, `internal/chat/menu.go`, `internal/chat/view.go`
- Test: `internal/chat/model_test.go`, `internal/chat/view_test.go`

**Interfaces:**
- Consumes: Task 3 `ChatSession` through a narrow interface, so tests can inject a fake:
  ```go
  type Host interface { Events() <-chan bridge.ChatEvent; Send(bridge.ChatMessage) error; Err() error; Close() }
  func New(host Host, baseline tea.Model) Model   // baseline = existing tui.Model (Task 7)
  ```
- Produces:
  - `Model` with fields `screen` (`startScreen|chatScreen`) and `tab` (`tabChat|tabBaseline|tabKeys`).
  - `func (m Model) Hints() []string`, the visible hint-bar entries for the current state. Tests assert on it.
  - Commands in the `/` menu: `model`, `mode`, `cost`, `review`, `export`, `resume`, `clear`, `baseline`, `keys`, `help`, `quit`. Each has a one-line description.
  - Transcript role labels (spec D10): `you ›` and `AI hỗ trợ ›` (AI support). Findings show as `đề xuất` (proposal) until G5. The UI never calls the model the scanner.

- [ ] **Step 1: Write the failing tests.**
  - `TestHintsPerState`:
    - typing: `["Enter send", "/ commands", "Esc stop", "? help"]`;
    - turn running: `["Esc stop", "? help"]`.
  - `TestSlashOpensFilterableMenu`: typing `/mo` shows exactly `model` and `mode`; Enter runs the highlighted one.
  - `TestToolBlocksCollapseAndExpandByClick`: a mouse click on a block's row toggles it.
  - `TestTabsClickable`: a click on "Baseline" sets `tab == tabBaseline`; Esc returns to Chat.
  - `TestBrokenPipeLeavesGateUndecided`:
    - the fake host's `Events` closes while a dialog is open;
    - the dialog closes, input is disabled, and the hints include `r restart`;
    - no `permission_reply` was sent.
  - `TestLayouts`: golden `View()` output at 80x24 and 75x26; at 59x17 the view is the resize message.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `go test ./internal/chat/`
  Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Turn mouse on through the v2 `tea.View` mouse mode (cell motion).
  - The status line shows `alias:model · local|cloud · mode · tokens · $cost` from the `ready` and `usage` events.
- [ ] **Step 4: Run the tests to confirm they pass.** Then run `go vet ./...` and `go test ./...`.
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Add the chat view with hint bar, command menu, tabs and mouse"
  ```

### Task 5: Permission dialog and G6 diff viewer

**Files:**
- Create: `internal/chat/dialog.go`, `internal/chat/diff.go`
- Test: `internal/chat/dialog_test.go`
- Modify: `AGENTS.md` (T4), `tests/harness/test_gates.py` (add a doc-sync assertion; see Step 4)

**Interfaces:**
- Consumes: `permission_request` events (spec §2.3).
- Produces: `dialog` with `highlight int`, which is `-1` when nothing is highlighted, and `diffSeenEnd bool`. A decision is sent as `{"type":"permission_reply","request_id","choice","reason","edits"}`.
- Button tables, which must match `gates.CHOICES`:
  - G0: `y` approve, `n` reject;
  - G1–G4 and G7: `y` approve, `e` edit, `n` reject;
  - G5: `c` confirm, `r` reject, `m` need_more;
  - G6: `a` apply, `r` reject, `d` defer.

- [ ] **Step 1: Write the failing tests.**
  - `TestEnterWithoutHighlightNeverAnswers`, for every gate: Enter sends nothing and the dialog stays open.
  - `TestArrowThenEnterAnswers`: Right then Enter on G3 sends `approve`. Left from `-1` goes to the last button.
  - `TestLetterAndClickAnswer`: `n` and a click on `[ n Reject… ]` both open the reason box. Esc in the reason box returns to the dialog without sending.
  - `TestEscAndFocusLossLeaveUndecided`: Esc closes the dialog, sends nothing, and the transcript shows `G3 left undecided`.
  - `TestDangerousMarked`: the views for G0 and G6 contain `DANGEROUS`. G3's view does not.
  - `TestG6ButtonsUnlockOnlyAtDiffEnd`:
    - with a 2,000-line diff at 80x24, `a` does nothing before the end;
    - after End, or after scrolling to the last line, `a` sends `apply`;
    - the hint shows `scroll to the end of the diff` until then.
  - `TestEditSendsJSONObjectOnly`: `e` opens a JSON box. Invalid JSON shows an inline error and sends nothing.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `go test ./internal/chat/ -run 'Dialog|Enter|Arrow|Letter|Esc|Dangerous|G6|Edit'`
  Expected: FAIL.
- [ ] **Step 3: Implement the dialog and the diff viewer.**
- [ ] **Step 4: Update AGENTS T4** with the text from spec §6. In `tests/harness/test_gates.py`, add `test_tui_button_table_matches_choices`. It parses the button table from `internal/chat/dialog.go`, which is kept as a literal `var buttonTable = ...` block, and asserts it equals `CHOICES`.
- [ ] **Step 5: Run the G3 commands and the Go tests.** Commit.
  ```bash
  git commit -m "Add the permission dialog with visible keys, arrows and a gated diff viewer"
  ```

### Task 6: Start screen

**Files:**
- Create: `internal/chat/start.go`
- Test: `internal/chat/start_test.go`

**Interfaces:**
- Consumes:
  - `models` events and the `model_add`, `model_key` and `model_remove` commands from Task 2b.
- Produces:
  - Start sends `{"type":"start","target","model":"alias[:id]","mode"}`.
  - The field order is target, model (a list of added models, `alias:model · local|cloud · key set|missing`), mode (`ask`/`auto`), then the [ Start session ] button.
  - A **＋ Add model** button opens a form with these fields: name, template (a list plus Custom), protocol, base URL, model ids, key (masked). Submitting it sends `model_add`.
  - The Keys tab lists the added models, each with **Set key** and **Remove** buttons.

- [ ] **Step 1: Write the failing tests.**
  - `TestStartScreenShowsKeyStatusNeverValue`: a cloud model with `key_set:false` shows `my-deepseek · key missing` and a `[ Set key ]` button. `View()` contains no key value and no `DEVSEC_KEY_`.
  - `TestAddModelFormMasksKeyAndSendsModelAdd`: the key field renders as `•••`. Submitting it sends one `model_add`, and the key never appears in `View()`.
  - `TestEmptyModelListShowsAddModelFirst`: with no models added, the start screen focuses the **＋ Add model** button and Start is disabled.
  - `TestStartDisabledUntilTargetAndKeyOK`: the Start button is greyed out, with the reason shown inline.
  - `TestModelListMarksLocal`: models whose base URL is on loopback show `local`.
  - `TestStartSendsStartMessage`: clicking Start sends exactly the start message.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Add the chat start screen with added models and an add-model form"
  ```

### Task 7: Baseline tab and comparison

**Files:**
- Modify: `internal/tui/app.go` (export `func NewEmbedded(api API) Model`, which hides the top tab bar because the chat model owns the tabs)
- Create: `internal/chat/baseline.go`, `internal/chat/compare.go`
- Test: `internal/chat/compare_test.go`, `internal/chat/baseline_test.go`

**Interfaces:**
- Produces:
  - `func Compare(harness []Finding, baseline []Finding) Comparison`, where `Finding{File string; CWE string}` and `Comparison{HarnessOnly, BaselineOnly, Both []Finding}`. The match key is `(path.Clean(File), CWE)`.
  - The harness findings come from the host command `findings`, which returns proposed findings and their status only. The baseline findings come from the existing `service.Backend.Findings`.

- [ ] **Step 1: Write the failing tests.**
  - `TestCompareCountsByFileAndCWE`: the inputs overlap on 2 of 5. The result is `Both` 2, `HarnessOnly` 1 and `BaselineOnly` 2.
  - `TestBaselineTabLabelledTestingOnly`: the view contains `Baseline comparison (testing only)` and the three buttons.
  - `TestBaselineResultsNeverSentToHost`: a recording fake host shows that opening and comparing sends no message containing baseline data.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Move baseline scans behind a testing-only tab with a session comparison"
  ```

### Task 8: Launch wiring

**Files:**
- Modify: `cmd/devsecops-agent/main.go` (`tui` builds `chat.New(bridge.StartChat(...), tui.NewEmbedded(backend))`)
- Modify: `src/vulnscan/cli/main.py` (`tui` always runs the Go binary. If it is missing, print `chat needs the native binary: run ci/build_native.py` and exit 2.)
- Test: `cmd/devsecops-agent/main_test.go`, `tests/cli/test_tui_launch.py`

- [ ] **Step 1: Write the failing tests.**
  - `test_tui_without_binary_exits_2_with_build_hint`.
  - `TestTuiStartsChatModel`: uses a fake chat module through `DEVSECOPS_CHAT_MODULE`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Open the chat client from devsec tui"
  ```

### Task 9: Remove the Python TUI

**Files:**
- Delete: `src/vulnscan/tui/`, `tests/tui/`
- Modify:
  - `pyproject.toml`: remove `textual` if nothing else imports it. Check with `git grep -n "import textual\|from textual"`.
  - `uv.lock` and the three `requirements*.lock` exports.
  - `ci/smoke_installed.py`: drop the `ScanApp` import.
  - `.github/workflows/checks.yml`: change `tests/platform tests/cli tests/tui` to `tests/platform tests/cli`.
  - `tests/platform/test_ci_contract.py`: the matching assertion.
- Modify: `AGENTS.md` (G4, T7 and the §4a title), `README.md`, `docs/BUILD-AND-RUN.md`, `CHANGELOG.md`, spec §12 phase 6.

- [ ] **Step 1: Update `test_ci_contract.py` first.** Its new expectations fail until the workflow changes. Run it to confirm it fails.
- [ ] **Step 2: Delete and edit.** Delete the package and the tests. Edit the workflow and the smoke script. Run `uv lock`, the three `uv export` commands and `ci/check_lock_exports.py`.
  Expected: `matches uv.lock` printed three times.
- [ ] **Step 3: Run everything.** Run the G3 commands, `go vet ./...`, `go test ./...` and `ci/package_smoke.py`. Expected: all pass.
- [ ] **Step 4: Update the docs.**
  - README and BUILD-AND-RUN: put the chat first. Move the baseline scan to a section labelled "Baseline scanners (testing and comparison only)".
  - AGENTS: G4 and T7 per spec §6.
  - Spec §12: mark phase 6 as "TUI done, dashboard session pages are project 3".
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Remove the Python TUI now that the Go chat client is the main interface"
  ```

### Task 10: Verify and open the PR

- [ ] **Step 1: Run everything and save the logs.** Run the G3 commands, `go vet ./...`, `go test ./...`, `ci/check_lock_exports.py`, `uv lock --check`, the web-ui `npm ci`, `lint`, `test` and `build`, and `ci/package_smoke.py`. Save the logs in `.tools/ci-logs/go-chat-tui/`.
- [ ] **Step 2: Run a manual check with a local or fake provider.** Start a session, answer G0, G3 and G6 with the keyboard, then with the mouse, then with arrows and Enter. Open `/baseline`. Record what was done in spec §13 as a manual check, with no invented numbers.
- [ ] **Step 3: Push and open the PR.** Push `feat/go-chat-tui` and open a PR to `main` with the verification table. Do not merge it.
