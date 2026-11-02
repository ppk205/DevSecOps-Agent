# Chat client, web remote control and local triggers — design

Status: **design only, not implemented.** Written 2026-11-01. It covers projects 2–4 of the agreed order:

1. Stabilize and merge `main`. Plan: `docs/superpowers/plans/2026-11-01-stabilize-and-merge-main.md`.
2. **Go chat TUI.** This spec, Part A.
3. **Web remote control.** This spec, Part B.
4. **Local triggers.** This spec, Part C.

Each project gets its own plan and PR, and each starts only after the previous one has merged.

Parent documents:
- `docs/ARCHITECTURE-MODIFICATION.md`, the spec. This document implements decision D9 and phase 6.
- `AGENTS.md`, the rules. Section 6 lists every rule this design changes.

How decisions are labelled below:
- **[owner]**: the owner chose it in the 2026-11-01 conversation.
- **[default]**: the author's recommendation. The owner has not reviewed it yet. Change it here before the matching plan runs.

## 1. Goals

- **[owner]** The Go TUI becomes the main client, and it is chat-first.
- **[owner, 2026-11-02]** AI is a supporting tool (spec D10, AGENTS A5). The harness's static tools detect candidates. The model investigates, explains and proposes inside gated batches, and a human decides. The UI labels model output "AI hỗ trợ" (AI support) and every proposal "đề xuất" (proposal).
- **[owner]** The baseline tools (the nine tools in essay Table 2.2, of which four have adapters, plus CodeQL through SARIF) are for comparison and testing only. They sit behind one Baseline tab, and the model never sees their results.
- **[owner]** You can use the UI without remembering any key. Whatever works at a given moment is shown on screen.
- **[owner]** The Python TUI is removed once the Go chat client works.
- **[owner]** The teammate's PIT WALL web UI becomes a remote control for the same harness session.
- **[owner]** Reviews can be triggered locally, after a git commit or merge. Targets without git use a folder watcher.
- **[owner]** With a local model in auto mode, G0 is approved automatically.

Non-goals:
- token streaming (SSE): **[owner]** whole replies first;
- multi-user accounts;
- internet exposure by default;
- the AI merging or committing code;
- replacing `scan-run`.

## 2. Part A — session host, chat bridge and Go chat TUI (project 2)

### 2.1 Processes

```
devsec tui (Go) ──stdio JSONL "devsec-chat/1"──► python -m vulnscan.harness.rpc
   │                                               └ SessionHost → Session → tools/gates/Laya
   └── existing scan bridge (vulnscan.core.rpc, protocol v1) — Baseline tab only, unchanged
```

**[owner]** Approach A: a separate chat process. The scan RPC is untouched.

### 2.2 SessionHost (`src/vulnscan/harness/host.py`)

`SessionHost` owns one `Session` and turns everything that happens in it into numbered events.

- **Event source.** `SessionLog` gets listeners: `SessionLog.subscribe(fn) -> Callable[[], None]`. Each `append` calls the listeners after writing to disk.
- **Mapping log entries to events.** The host maps log entries to events:
  - assistant text → `text_delta`;
  - assistant tool calls → `tool_call`;
  - a `tool` message → `tool_result`;
  - `usage` → `usage`;
  - a GateKeeper record → `gate_result`.
- **Turns.** Turns run on one worker thread. A `user_message` that arrives while a turn is running gets an `error` event ("a turn is already running") and is dropped. It is never queued silently.
- **Interrupt.** `Session.cancel()` sets a flag. `Session.send` checks it before each provider call and before each tool run, then ends the turn with `done{reason:"interrupted"}`. A provider call already in flight finishes, and its reply is discarded. Interrupting never approves anything.
- **Event numbers.** Every event carries a sequence number `seq` that increases by 1 per session. Clients can replay from a given `seq` (Part B needs this).

### 2.3 Protocol `devsec-chat/1`

The protocol is one JSON object per line. A line is at most 8 MiB, the same limit as `internal/bridge`. Every line has `"protocol":"devsec-chat/1"`.

**Client → host:**

| type | fields |
|---|---|
| `hello` | — (the host answers with `models`) |
| `start` | `target`, `model` (`alias[:model-id]`), `mode` |
| `model_add` / `model_remove` / `model_key` | see §2.5b |
| `user_message` | `text` |
| `permission_reply` | `request_id`, `choice`, `reason`, `edits` |
| `interrupt` | — |
| `command` | `name`, `args` (the slash commands of T7) |

**Host → client:**

| type | fields |
|---|---|
| `models` | `items:[{alias, protocol, base_url, models, default_model, local, key_set}]` (no key values and no variable names, §2.5b) |
| `ready` | `target`, `commit`, `dirty`, `provider`, `model`, `mode`, `local` |
| `text_delta` | `text` (a whole reply for now) |
| `tool_call` | `id`, `name`, `arguments` |
| `tool_result` | `id`, `name`, `summary`, `result` |
| `permission_request` | `request_id`, `gate`, `title`, `detail`, `payload`, `ai_recommendation`, `mode`, `dangerous`, `choices` |
| `gate_result` | `request_id`, `gate`, `choice`, `person` |
| `usage` | `input_tokens`, `output_tokens`, `cost_usd`, `total_tokens`, `total_cost_usd` |
| `error` | `message` |
| `done` | `reason`: `completed` \| `interrupted` \| `failed` |

`models`, `ready` and `gate_result` are new compared with spec §4.1. AGENTS T2 is updated to list them, each with a harness test.

### 2.4 bridge_asker

`bridge_asker(emit, replies) -> Asker` sends a `permission_request` with a new uuid4 `request_id`, then blocks until the `permission_reply` with that id arrives. The reply becomes `GateDecision(gate, "undecided", reason)` instead of an approval when:
- the choice is not in `CHOICES[gate]`;
- the edits are not a JSON object;
- stdin closes;
- the host shuts down;
- an exception occurs.

There is no timeout while a client is attached; the gate waits for a human. On exit, any pending request becomes undecided. Rules H5 and T8 stay in force.

### 2.5 Go side

- **Chat bridge.** `internal/bridge/chat.go` provides `ChatSession`:
  - `StartChat(python string) (*ChatSession, error)`;
  - `Events() <-chan ChatEvent`, backed by an unbounded queue owned by one goroutine, so it **never drops** an event. This differs from the scan bridge, which drops events when full.
  - `Send(ChatMessage) error`;
  - `Close()`.
- **Chat UI.** A new package `internal/chat` holds the chat UI. The existing `internal/tui` scan model becomes the Baseline tab, embedded and called when that tab is active.
- **Screens and widgets.**
  - **[owner]** a start screen form;
  - **[owner]** a chat view (transcript, input, status line);
  - **[owner]** clickable tabs: Chat · Baseline · Keys;
  - **[owner]** a context hint bar;
  - **[owner]** a `/` command menu with descriptions and filtering;
  - **[owner]** `?` help;
  - **[owner]** mouse support everywhere.
- **Permission dialog.**
  - **[owner]** It shows everything rule T3 requires. Its buttons spell out their key (`[ y  Approve ]`).
  - G0 and G6 are red and labelled DANGEROUS.
  - The G6 buttons are disabled until the diff has been scrolled to its end (T5).
  - **[owner, AGENTS T4 change]** Answers can be given by letter, by click, or with arrows and Enter. The highlight starts on **no** button. Enter with nothing highlighted does nothing. Esc, losing focus or closing the dialog leaves the gate undecided.
- **Baseline tab.** **[owner]** It shows "Baseline comparison (testing only)" with the buttons Run baseline scan · Compare with this session · History.
  - The comparison runs **in Go** (`internal/chat/compare.go`). It matches the session's proposed findings with baseline findings by (file, CWE), and the counts are harness-only, baseline-only and both.
  - These are counts, not precision or recall. Precision and recall need the labelled ground truth from spec §8.
  - Doing this in Go keeps the harness from reading scanner results (A4).
- **Launch.**
  - `devsec tui` runs the Go binary in chat mode.
  - If the binary is missing, it prints how to build it and exits with code 2.
  - **[owner]** The Python TUI is removed in the last task of project 2.
  - **[default]** The wheel does not ship the Go binary. pip users get `devsec chat` (the console) and the web remote.

### 2.5b Adding models (Hermes pattern) — **[owner, 2026-11-02]**

API keys belong to the **model the user added**, not to a provider. The user never types or sees an environment-variable name.

- **One flow, three places:** `devsec model add` (CLI wizard), `/model add` (console and TUI), and the **＋ Add model** button on the start screen and the Keys tab.
- **The wizard asks for:**
  1. a name (alias): `[a-z0-9-]{1,32}`, for example `my-deepseek`, `local-qwen`;
  2. a template: one of the built-in profiles (Anthropic, OpenAI, OpenRouter, DeepSeek, Ollama, LM Studio) or **Custom**. A template only pre-fills the protocol and base URL; it is not a separate code path (AGENTS A3);
  3. the protocol: `openai_compatible` or `anthropic_messages`;
  4. the base URL;
  5. the model id or ids;
  6. the API key, masked (T10). The key may be left empty when the base URL is local.
- **Storage:**
  - The profile goes to `.providers/<alias>.json` (the existing `profile_store` format), with `api_key_env` generated as `DEVSEC_KEY_<ALIAS>`.
  - The key value goes to the project `.env` through the existing `EnvFile` (K1/K2: stored by variable name, never printed).
  - The user sees only "key: set / missing".
- **Local vs cloud is decided by the base URL**, through `is_local_base_url` (loopback hosts only), not by the provider's name. G0 applies to every non-local model.
- **Using and managing models:**
  - Choose a model with `--model <alias>[:<model-id>]` on `chat`, `remote` and the experiment runners. In-session, use `/model <alias>[:<model-id>]`.
  - `/model` with no argument lists the added models as `alias:model · local|cloud · key set|missing`.
  - `devsec model list|remove <alias>|key <alias>` manage entries. `key` replaces the key, masked.
- **Backward compatibility:** `--provider` keeps working for one release, mapped to the template of the same name, and existing key variables such as `DEEPSEEK_API_KEY` are still read if set. **[default]** The docs show only the add-model flow.
- **Protocol changes (§2.3):**
  - The `profiles` event becomes `models{items:[{alias, protocol, base_url, models, default_model, local, key_set}]}`. No `key_env` field is sent to clients.
  - New client commands: `model_add{alias, template, protocol, base_url, models, key}`, `model_remove{alias}` and `model_key{alias, key}`.
  - The key travels only over the local stdio pipe (or the authenticated remote POST in Part B). It is never written to the session log, and `redact_value` runs on every event.

### 2.6 Layout

The layout works at 80x24 and 75x26 and shows a resize message below 60x18 (rule T9). The hint bar drops entries from the right when space runs out, and it always keeps `? help`.

## 3. Part B — web remote control (project 3)

### 3.1 Where the session lives

The session lives in one process: the SessionHost process from Part A.
- **Remote mode.** The host can also serve HTTP. A TUI user turns it on with `/remote on`.
- **Headless mode.** `devsec remote --target … --model <alias>[:<id>] --mode …` runs the host without a TUI. Its start form is on the web page.

Both modes produce a single session that serves events to every attached client. No session state is shared across processes.

### 3.2 Endpoints

Endpoints are served by `vulnscan.harness.remote`, a FastAPI app inside the host process:

| method | path | purpose |
|---|---|---|
| POST | `/api/remote/login` | swap the one-time token for a session cookie |
| GET | `/api/remote/state` | `ready` info, pending request, totals |
| GET | `/api/remote/events?after=<seq>` | SSE stream that replays from `seq`, then streams live (uses the approved `sse-starlette`) |
| POST | `/api/remote/messages` | the same client → host messages as §2.3 |
| GET | `/app/remote` | the built PIT WALL SPA (`web-ui/dist`) |

### 3.3 Security

- **Binding.**
  - **[default]** The server binds to `127.0.0.1` on a random free port.
  - Binding to a non-loopback address needs `--remote-allow-lan`, and the server prints a warning.
  - For phone access, the docs recommend an SSH tunnel or a VPN (Tailscale or similar) over LAN binding.
- **Login.**
  - **[default]** `/remote on` prints a URL with a 32-byte random token in the fragment: `http://127.0.0.1:PORT/app/remote#t=…`. The token is valid once, for 10 minutes.
  - Login returns an `HttpOnly; SameSite=Strict` cookie.
  - Every POST needs a CSRF token, using the double-submit pattern already in `web/app.py`.
- **Dangerous gates.**
  - **[default]** On the web, G0 and G6 need the button *and* a typed confirmation word: `send` for G0, `apply` for G6.
  - The word is checked by the host, not just by the page.
- **Recording who decided.**
  - **[default]** Rule H7 records `person` as `tui` or `web:<8-char client id>`.
  - The first valid reply to a request wins. Other clients receive `gate_result`, and their dialog closes.
- **Secrets.** Rule K3 applies to every SSE event and every response.
- **Non-interactive runs.** Rule H6 is kept: a headless host with no attached client waits, and nothing is approved automatically except what H2 and the Part C rule allow.

### 3.4 Web UI

- A new route `/app/remote` (`RemoteSessionPage`) mirrors the TUI: transcript, input, dialog, status line, `/` menu and visible hints.
- It reuses the existing component kit and i18n (EN/VI).
- Gate dialogs follow the same rules as the TUI, plus the typed confirmation for G0 and G6.

## 4. Part C — local triggers and local G0 auto (project 4)

### 4.1 Local G0 auto (AGENTS H3 change)

- **[owner]** `GateKeeper` approves G0 automatically, recorded with person `auto`, only when all three hold:
  1. the mode is `auto`;
  2. `payload["local"] is True` and `payload["code_leaves_machine"] is False`;
  3. the keeper is **interactive**: a new constructor flag `interactive: bool`, true only for the TUI, the web and the console asker.
- **[default]** Condition 3 keeps H6 intact: `devsec chat -p` from a pipe, CI and hooks never pass G0, even for local models.
- G6 is never automatic, and neither is G5.

### 4.2 Git hooks

- **Commands.** `devsec hooks install|uninstall|status --target PATH` writes `.git/hooks/post-commit` and `.git/hooks/post-merge`. Each hook starts with the marker `# devsec-hook v1`.
- **Existing hooks.** If a hook already exists without the marker, install refuses, prints the line to add, and exits 1. Uninstall removes only hooks that carry the marker.
- **What the hook runs.** The hook body runs `"<absolute python>" -m vulnscan.harness.pending record --hook <name> || true`. It never blocks git.
- **What `record` writes.** `record` appends one JSON line to `.git/devsec/pending.jsonl`: `{id, source:"post-commit"|"post-merge", commit, branch, files, at}`. The changed files come from `git diff-tree --no-commit-id --name-only -r HEAD`, or for a merge from `git diff --name-only ORIG_HEAD HEAD`. These are fixed git argument lists, and rule S1 is updated to list `harness/pending.py`.

### 4.3 Folder watcher (non-git targets)

- **[owner]** The watcher runs inside the host only while a session is open, so no daemon is involved.
- **[default]** It polls every 5 s using `Workspace.files()` (which applies credential exclusion), keyed by relative path to `(mtime_ns, size)`.
- It ignores `.devsec/`, `.git/`, `target/`, `build/`, `out/` and `node_modules/`.
- After 10 s with no changes, it queues one pending review into `.devsec/pending/<sha1(target)[:12]>.jsonl` in the harness working directory. That directory is not the target, so the target stays clean.

### 4.4 Pending reviews in clients

- **Start screen.** It lists pending reviews.
- **During a session.** A banner shows: `New commit abc123 · 5 files — [r] Review now  [x] Dismiss`.
- **Auto-start.** **[default]** In auto mode with a local provider and no turn running, the host submits the review prompt itself: `PENDING_PROMPT = "Review the changes in {ref}: {files}. Start with propose_scan_plan limited to these files."`. In every other case it waits for the human.

### 4.5 Targets without git

- **[owner]** The target opens as `unversioned`.
- After G6 approval, `apply_fix` writes `.devsec/patches/<finding_id>.patch` in the harness working directory instead of creating a worktree. The G6 dialog title says "Export patch (target is not a git repository)".
- `rescan` returns `unavailable: target is not a git repository`.

## 5. Error handling (all parts)

| Situation | Behavior |
|---|---|
| Harness process dies | TUI shows `error`; pending gate is undecided; input disabled; `[r] Restart session` button resumes from the session JSONL (`--resume`) |
| Malformed line from either side | Host: `error` event, line ignored. Go: session marked broken, user told, gate undecided |
| Provider error / budget | Existing `Session._fail` path → `error` + `done{failed}` |
| Two clients answer one gate | First valid reply wins; second gets `error{"already answered by <person>"}` |
| Web login token reused/expired | 401, page shows "ask the TUI for a new link (`/remote on`)" |
| Hook cannot write pending file | Hook prints one stderr line, exits 0 (git is never blocked) |

## 6. AGENTS.md and spec changes made by these projects

Each change below goes in the same change as its tests (H9, D1):
- **G4:** "Keep `scan-run`, `serve`, the Python TUI and the Go TUI working" becomes "Keep `scan-run`, `serve`, the Go TUI and the web remote working" (project 2 removes the Python TUI).
- **K2:** keys are added per model through the add-model flow (§2.5b). Profiles still store only a generated `api_key_env`, and the key value lives in `.env`.
- **T2:** add `models`, `ready`, `gate_result` and the `model_*` commands. Name the protocol `devsec-chat/1` on its own stdio pipe, not `internal/bridge` v1.
- **T4:** add arrows and Enter as an answer method, with the highlight starting on no button. Enter, Esc, timeout and focus loss without a highlighted button still never approve.
- **T7:** `/scan`, `/history` and `/findings` become `/baseline`; `/keys` stays and lists added models with their key status; `/model add` is added; add `/remote`.
- **New T11:** web remote rules (§3.3).
- **H3:** the local G0 auto exception (§4.1).
- **S1:** add `harness/pending.py` git calls with fixed argument lists.
- **Spec §12 phase 6:** mark the delivered parts.

## 7. Testing

- **Python:**
  - SessionHost event mapping, ordering and replay;
  - interrupts;
  - the bridge_asker undecided paths (each condition in §2.4);
  - the protocol round trip through real pipes;
  - remote auth, CSRF, replay and first-reply-wins;
  - typed confirmation enforced by the host;
  - local G0 auto in all 8 combinations of mode × local × interactive;
  - hooks install, refuse and uninstall on a temporary git repo;
  - the watcher debounce, using an injected clock;
  - `.patch` export for unversioned targets.
- **Go:**
  - ChatSession never drops events (10,000-event burst) and reports a broken pipe;
  - the dialog key, mouse and arrow tables, including Enter with no highlight giving no decision;
  - G6 disabled until the end of the diff;
  - hint-bar contents per state;
  - layouts at 80x24, 75x26 and 59x17 (golden view tests);
  - the comparison counts.
- **Web:** Vitest for RemoteSessionPage (dialog, typed confirmation, replay after reconnect).
- **CI:** the existing jobs and the `web-ui` job from project 1 cover all of this. No live model calls.
