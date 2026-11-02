# Web remote control for harness sessions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the PIT WALL web UI attach to a running harness session, or start a headless one, and act as a second relay client. The web shows the transcript, sends messages and answers gates under the same rules as the TUI.

**Architecture:**
- The SessionHost process from project 2 is the single owner of the session. It can also serve a small FastAPI app on loopback: one-time token login, a cookie, CSRF, SSE events that replay from `seq`, and a POST for messages.
- Many clients can attach. The first valid gate reply wins.
- The React SPA gets a `/app/remote` page that mirrors the chat TUI.

**Tech Stack:** FastAPI, `sse-starlette` (owner-approved in project 1), uvicorn (already a dependency), React 18, TypeScript, Vitest (from `web-ui/`).

**Spec:** `docs/superpowers/specs/2026-11-01-chat-client-remote-triggers-design.md` Part B, §5, §6 and §7.

**Precondition:** project 2 (`2026-11-01-go-chat-tui.md`) has merged. Branch: `feat/web-remote`.

## Global Constraints

- AGENTS T1: the web only displays and relays. Every gate check runs in Python (`GateKeeper`, `bridge_asker` and `CHOICES`).
- Bind to `127.0.0.1` by default. Binding to any other address requires `--remote-allow-lan` and prints a warning. The host refuses `0.0.0.0` without the flag.
- Tokens: 32 bytes from `secrets.token_urlsafe(32)`, usable once, valid for 10 minutes. The cookie is `devsec_remote`, set with `HttpOnly; SameSite=Strict; Path=/`. CSRF uses the double-submit pattern from `web/app.py`.
- On the web, G0 and G6 need a typed confirmation word, `send` and `apply` respectively. The host checks it, not just the page.
- H7: `person` is `tui` or `web:<first 8 hex chars of sha256(client cookie)>`.
- K3: every SSE payload and every JSON response goes through `redact_value`.
- No new dependencies.

## Review Focus

1. **A phone on the same Wi-Fi opens the LAN address without `--remote-allow-lan`.** The connection is refused because the host only listens on loopback. Pinned in Task 3 by `test_non_loopback_bind_requires_flag`.
2. **The browser reconnects after sleeping.** SSE replays from the last `seq`, a pending gate dialog reappears, and no event is duplicated or lost. Pinned in Task 2 by `test_events_replay_after_seq` and in Task 5 by the Vitest `replays after reconnect`.
3. **The TUI and the web answer the same G3 at once.** Exactly one decision is logged, and the other client gets `already answered by …`. Pinned in Task 1 by `test_first_reply_wins`.
4. **A malicious page posts to the remote API from another origin.** It is rejected by SameSite plus CSRF. Pinned in Task 2 by `test_post_without_csrf_is_403`.
5. **A web user clicks Apply on G6 without typing `apply`.** The host treats it as undecided. Pinned in Task 1 by `test_dangerous_web_reply_needs_confirmation_word`.

---

### Task 1: Multi-client replies in SessionHost

**Files:**
- Modify: `src/vulnscan/harness/host.py`
- Test: `tests/harness/test_host_clients.py`

**Interfaces:**
- Consumes: project 2 `SessionHost` and `bridge_asker`.
- Produces:
  - `SessionHost.attach(client_id: str, kind: Literal["tui", "web"]) -> Callable[[], None]`. The returned function detaches.
  - `SessionHost.reply(client_id: str, message: dict) -> dict`. It returns `{"ok": True}` or `{"ok": False, "error": str}`.
  - `SessionHost.events_after(seq: int) -> list[dict]`. It replays from an in-memory list capped at 5,000 events. Older events are re-read from the session JSONL.
  - The confirmation word sits in `permission_reply.confirm`. It is required only when `kind == "web"` and the gate is in `DANGEROUS`. If it is missing or wrong, the reply becomes `undecided` with the reason `confirmation word missing`.

- [ ] **Step 1: Write the failing tests.**
  - `test_first_reply_wins`: two clients reply to one request. Exactly one gate record is logged. The second reply gets `{"ok": False, "error": "already answered by web:…"}` (or `tui`).
  - `test_dangerous_web_reply_needs_confirmation_word`: G6 `apply` from a web client without `confirm` is logged as `undecided`. With `confirm: "apply"`, it applies. From the TUI no `confirm` is needed.
  - `test_person_is_client_kind`: the logged person is `tui`, or `web:` followed by 8 hex characters.
  - `test_events_after_spans_memory_and_log`.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `.venv\Scripts\python.exe -m pytest tests/harness/test_host_clients.py -q`
  Expected: FAIL.
- [ ] **Step 3: Implement.** Then run the tests to confirm they pass, and run all of `tests/harness`.
- [ ] **Step 4: Commit.**
  ```bash
  git commit -m "Let several clients attach to one session with first-reply-wins gates"
  ```

### Task 2: Remote HTTP app

**Files:**
- Create: `src/vulnscan/harness/remote.py`
- Test: `tests/harness/test_remote.py`

**Interfaces:**
- Produces:
  - `create_remote_app(host: SessionHost, token: str, spa_dir: Path | None) -> FastAPI`, with the routes from spec §3.2.
  - `issue_token() -> str`.
  - `remote_url(port: int, token: str) -> str`, which returns `http://127.0.0.1:{port}/app/remote#t={token}`.

- [ ] **Step 1: Write the failing tests** (FastAPI `TestClient`).
  - `test_login_token_is_single_use_and_expires`: the first login returns 200 and sets the cookie. A second login returns 401. A token older than 10 minutes returns 401 (use an injected clock).
  - `test_post_without_csrf_is_403`.
  - `test_events_replay_after_seq`: post a message, then `GET /api/remote/events?after=3`. The SSE body holds `seq` values 4, 5 and so on, with no duplicates.
  - `test_state_contains_pending_request`.
  - `test_responses_are_redacted`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Commit.**
  ```bash
  git commit -m "Serve a token-protected remote API for harness sessions"
  ```

### Task 3: Turning remote on from the TUI, and headless `devsec remote`

**Files:**
- Modify: `src/vulnscan/harness/rpc.py` (command `remote` with `on`/`off`. It starts uvicorn in a thread on `127.0.0.1:0` and emits a new event `remote{url}`, or `remote{off}`.)
- Modify: `src/vulnscan/cli/main.py` (new command `remote` with the `chat` options, plus `--port`, `--remote-host` and `--remote-allow-lan`)
- Modify: `internal/chat/menu.go` (add `/remote`; show the URL in the transcript with a "copy" hint)
- Test: `tests/harness/test_remote_cli.py`, `internal/chat/model_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `test_non_loopback_bind_requires_flag`: `--remote-host 0.0.0.0` without the flag exits 2 with a message. With the flag, a warning line is printed.
  - `test_remote_on_emits_url_event`.
  - `test_headless_waits_without_client`: G0 stays pending until a client replies. Nothing is approved automatically.
  - Go `TestRemoteCommandShowsURL`.
- [ ] **Step 2: Run the tests to confirm they fail.** Then implement, and run them to confirm they pass.
- [ ] **Step 3: Update docs and rules.**
  - AGENTS: T7 gains `/remote`. Add the new rule T11 (spec §3.3).
  - T2 gains the event `remote`, with its test.
- [ ] **Step 4: Commit.**
  ```bash
  git commit -m "Add /remote and headless devsec remote with loopback-only defaults"
  ```

### Task 4: Serve the SPA from the host

**Files:**
- Modify: `src/vulnscan/harness/remote.py` (mount `spa_dir` at `/app` with an `index.html` fallback, the same logic as `web/app.py` `_spa_dir`)
- Test: `tests/harness/test_remote.py::test_spa_served_when_built`, which builds a fake dist folder in `tmp_path`

- [ ] **Step 1: Write the failing test.** Run it to confirm it fails. Then implement, and run it to confirm it passes.
- [ ] **Step 2: Commit.**
  ```bash
  git commit -m "Serve the built web UI from the session host"
  ```

### Task 5: RemoteSessionPage in the web UI

**Files:**
- Create:
  - `web-ui/src/pages/RemoteSessionPage.tsx`
  - `web-ui/src/components/remote/Transcript.tsx`
  - `web-ui/src/components/remote/GateDialog.tsx`
  - `web-ui/src/components/remote/CommandMenu.tsx`
  - `web-ui/src/api/remote.ts`
- Modify: the router (add the route `remote`), the i18n EN and VI dictionaries.
- Test: `web-ui/src/pages/RemoteSessionPage.test.tsx`, `web-ui/src/components/remote/GateDialog.test.tsx`

**Interfaces:**
- `remote.ts`:
  - `login(token: string): Promise<void>`;
  - `subscribe(after: number, onEvent: (e: RemoteEvent) => void): () => void`, an EventSource that reconnects with `after = lastSeq`;
  - `send(msg: RemoteMessage): Promise<{ok: boolean; error?: string}>`.
- The page reads `#t=` once, logs in, and then removes the fragment from the URL with `history.replaceState`.

- [ ] **Step 1: Write the failing Vitest tests.**
  - `replays after reconnect`: a mocked EventSource drops and reconnects, and the client requests `after=lastSeq`.
  - `G6 apply disabled until diff end and "apply" typed`.
  - `Enter with nothing highlighted does nothing` (the same rule as the TUI).
  - `shows "already answered by" and closes dialog`.
  - `removes token from URL after login`.
- [ ] **Step 2: Run the tests to confirm they fail.**
  Run: `npm test` in `web-ui/`.
  Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Reuse the existing component kit, focus ring and live regions.
  - Show hints in a footer, the same as the TUI.
- [ ] **Step 4: Run all the web-ui checks.** Run `npm test`, `npm run lint` and `npm run build`. Expected: all pass.
- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "Add the remote session page to the web UI"
  ```

### Task 6: Docs, verification and PR

- [ ] **Step 1: Update the docs.**
  - README and BUILD-AND-RUN get a section "Remote control from a browser": `/remote on`, `devsec remote`, the SSH tunnel example `ssh -L 8765:127.0.0.1:<port> user@host`, and the LAN flag warning.
  - CHANGELOG.
  - Spec §12, phase 6: the dashboard session pages are done through the remote page.
- [ ] **Step 2: Run everything.** Run the G3 commands, the Go tests, all the web-ui checks and `ci/package_smoke.py`. Save the logs to `.tools/ci-logs/web-remote/`.
- [ ] **Step 3: Push and open the PR.** Push `feat/web-remote` and open a PR to `main`. Do not merge it.
