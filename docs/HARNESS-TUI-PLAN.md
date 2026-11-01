# Agent harness and chat TUI plan

> Superseded by `docs/ARCHITECTURE-MODIFICATION.md` for gates, tools and
> scanners. Sections 3 (chat experience) and 5 (provider layer) still apply.

Status: plan only, no code changed. Drafted 2026-10-28 on branch
`fix/native-tui-api-key-input` (agent 0.3.0).

Goal: turn DevSecOps-Agent into a conversational security agent in the style
of Claude Code. You type a request, the agent streams its answer, calls tools
(read code, run scans, inspect findings), asks permission before expensive
actions, and records every step so its behaviour can be measured.

## 1. Decisions

| # | Decision |
| --- | --- |
| 1 | The harness is written in Python. The TUI stays in Go (Bubble Tea) and talks to the harness over the existing bridge. |
| 2 | Chat becomes the default screen. The current views move behind slash commands: `/scan`, `/history`, `/findings`, `/keys`. |
| 3 | Both provider families, in the Hermes Agent pattern: native Anthropic (Messages API) and any OpenAI-compatible endpoint (OpenAI, OpenRouter, DeepSeek, Ollama, LM Studio, custom). `/model` switches between them. |
| 4 | v1 is read-only and scan-only. The agent can read and search code, run scans and propose verdicts. It cannot edit files or run arbitrary commands. |
| 5 | v1 records data and numbers from every session so later scope (edit tools, fix mode) is decided by evidence. |

## 2. What already exists

| Piece | Current state | Use in this plan |
| --- | --- | --- |
| Go TUI | Bubble Tea v2, Bubbles, Lip Gloss; five form-style views (`internal/tui`) | Base for the chat view |
| Go↔Python bridge | `internal/bridge` | Carries chat events as JSONL |
| Provider profile | `contracts/provider.py`: `protocol`, `base_url`, `api_key_env`, `models`, `default_model`, `timeout_seconds`, `max_retries`, `headers` | Already matches the Hermes pattern |
| Provider protocols | `ProviderProtocol` enum: `anthropic_messages`, `openai_chat_completions`, `openai_responses`, `openai_compatible` | Selects the transport |
| LLM client | `providers/client.py`: only `/chat/completions`, no streaming | Extended into the Chat Completions transport |
| Budget and redaction | `providers/budget.py` (`BudgetManager`), `providers/credentials.py` (`redact`) | Reused unchanged |
| Agent loop | `agent/loop.py`: one finding at a time, at most 5 tool rounds; not called anywhere outside tests | Starting point for the session loop |
| Agent tools | `agent/tools.py`: `inspect_code`, `lookup_route`, `get_evidence`, `check_coverage`, `propose_verification` | Generalised into the tool registry |
| Scanning | `ScanService`, SQLite scan history, reports | Backs the `run_scan` and findings tools |
| Evaluation | `evaluation/metrics.py`, `evaluation/calibration.py` | Turns recorded verdicts into numbers |

## 3. Target experience

```
╭─ DevSecOps-Agent ─ JVA-bookstore @ dd48d12 ─ mode: ask ──────────────────╮
│ > scan the bookstore and tell me what's actually exploitable             │
│                                                                          │
│ ● run_scan(profile=fast)                                     ✓ 41s       │
│   ⎿ 7 findings · semgrep 7 · gitleaks 0                                  │
│ ● read_file(src/main/java/dao/CartDAO.java:500-520)          ✓           │
│ ● Of the 5 SQL-injection hits, all build table-creation SQL from fixed   │
│   strings (not exploitable). The real issue is OTPUtil.java:18 …         │
│                                                                          │
│ ┌ Permission ───────────────────────────────────────────────────────┐    │
│ │ run_scan(profile=full) builds the target in Docker (~5 min)        │    │
│ │ [y] yes   [a] always this session   [n] no                         │    │
│ └────────────────────────────────────────────────────────────────────┘    │
├──────────────────────────────────────────────────────────────────────────┤
│ > _                                                                      │
╰ claude-sonnet-5-5 · 12.4k tokens · $0.04 · ? for shortcuts ──────────────╯
```

## 4. Architecture

```
┌──────────── Go TUI (Bubble Tea) ────────────┐        ┌──────────────── Python harness ────────────────┐
│ chat transcript · input · permission dialog │ JSONL  │ Session loop (streaming, cancel, budget)        │
│ status line · /slash commands · old views   │◄──────►│ Tool registry (read-only + run_scan)           │
└─────────────────────────────────────────────┘ bridge │ Provider layer:                                │
                                                       │   profile → protocol → transport               │
                                                       │     anthropic_messages  ─► Anthropic transport │
                                                       │     openai_* / compatible ─► Chat Completions  │
                                                       │ Telemetry recorder ──► SQLite + JSONL          │
                                                       │ ScanService · validator · evaluation/metrics   │
                                                       └────────────────────────────────────────────────┘
```

Events from the harness to the TUI: `text_delta`, `tool_call`,
`tool_result`, `permission_request`, `usage`, `error`, `done`.
Messages from the TUI to the harness: `user_message`, `permission_reply`,
`interrupt`, `command`.

The rule from the SRS stays in force: the AI only proposes. Findings come
from scanners, and AI conclusions go through the existing validator.

## 5. Provider layer (Hermes pattern)

Hermes Agent declares each provider once as a profile and routes calls by
`api_mode` to a transport. This plan follows the same split using the
existing `ProviderProfile` and `ProviderProtocol`.

**Profiles.** JSON files under `.providers/`, keys referenced by environment
variable name only. Built-in profiles:

| Profile | Protocol | Key |
| --- | --- | --- |
| `anthropic` | `anthropic_messages` | `ANTHROPIC_API_KEY` |
| `openai` | `openai_chat_completions` | `OPENAI_API_KEY` |
| `openrouter` | `openai_compatible` | `OPENROUTER_API_KEY` |
| `ollama` | `openai_compatible` | none (local) |
| `custom` | `openai_compatible` | user-supplied `base_url` and variable |

**Transports.** One interface, `stream(messages, tools) → events`:

- `AnthropicTransport`: Messages API, SSE streaming, `tool_use` and
  `tool_result` blocks, prompt caching on the system prompt and tool
  definitions.
- `ChatCompletionsTransport`: extends today's `client.py` with
  `stream=true` and assembles streamed tool-call fragments into whole calls.

**Shared message format.** One internal representation, converted to each
provider's format at the transport edge. Sessions, telemetry and the TUI
never depend on the provider.

**Shared behaviour.** `BudgetManager` limits, `redact` on everything that
leaves the provider boundary, a model price table for cost, retries with
backoff.

**Not taken from Hermes (YAGNI):** OAuth logins, provider plugins, key
rotation. Environment-variable keys cover v1.

## 6. Tools in v1

| Tool | Permission | Notes |
| --- | --- | --- |
| `read_file(path, lines)` | auto | Target checkout only; size-capped |
| `grep(pattern, glob)` | auto | Target checkout only |
| `glob(pattern)` | auto | Target checkout only |
| `list_findings(run, filter)` | auto | Scan history database |
| `get_finding(id)` | auto | Scan history database |
| `get_evidence(id)` | auto | Scan history database |
| `lookup_route(class)` | auto | From current `agent/tools.py` |
| `check_coverage(run)` | auto | From current `agent/tools.py` |
| `run_scan(profile)` | ask | `fast` about 1 min; `full` uses Docker, about 5 min |
| `propose_verdict(finding, status, severity, rationale, evidence)` | auto | Records a proposal only; the validator decides; nothing is applied |

No tool in v1 writes files or runs shell commands. Permission modes: `ask`
(default) and `auto-scan`. `accept-all` waits until edit tools exist.

## 7. Data and numbers

Stored in new SQLite tables beside the scan history, plus one JSONL
transcript per session.

| Level | Recorded |
| --- | --- |
| Turn | provider, model, input/output/cached tokens, cost (USD), time to first token, total time, stop reason |
| Tool call | name, redacted arguments, duration, result size, ok or error, permission asked, approved or denied |
| Session | turns, total cost, scans run, end state (completed, interrupted, budget limit, error) |
| Finding verdict | AI proposal (true positive, false positive, needs review; severity; confidence), cited evidence, validator outcome, human or ground-truth label when one exists |

Numbers produced:

- **Accuracy:** agreement of AI verdicts with the validator and with ground
  truth; precision and recall. Initial ground truth: the 7 labelled
  bookstore findings in `evidence/laya-labels/jva-bookstore` plus the 5
  access-control and disclosure issues found by running the app (see
  section 10).
- **Calibration:** stated confidence against observed accuracy, using
  `evaluation/calibration.py`.
- **Cost and speed:** cost per finding and per session, time to verdict,
  tool calls per verdict.
- **Provider comparison:** the same scan and prompt on Anthropic and on an
  OpenAI-compatible model, side by side.

Access: a `devsec stats` command and a Sessions page on the existing
dashboard (`serve`).

## 8. Phases

| # | Delivers | Done when | Estimate |
| --- | --- | --- | --- |
| 1. Provider layer | Both transports with streaming, built-in profiles, shared message format, cost tracking | The same 3-turn tool-using test passes on Anthropic and on an OpenAI-compatible provider, against recorded replies in CI and once live by hand | 4–5 days |
| 2. Headless harness | Session loop, read-only tools, permission requests as events, telemetry recorder, `devsec chat -p "…"` | `devsec chat -p "scan ./JVA-bookstore and triage the findings"` completes a session and writes complete telemetry | 4–5 days |
| 3. Chat TUI | Chat as default screen, streaming text, tool-call blocks, y/a/n permission dialog, status line (model, tokens, cost), Esc to interrupt, Ctrl+C twice to quit, ↑ for prompt history | Phase 2 behaviour works interactively; existing views open through slash commands | 1–1.5 weeks |
| 4. Sessions and commands | `/model`, `/cost`, `/resume`, `/clear`, `/compact`, `/export`, `/help`; `@file` mentions; `DEVSECOPS.md` project memory | After a restart, `/resume` continues a session with its costs intact | 1 week |
| 5. Measurement | `devsec stats`, dashboard Sessions page, evaluation runner, provider comparison report | One command produces the numbers table for Anthropic and an OpenAI-compatible model on JVA-bookstore | 4–5 days |
| Later | Edit tools and fix mode (diff, approval, re-scan), subagents per finding | Started only if phase 5 numbers justify it | — |

## 9. Risks

| Risk | Handling |
| --- | --- |
| Source code is sent to the AI provider | Consent prompt on first use per session; provider shown in the status line; Ollama available for code that must stay local |
| Prompt injection from the scanned code | Read-only tools in v1; file content marked as data, not instructions; verdicts must pass the validator |
| Runaway cost | `BudgetManager` per-session and overall limits; running cost always visible |
| Provider differences in tool-call format and streaming | Shared message format; recorded reply fixtures per transport in the test suite |

## 10. Initial evaluation cases

Found by running JVA-bookstore on 2026-10-25 and not reported by the full
scan (run `run-05eee3b7ad3641c78122e9f60db01b9e`, stored in
`evidence/instabox-fullscan/`):

| # | Issue | Location | CWE |
| --- | --- | --- | --- |
| 1 | Any logged-in customer can list all users | `web/admin/AdminUsersServlet.java` (`doGet`, no role check); `filters/JwtFilter.java` validates the token only | CWE-862 |
| 2 | Unauthenticated user wipe guarded by a hard-coded secret | `JwtFilter.isPublicEndpoint` lists `/api/admin/clear-users`; `web/AdminServlet.java` compares against `dev-secret-key-change-me` | CWE-306, CWE-798 |
| 3 | Admin dashboard statistics readable without login | `JwtFilter.isPublicEndpoint` allows GET `/api/admin/dashboard` | CWE-862 |
| 4 | OTP returned in the response when email sending fails | `web/AuthServlet.java` `handleSendOTP` (`debugOtp`) | CWE-200 |
| 5 | Shipper API reachable by customers (no data exposed) | `web/ShipperApiServlet.java` | CWE-862 |

These also show a gap against SRS Appendix B: CWE-798 and CWE-862/639 are
listed as supported, but `src/vulnscan/scanners/rules/java.yml` has no rule
for either.
