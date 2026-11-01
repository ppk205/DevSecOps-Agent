# WEBUI-NOTES — PIT WALL investigation (Step 0)

Date: 2026-11-01. Author: Hermes Agent (Step 0 of SUPER-PROMPT).

## Discovered API surface (real, in `src/vulnscan/web/app.py`)

| Method | Path | Notes |
|---|---|---|
| GET | `/` | Jinja `targets.html` (legacy, keep) |
| POST | `/scans` | form: target_repository_url, target_commit_sha, repository_checkout_path |
| GET | `/runs/{id}` | Jinja `runs.html` — now BMW corporate light + live polling |
| GET | `/runs/{id}/findings` | Jinja findings + filter chips; paged variant when `?query` |
| GET | `/runs/{id}/findings/{fid}` | evidence drawer (legacy keep) |
| GET | `/findings/{fid}` | evidence detail (legacy keep) |
| POST | `/findings/{fid}/status` | CSRF-protected human review |
| GET | `/runs/{id}/export/{fmt}` | fmt ∈ json/sarif/html/markdown/txt/docx; Content-Disposition attachment |
| GET | `/runs/{id}/report` | final-report.md download (added 2026-11) |
| GET | `/api/runs/{id}` | `{run_id,status,gate,counts,stages[],reports{}}` (extended 2026-11) |

DB models (`src/vulnscan/storage/models.py`): `RunORM` (status, scan_spec_json,
result_json incl. routing/assessments/validation_decisions/comparison/reports),
`StageORM` (ordinal, name, status, started/completed_at, error_message),
`FindingORM` (finding_json blob + summary_json + search_text), `TargetORM`.
Events are stage rows + `result_json.events` list — **no dedicated event/log table**,
no log lines persisted per stage. Timestamps stored UTC; display Asia/Saigon is a
frontend concern.

## Gaps vs SUPER-PROMPT contract

1. **No SSE** — live updates currently via 2s polling (`runs.html`). SSE endpoint
   + client fallback still to build.
2. **No event/log persistence** — `log` lines, `ai_step`, `ai_proposal`,
   `verification_result` events do not exist server-side. Options: (a) new
   `events` table + emit hooks in `ScanService.persist()` and `AgentLoop`;
   (b) derive coarse events from stage rows only. Recommend (a) minimal table.
3. **No CSV export** — `ExportFormat` has sarif/json/html/markdown/txt/docx only.
   Spec asks CSV: add renderer (flat finding rows) or mark NOT AVAILABLE.
4. **No /api/scans, /api/findings, /api/tools, /api/usage, /api/settings/keys,
   /api/compare, /api/logs** — all to build thin over existing services.
5. **Keys**: project-local `.env` via `env_set`/`env_list` CLI (+ `.providers/*.json`
   for model profiles, gitignored). No server-side key API — build write-only
   endpoints over the same mechanism; never return secrets.
6. **ODC separate panel**: scanner results exist per-tool in `result_json`; frontend
   can split dependency vs source findings by tool name.
7. **Mock mode**: no fixture yet — build `web-ui/src/mock/` with scripted JVA-like run.
8. **npm offline**: `@fontsource` + deps must be vendored at build; verify
   `npm run build` works with network once, then offline serve.

## Assumptions (recorded, continue on these)

- A1: Single-user local only; auth = none beyond bind 127.0.0.1 + CSRF (as today).
- A2: Jinja pages stay as legacy fallback; React SPA served at `/app/*` or root
  with SPA fallback;decision made in Phase 1 by implementer (prefer `/app` to avoid
  breaking `/` for existing users; revisit before finalize).
- A3: Budget cap USD 50 (`BudgetManager`); usage from `ai_usage` in result_json.
- A4: Timestamps UTC in DB/API; UI renders Asia/Saigon by default with toggle.
- A5: Node 26 + npm 11 available on build machine (verified 2026-11-01).
- A6: `muse-glimmer`/`north-mini-code` style free models may return reasoning-only
  content — hunt fast-path pattern (`ai/hunt.py`) is the proven shape; SSE AI feed
  should consume persisted step summaries, never raw chain-of-thought.

## Endpoint contract to implement (SUPER-PROMPT §8, reconciled)

Keep existing routes. Add under `/api` with `X-Contract-Version: 1`:
`GET /api/health`, `GET /api/tools`, `GET/POST /api/targets`,
`GET /api/scans?status&limit`, `POST /api/scans`, `GET /api/scans/{id}`,
`POST /api/scans/{id}/cancel|/retry`, `GET /api/scans/{id}/events` (SSE,
Last-Event-ID), `GET /api/scans/{id}/events/history`,
`GET /api/scans/{id}/findings` (filters), `GET /api/findings/{id}`,
`GET /api/scans/{id}/reports`, `POST /api/scans/{id}/reports`,
`GET /api/reports/{rid}/download`, `GET /api/compare?scan_ids=`,
`GET /api/logs*` (stream+history), `GET/PUT /api/settings`,
`GET/PUT/DELETE /api/settings/keys/{profile}`, `POST .../test`,
`GET /api/usage`.

## Phased plan

1. Foundation (web-ui scaffold, tokens, shell, components, styleguide, mock,
   static mount + SPA fallback, SSE skeleton + events table).
2. Home + New Scan + API Keys (+ backend key/tool/settings endpoints).
3. Live Pipeline + replay.
4. Findings + drawer + evidence viewer.
5. Reports (download/generate/preview/compare) + Logs.
6. Polish (VI i18n, a11y, responsive, motion, tests, docs/screenshots).
