# Screenshots — PIT WALL web UI

> No PNG screenshots are checked in. No real Chromium exists in this
> environment, so rendered screenshots could not be captured — and none
> are fabricated here. What follows is the textual page inventory used
> for the Phase 6 acceptance sweep, plus how to capture real shots.

## How to capture (mock mode, no backend)

```bash
cd web-ui
VITE_MOCK=1 npm run dev     # or: npm run dev:mock
# Open http://127.0.0.1:5173/app/ at 375 / 768 / 1024 / 1440 / 1920 px
```

Toggle EN/VI from the topnav (persists to `localStorage`, sets `<html lang>`).

## Page inventory (all 7 nav destinations + hidden styleguide)

1. **Home** (`/app/`) — hero band "FIND. VERIFY. SHIP SECURE.", 6 KPI
   spec-cells, severity donut + bars, top-CWE bars, tool-health strip
   (8 steps), scan-history table, CTA band. VI: "TÌM. XÁC MINH. TRIỂN KHAI AN TOÀN."
2. **New Scan** (`/app/scans/new`) — target input, FAST/DEEP profile radio
   (DEEP disabled), scanner switches, AI-review switch, advanced
   details, sticky review panel with CLI preview + Start.
3. **Live Pipeline** (`/app/live`) — 8-node stage rail with running
   stripe (single 200ms sweep), timeline scrubber, mobile-only
   Stages/AI/Results/Logs tabs, stage detail, AI panel (NOW ANALYZING,
   reasoning feed, CVSS proposals, claim-vs-check), confirmed-first
   results with counters, log dock with pause/auto-scroll.
4. **Findings** (`/app/findings`) — origin tabs (All/Source/Dependencies),
   filter bar, saved views, sort controls, J/K/Enter/Esc/V keyboard map,
   table with severity/status badges, drawer (header, viewers, V raw
   JSON) and full detail page at `/app/findings/:id`.
5. **Reports** (`/app/reports`) — per-format table (json/sarif/html/
   markdown/txt/docx/csv) with Download/Generate/Copy-CLI, final
   narrative link, sandboxed HTML preview + fullscreen, compare panel
   (per-scanner/per-CWE tables, New/Fixed/Changed, HTML export).
6. **Logs** (`/app/logs`) — scan/level/source/search filters, pause/
   resume, wrap, copy, .log/.jsonl download, pause buffering pill,
   finding-id links, expandable JSON rows.
7. **API Keys** (`/app/keys`) — provider profile form (write-only key),
   profile list with test/delete, scanner tools detect/verify, usage
   bar against the USD 50 ceiling, general settings.
8. **Styleguide** (`/app/styleguide`, hidden) — tokens, type, buttons,
   badges, stage rail, spec cells, charts, drawer demo.

## Visual rules checked (BMW M)

0-radius surfaces (only 48px circular icon buttons), UPPERCASE 700
display + labels, Light 300 body, M stripe divider/rail only (never
fills), black canvas, flat cards, no shadows, 2px white focus ring.
