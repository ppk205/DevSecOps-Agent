# PIT WALL web UI (Phase 1 foundation)

React 18 + TypeScript + Vite + Tailwind SPA, BMW M dark tokens, served by
FastAPI at `/app/*` with an SPA fallback. Legacy Jinja pages stay intact.

## Run (mock, no backend)

```bash
cd web-ui
npm install
VITE_MOCK=1 npm run dev        # or: npm run dev:mock
```

Open http://127.0.0.1:5173/app/ — shell, styleguide, scripted ~60-finding
run, and the staged event rail all render without a backend.

- `/app/styleguide` — hidden route rendering every token + component.
- `VITE_MOCK=1` can also be set in `web-ui/.env.local`.

## Run (live backend)

```bash
npm run build                  # emits web-ui/dist (self-hosted Inter, offline-safe)
cd .. && .venv/Scripts/python -m uvicorn vulnscan.web.app:app_factory --port 8000
# SPA at http://127.0.0.1:8000/app/ ; legacy Jinja still at /
```

Vite dev proxies `/api` → `127.0.0.1:8000` for live work (`npm run dev`).

Packaging: copy `web-ui/dist/*` → `src/vulnscan/web/static/app/` (gitignored,
created at build time) so the wheel serves the SPA offline; in a source
checkout the app auto-detects `web-ui/dist` in place.

## Verify

```bash
npm run lint                   # tsc --noEmit
npm test                       # vitest run
npm run build                  # must succeed; dist/ is gitignored
```

## Conventions

- Tokens live once in `src/tokens.ts` (+ Tailwind + `styles.css` mirror).
- No chart library: hand-written SVG in `src/components/charts/`.
- EN strings in `src/i18n/en.ts` (VI lands in Phase 6).
- Mock layer in `src/mock/` — deterministic, seeded, ~60 findings.
