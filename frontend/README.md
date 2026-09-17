# PacketKage frontend

React + TypeScript + Vite SPA for the PacketKage web UI.

## Development

```bash
npm install
npm run dev        # Vite dev server on http://localhost:5173 (expects the API on :8000)
```

## Commands

| Command            | Purpose                              |
| ------------------ | ------------------------------------ |
| `npm run dev`      | Vite dev server with HMR             |
| `npm run build`    | Typecheck + production build to `dist/` |
| `npm run lint`     | Oxlint                               |
| `npm test`         | Vitest unit tests                    |
| `npx playwright test` | End-to-end tests (boots API + dev server) |

## Structure

* `src/api/` - typed REST client for the backend API
* `src/pages/` - route views (Graph, Capture, Cases, Flows, Alerts, Replay, …)
* `src/components/` - shared UI primitives and domain components
* `src/hooks/` - React Query data hooks
* `src/types/` - API shared types
* `src/test/` - test render harness and helpers
* `e2e/` - Playwright end-to-end specs