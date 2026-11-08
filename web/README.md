# Cloud Safeguard — operator console

React 18 + TypeScript + Vite single-page console for the Cloud Safeguard control
plane. It is built into `dist/` and embedded in the `csg` binary via `web.FS()`
(`web/embed.go`); `make build` rebuilds it automatically.

Normative sources: [`docs/CONTRACT.md`](../docs/CONTRACT.md) §3–§5 (API) and §12
(console requirements); wire types mirror [`internal/model/model.go`](../internal/model/model.go).

## Commands

```sh
npm install            # Node >= 20
npm run dev            # http://127.0.0.1:18803, proxies /api + /mock-cloud + /healthz to 127.0.0.1:8787
npm run typecheck      # tsc --noEmit
npm run build          # typecheck + production bundle into dist/ (base "./")
npm run preview        # serve the built bundle on 18803 (needs a live API)
npm run mock           # local devmock API on 127.0.0.1:8787 (see below)
```

The shipped app always talks to the same origin (`/api/v1`, `/mock-cloud`,
`/healthz`); there are no absolute API URLs, external CDNs or webfonts, so it
works fully offline.

## Local development without the Go backend

`devmock/server.mjs` implements the contract subset the console consumes with
realistic fixtures (5 capabilities, a mock provider, 2 agents, 10 leases and a
real hash-chained audit log). It prints a freshly generated admin token on
startup — nothing is persisted to disk.

```sh
npm run mock                          # another terminal; port 8787
npm run dev                           # console on 18803, proxied to the devmock
# If 8787 is occupied: MOCK_PORT=18804 npm run mock
# and CSG_API_PROXY=http://127.0.0.1:18804 npm run dev
```

Use the printed token on the login screen. `MOCK_ADMIN_TOKEN` can pin the token
for scripted browser tests. The devmock is development tooling only — it is not
imported by `src/` and therefore never bundled into `dist/`.

## Structure

```
src/
  api/types.ts       1:1 TypeScript mirror of internal/model/model.go
  api/client.ts      typed fetch client, envelopes, 401 -> login, error mapping
  api/hooks.ts       visibility-aware polling, resources, mutations, server clock
  auth.ts            admin token storage (localStorage key csg.adminToken)
  router.tsx         small History-API router (Go server serves index.html fallback)
  components/        design-system primitives, overlays, toasts, lease decision UI
  pages/             Login, Overview, Agents, Capabilities, Leases, Providers, Audit, Settings
  styles/            plain-CSS design tokens + layout/pages (no UI kit)
devmock/server.mjs   local fixture API (optional, dev only)
```

## Security properties the UI must preserve

- The admin token is only read from `localStorage` and sent as a Bearer header; it
  is never rendered, logged or put in a URL after login.
- Provider AccessKeys/STS secrets are never rendered, stored client-side or echoed
  by the rotate form. Only masked AccessKey IDs from the API are shown.
- The agent bearer token is displayed exactly once, in the create/rotate reveal
  dialog, and cannot be reopened.
- Destructive actions (suspend, revoke, deny, disable capability, rotate) use
  confirm dialogs and required reasons where the contract requires them.
- `grep -rE 'csg_adm_[A-Za-z0-9]|LTAI[0-9A-Za-z]{8,}' dist/` must stay empty.
