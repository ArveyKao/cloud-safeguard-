# Cloud Safeguard console

React 18 + TypeScript + Vite single-page console. It is built into `dist/` and embedded in the
`csg` binary (`web/embed.go`). Normative source: [`docs/CONTRACT.md`](../docs/CONTRACT.md)
§12 and §17.

## Commands

```sh
npm install            # Node >= 20
npm run dev            # http://127.0.0.1:18803, proxies /api, /mock-cloud and /healthz to a running csg serve
npm run typecheck
npm run build          # into dist/ (absolute asset paths: routes are nested)
```

For local development run `csg init --demo` and `csg serve` (port 8787, or set
`CSG_API_PROXY`), then set up the first supervisor with the code `csg init` printed.

## Structure

```
src/main.tsx            entry
src/app/App.tsx         session gate and page routing
src/app/api.ts          session client: cookie + in-memory CSRF token, no localStorage
src/app/types.ts        wire types of the person-facing API
src/app/ui.tsx          buttons, cards, fields, modal, toasts, QR code, formatting
src/app/Shell.tsx       sidebar layout
src/app/pages/          Login, Setup, Inbox, SignInApproval, Agents, Accounts, AddAccount,
                        Activity, People, Settings
src/app/app.css         all styles
```

## Security properties the UI keeps

- Sign-in uses the HttpOnly session cookie; the CSRF token lives in memory only and is sent
  on every change. Nothing secret is written to `localStorage`.
- Setup codes are shown once, in a dialog that cannot be dismissed by clicking outside.
- AccessKey secrets are typed into password fields, sent once and never displayed.
- Text from the server is rendered as text; the only HTML injected is the QR code SVG the
  console generates itself.
