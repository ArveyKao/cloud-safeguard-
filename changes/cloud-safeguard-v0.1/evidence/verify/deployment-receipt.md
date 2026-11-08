# Deployment receipt — Cloud Safeguard v0.1.0 (verifier)

Captured at: **2026-11-08T14:13:00Z** (2026-11-08 06:13 America/Los_Angeles).

## Candidate identity

| Field | Value |
| --- | --- |
| Repository | `/Users/arveykao/code/cloud-safeguard` (no remote; local clone used for verification) |
| Candidate commit (branch `main`, HEAD) | `a509c1c9868bfbed458ee07789c1a6191bc10bd0` |
| Base commit | `122f4c8` (per SPEC §8 baseline); delta from `37e53d1` to `a509c1c` is a mechanical `internal/vault` → `internal/vaultcrypto` directory rename (Go package still `vault`) + import/doc path updates |
| Fresh-clone verification root | `/tmp/csg-verify/candidate` (`git clone` + `git checkout a509c1c`) |
| Product version reported | `csg 0.1.0 (Cloud Safeguard)` / `model.Version=0.1.0` |

## Environment

| Field | Value |
| --- | --- |
| Host | macOS (Darwin, `arm64`), loopback-only local dev artifact |
| Go | `go1.24.4 darwin/arm64` |
| Node / npm | `v26.7.0` / `11.19.0` |
| Playwright | `playwright-core 1.65.0`, cached Chromium 1228 headless, 1440×900 (1024×768 responsive check) |
| Extra tooling | installed under `/tmp/csg-verify/ui` only — nothing added to the repository |

## Built artifact

- `make build` (web `npm install --no-audit --no-fund` + `npm run build` → `web/dist`, then
  `go build -trimpath -ldflags "-s -w" -o bin/csg ./cmd/csg`) — exit 0.
- `bin/csg` single Go binary (~11 MB), embeds the React console via `web.FS()`.
- Committed `web/dist` was rebuilt during verification: `vite v6.4.5` produced
  `dist/index.html 1.21 kB`, `index-DKKeRUwd.css 60.88 kB`, `index-JCLQlyqB.js 292.67 kB`.
- Static checks on `a509c1c`: `gofmt -l .` empty, `go vet ./...` clean, `go build ./...` ok,
  `go test ./...` all packages ok, `go test -race` on store/vaultcrypto/policy/server ok —
  see `scripts/verify/build.log`.

## Runtime / data dirs / ports (all loopback, throwaway)

| Purpose | Command | Data dir | Port |
| --- | --- | --- | --- |
| Demo S1–S8 (twice, clean re-init) | `./scripts/demo.sh --port 18787 --data-dir /tmp/csg-verify/demo-data[-final]` | throwaway | 18787 |
| API/security probes | `csg serve --addr 127.0.0.1:18891 --data-dir /tmp/csg-verify/probe-run/data` | throwaway | 18891 |
| Tampered-audit probe | `csg serve --addr 127.0.0.1:18892 --data-dir /tmp/csg-verify/probe-run/tamper-data` | throwaway copy | 18892 |
| Console E2E (A13) | `csg serve --addr 127.0.0.1:18893 --data-dir /tmp/csg-verify/ui-run/data` | throwaway | 18893 |
| Docs spot-check | `csg serve --addr 127.0.0.1:18787 --data-dir /tmp/csg-verify/docs-check` | throwaway | 18787 |

Bootstrap always `csg init --demo --json --data-dir <dir>` (creates `master.key` 0600,
`csg.db` 0600 inside a 0700 dir, admin token + two one-time demo agent tokens, 5 built-in
capabilities, 1 mock `aliyun` provider, default policy settings).

## Health / demo confirmation

- `GET /healthz` → `200 {"status":"ok","version":"0.1.0",...}` on every instance.
- `GET /` serves the real built dashboard (`<div id="root">`, hashed JS/CSS assets 200).
- `./scripts/demo.sh --port 18787 ...` → **8 passed, 0 failed**, `EXIT_CODE=0`, no listener left
  on 18787; run twice from clean data dirs with identical results —
  `scripts/verify/demo-transcript.log` (second run) and `/tmp/csg-verify/demo-run1.log` (first run).
- `make demo` → S1–S8 8/8 pass, server cleaned up — `scripts/verify/make-targets.log`.
- Console E2E — 34/34 checks pass, all pages navigated, no uncaught console/page errors —
  `scripts/verify/console-e2e.log`, screenshots in `docs/screenshots/`.
- Black-box API/security probes — 164 PASS / 0 FAIL — `scripts/verify/api-probes.log`.

## Cleanup

All verifier-owned `csg` servers were signalled with SIGINT at the end of each run; no
`csg serve` process or listener remains on 18787/18891/18892/18893, and the repository was
not committed to (working tree changes are verifier evidence files only).
