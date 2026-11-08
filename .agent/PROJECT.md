# cloud-safeguard — project record

Canonical instructions: `../AGENTS.md` (agentic-delivery block). Product/delivery spec:
`docs/SPEC.md`; normative build contract: `docs/CONTRACT.md`.

## Now

- **Stage:** develop (base contract frozen, parallel implementation in flight).
- **North star:** an AI agent gets least-privilege, time-boxed cloud access in seconds
  without ever holding a long-lived AK/SK; risky access needs one human approval; every
  lease and cloud API call is auditable; rotating the broker credential touches one place.
- **In flight:**
  - `core-api` — store/vault/policy/audit/HTTP API/sweeper/init.
  - `agent-toolkit` — Aliyun STS signer, mock provider, capability catalog, mock cloud,
    full CLI, demo script.
  - `console-ui` — React/Vite console (overview, approvals, agents, capabilities, leases,
    providers/vault, audit, settings).
  - `product-docs` — README, PRODUCT (zh), SECURITY, ARCHITECTURE, QUICKSTART, API,
    DECISIONS.
- **Blocked:** none. Lead integrates and runs combined checks; verifier spawned after the
  first integrated build.
- **Accepted:** MVP scope per `docs/SPEC.md` §3; contract per `docs/CONTRACT.md`;
  single-tenant, Alibaba Cloud (`sts` + `mock`), console + CLI + demo.
- **Next:** finish parallel implementation, integrate `make build`/`make test`, run verifier
  A1–A16, fix findings, final demo + evidence.

## Next useful delivery

- **Outcome / north star:** see Now.
- **Accepted problem/hypothesis:** agents currently get broad, long-lived AK/SK; replace
  with capability leases minted just-in-time from a vaulted broker credential. Success:
  A1–A16 in `docs/SPEC.md` pass; zero long-lived cloud secrets outside the vault; demo
  shows auto-approve, one-click approval, denial, break-glass revocation and audit verify.
- **Non-goals / boundaries:** multi-tenant/SaaS, SSO, credential-free API proxy, non-Alibaba
  providers, K8s/HA deployment, chat approvals (all roadmap, see SPEC §3).
- **Target kind / environment / surface:** local dev artifact on this macOS machine
  (`/Users/arveykao/code/cloud-safeguard`); surface = CLI + HTTP API + embedded web console.
  No production deployment requested.
- **Address / artifact:** `bin/csg` (single binary), demo on `http://127.0.0.1:18787`.
- **Final demo:** `make demo` → S1–S8 pass; console screenshots captured by verifier.
- **Evidence / review:** `scripts/demo.sh` transcript, `go test ./...`, `npm run build`,
  verifier report `docs/VERIFICATION.md`, cross-family independent review (`arvey-develop
  review run` or verifier teammate).
- **Next action:** integrate parallel work; then independent verification.

## Existing commands

| Purpose | Command |
| --- | --- |
| Dependency setup / build | `make build` (`go` 1.24+, `npm`/Node ≥20) |
| Automated checks | `go test ./...`; `go vet ./...`; `cd web && npm run typecheck && npm run build` |
| Demo / E2E | `make demo` (`./scripts/demo.sh --port 18787 --data-dir .demo/data`) |
| Run console | `./bin/csg init --demo --data-dir .demo/data && ./bin/csg serve --data-dir .demo/data` |
| Server/API contract checks | Go httptest suites in `internal/server`, `internal/mockcloud`; verifier probes |
| Performance budget | not triggered (no hot-path optimization target) |

## Target applicability and access

- Execution mode: coordinated Lead delegates implementation to DSH Agent Teams workers;
  Lead owns contract, integration and combined checks. No production target, no operator
  heartbeat required (CLI/library-style local artifact + local demo server).
- Operator applicability: not_applicable for v0.1 (local-only artifact; no monitored
  background service). Revisit when deployed.
- Credentials: no real cloud credentials are used for the build or demo. Demo runs entirely
  in `mock` provider mode. Broker AccessKey values live only in an encrypted SQLite vault in
  a throwaway data dir; no secret is written to the repo or evidence.

## Shared contract and context map

- Canonical instructions: `AGENTS.md`; product spec: `docs/SPEC.md`; contract:
  `docs/CONTRACT.md`; shared types: `internal/model/model.go`.
- Ownership map: `docs/SPEC.md` §8; frozen signatures: `docs/CONTRACT.md` §13.
- Evidence: `docs/VERIFICATION.md` (verifier), demo transcript, test output; screenshots
  under `docs/screenshots/`.
- Working notes: `.agent/scratch/` (gitignored).

## Actual constraints

- Work on one macOS host, no real Alibaba Cloud account access for the build; `mock` mode is
  the verification path, `sts` mode is implemented and unit-tested against a fake STS
  endpoint (no live cloud call).
- Local-only deployment (loopback bind). Do not weaken auth checks, TTL limits, audit chain
  or secret hygiene to pass checks.
