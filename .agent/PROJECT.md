# cloud-safeguard — project record

Canonical instructions: `../AGENTS.md` (agentic-delivery block). Product/delivery spec:
`docs/SPEC.md`; normative build contract: `docs/CONTRACT.md`.

## Now

- **Stage:** complete (delivered 2026-11-08; independent verification PASS).
- **North star:** an AI agent gets least-privilege, time-boxed cloud access in seconds
  without ever holding a long-lived AK/SK; risky access needs one human approval; every
  lease and cloud API call is auditable; rotating the broker credential touches one place.
- **Accepted implementation:** `docs/SPEC.md` §3 scope built per `docs/CONTRACT.md`:
  Go control plane (SQLite store, AES-256-GCM vault, explainable policy engine, lease
  lifecycle + sweeper, agent/admin REST API, init/demo seed), Alibaba Cloud STS signer
  (in-tree RPC v1) + mock provider/cloud, 5 built-in capabilities, `csg` CLI,
  `scripts/demo.sh` (S1-S8), embedded 8-page React console, docs suite.
- **Verification:** independent verifier on freshly cloned candidate `a509c1c`
  (product content unchanged by the later evidence-only commit) — PASS on verifiable
  A1-A16 scope: 164 PASS / 0 FAIL black-box probes, demo 8/8 twice, console Playwright
  34/34 with 0 console errors, 48 documented commands executed, secret-at-rest/log/bundle
  scans clean, audit tamper detected. Low findings F1-F3 (bootstrap rotation not audited,
  capability-create enabled default, approve does not recheck agent status) are recorded
  as nonblocking/deferred. Environmental NOT RUN: live Alibaba STS success path (no cloud
  credentials; signer unit-tested against golden vector + fake STS endpoint) and the
  default :8787 bind (port held by an unrelated process; all other A2 properties verified).
- **Canonical delivery record:** `changes/cloud-safeguard-v0.1/delivery.json` — complete
  assessment PASS (`arvey-develop delivery check --phase complete`, 16/16 behavior,
  5/5 checks, target/runtime/review recorded; source:v2:sha256:195530e5..., tested
  revision a509c1c). Evidence lives in `changes/cloud-safeguard-v0.1/evidence/`
  (report, screenshots, raw logs, repro scripts, deployment receipt); it is intentionally
  outside the product source identity (delivery-tooling evidence dir).
- **Blocked:** none. Future work (not v0.1): credential-free proxy mode, per-parameter
  grant constraints, chat approvals, multi-cloud, SSO/multi-tenant (see README roadmap).

## Next useful delivery

- **Outcome / north star:** see Now.
- **Accepted problem/hypothesis:** agents currently get broad, long-lived AK/SK; replace
  with capability leases minted just-in-time from a vaulted broker credential. Success:
  A1–A16 in `docs/SPEC.md` pass; zero long-lived cloud secrets outside the vault; demo
  shows auto-approve, one-click approval, denial, break-glass revocation and audit verify.
- **Non-goals / boundaries:** multi-tenant/SaaS, SSO, credential-free API proxy, non-Alibaba
  providers, K8s/HA deployment, chat approvals (all roadmap, see SPEC §3).
- **Target kind / environment / surface:** local dev artifact on this macOS machine
  (`/Users/arveykao/code/cloud-safeguard`); surface = CLI + HTTP API + embedded web console (target surface = api; browser E2E covers the console).
  No production deployment requested.
- **Address / artifact:** `bin/csg` (single binary), demo on `http://127.0.0.1:18787`.
- **Final demo:** `make demo` → S1–S8 pass; console screenshots captured by verifier.
- **Evidence / review:** `scripts/demo.sh` transcript, `go test ./...`, `npm run build`,
  verifier report `changes/cloud-safeguard-v0.1/evidence/report/VERIFICATION.md`, canonical
  `arvey-develop delivery check --phase complete` PASS.
- **Next action:** delivered; no open workstreams or blockers.

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
- Evidence: `changes/cloud-safeguard-v0.1/evidence/` — independent verification report,
  screenshots (12), build/demo/probe/console/docs logs, repro scripts, deployment receipt;
  canonical delivery record `changes/cloud-safeguard-v0.1/delivery.json`.
- Working notes: `.agent/scratch/` (gitignored).

## Actual constraints

- Work on one macOS host, no real Alibaba Cloud account access for the build; `mock` mode is
  the verification path, `sts` mode is implemented and unit-tested against a fake STS
  endpoint (no live cloud call).
- Local-only deployment (loopback bind). Do not weaken auth checks, TTL limits, audit chain
  or secret hygiene to pass checks.
