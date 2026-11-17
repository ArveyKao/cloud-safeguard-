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
- **Agent roles + IAM prohibition (2026-11-09, branch `feat/agent-roles`, CONTRACT §16,
  ADR-014):** integrated in the main checkout, not committed. Five cross-family (dsh) security
  reviews; every finding fixed with a regression test proven to fail without its fix. Combined
  checks on the merged tree: gofmt, vet, `go test ./...`, `go test -race ./internal/...` (8/8),
  web typecheck + build (web/dist regenerated), demo S1-S9 9/9, live console check against the
  real backend (roles, role-limited grants, access labels; no console errors). Known/deferred:
  D4 access-raise vs concurrent grant (low; role check still blocks any credential); console
  L1 retired-capability checkbox in the detail drawer (low; superseded by the redesign). Docs
  outside CONTRACT/DECISIONS not yet updated.
- **Role change (owner's instruction, 2026-11-09):** the owner asked Claude (Lead) to implement
  the security-critical code itself: IAM prohibition/policy rendering, role enforcement and
  approval rechecks, migrations, and §17 authentication, request verification and approval.
  Workers keep console, CLI, MCP client, demo and docs. Every change, including Lead's, gets a
  cross-family review. This overrides the "owner does not edit product code" rule for those areas.
- **Accepted next:** supervisors bind people to cloud accounts with a role; agents inherit
  their owner's role; requests carry read/write/full plus a required validity period; read is
  automatic, write and full wait for the owner's approval; agent-first sign-in and MCP server
  (CONTRACT §17, ADR-015). Accepted 2026-11-09, revised by the owner 2026-11-10; starts after
  §16 merges. This removes the §16 agent role, grants and `aliyun.account.admin`.
- **§17 progress (2026-11-10):** identity foundation built by Lead and verified locally:
  `internal/authn` (Argon2id, TOTP), schema v3 (persons, role_bindings, sessions), session
  login with CSRF, supervisor API for people and bindings, first supervisor in `csg init`,
  `csg supervisor recover`. Adds `golang.org/x/crypto`. Not yet cross-family reviewed, and
  bindings are not yet enforced on agent requests. Status table: CONTRACT §17.8.
- **§17 progress (2026-11-11):** review of the identity foundation done (dsh; 1 high, 1 medium,
  6 low, all fixed in 372d21f). Qoder QA run on 372d21f (sections A and B of
  `docs/QA_BRIEF.md`): 2 real bugs fixed (empty `Statement` accepted at capability create;
  negative approve TTL accepted), 4 points clarified in CONTRACT. Agent ownership and
  agent-first sign-in built by Lead (schema v4, `internal/server/agentsignin.go`), verified
  locally, not yet reviewed. GitHub issues cannot be filed or read from this machine (no `gh`,
  connector failing), so QA findings arrive in task reports.
- **§17 access requests (2026-11-11):** built by Lead: code-defined access templates with an
  action classification table (`internal/capcatalog/access.go`), cloud account IDs on providers
  (schema v5), `POST /agent/access-requests` with the owner's role read live, owner
  approve/deny/revoke under `/me/requests`, and revocation when a binding is lowered or
  removed. Verified locally (tests, race, demo, live run against the mock cloud); not yet
  cross-family reviewed. Templates are untested on real Alibaba Cloud. Remaining: CLI,
  MCP server, console redesign, removal of the §16 agent role and the admin token.
- **§17 approval modes (2026-11-12, plan confirmed by the owner with the explainer video):**
  each person chooses one mode for all their agents (read default, write, full; optional
  expiry); a supervisor sets each cloud account's highest automatic level (default read);
  automatic = the lower of the two, after the role check. Schema v6. Built by Lead, verified
  locally (tests, race, demo, live run); not yet committed or cross-family reviewed.
- **Supervisor API (2026-11-12):** cloud accounts, settings, audit and the emergency stop
  under `/api/v1/supervisor/`, reusing the operator handlers with actions attributed to the
  signed-in supervisor; `GET /api/v1/me/accounts` for everyone. Verified locally; not yet
  committed or cross-family reviewed. Step 1 of the four-step plan below is done.
- **Decided (review of 7d486a5, F2, owner 2026-11-12): accept and trace.** Supervisors are
  trusted to hand over setup codes; every setup records who issued the code (schema v7) and the
  setup-completed audit event names the issuer.
- **Agent CLI and MCP server (2026-11-12):** `csg login` agent sign-in, `csg accounts`,
  `csg access request|status`, `csg exec --account`, and `csg mcp` (five tools; credentials go
  to a 0600 file, never to the model). End-to-end tests against a real server. Verified
  locally; not yet committed or cross-family reviewed. Step 2 of the four-step plan is done.
- **Console redesign (2026-11-14):** new React console in `web/src/app/` on the person login
  (setup with QR, sign-in, Inbox, agent sign-in approval, Agents, Cloud accounts with the add
  wizard, Activity, People, Settings); the old admin-token console and `web/devmock` are
  removed. Checked in a browser against a real server. Step 3 of the four-step plan is done;
  step 4 (remove the admin token and the §16 agent model) remains.
- **Admin token and the §16 agent model removed (2026-11-15):** step 4 of the four-step plan.
  No admin token, admin API or admin CLI; no agent roles, grants, stored capabilities,
  break-glass or risk-tier policy engine. `csg init` prints only the first supervisor's setup
  code and never touches an existing directory. Schema version 8 deletes the admin token and
  revokes agents without an owner; leases that are not access requests are revoked at start.
  Supervisors are Administrator on every cloud account (owner's decision, 2026-11-14).
  `scripts/demo.sh` now runs nine scenarios through `scripts/demo/` (people over HTTP, the
  agent through the real `csg`). Verified locally; awaiting commit and independent review.
- **Review of a936962 (2026-11-16):** one blocker and eight majors, all fixed. The server now
  refuses to start without a supervisor (an upgraded v0.1 install has none) and says to run
  `csg supervisor recover`; `csg init` validates first and removes what it created when it
  fails; limits are the supervisor's current settings, not a copy made at agent sign-in; an
  agent without an owner is refused everywhere; every role write re-checks the person's
  agents; the connection test also assumes the role; the console wizard, QUICKSTART and the
  access templates share one role policy (tested). Found on the way: the STS client read the AssumeRole credential from the top
  level of the response, but Alibaba Cloud nests it under `Credentials`, so real mode could
  never have issued anything. Fixed; still unverified against a live account.
- **Second review round, of dfb2b7a (2026-11-16):** rejected with two blockers and five
  majors, all fixed: recovery now works on a v0.1 directory that never stored a secret, and
  the upgrade is recorded whichever command runs first; the demo script deletes a directory
  only when it really is inside `.demo/` (symlinks and ".." resolved); cloud-account edits
  are serialized and a connection test or key replacement writes only its own fields;
  giving an account its ID and removing its old roles is one transaction; approvals hold
  the agent's lock, so parallel approvals cannot exceed the limit; startup and recovery
  revocations name the agent and owner. Awaiting the third round.
- **Third review round, of 478e3c0 (2026-11-16):** round two confirmed fixed except one new
  blocker from my own fix: `csg serve` with a wrong `$CSG_MASTER_KEY` on an old directory
  wrote the key check with that key and locked the right one out. Fixed: a supplied key
  must equal `master.key` when the file exists, and a key that exists only in the
  environment is written into the key check only when the server is about to serve. The
  upgrade report is now kept in the database until it is audited. Minor items fixed too
  (deterministic parallel-approval test, demo delete race, `-wal`/`-shm` remnants, owner
  revocation attribution). Awaiting the fourth round.
- **Fourth review round, of c6a744a (2026-11-16):** the stricter key rule had its own traps
  (a whitespace-only `$CSG_MASTER_KEY` made `csg serve` create a random `master.key`; a
  correct key was refused next to a stale key file; an environment-only key could still be
  adopted from a typo once a supervisor existed). Replaced by one rule: `serve` and
  `recover` only read the key and prove it against the data; a supplied key the data proves
  right wins over the file; a directory with nothing encrypted takes its own `master.key`;
  with no `master.key` either, the operator must pass `--trust-master-key` once (audited).
  The upgrade record is written in the upgrade's own transaction and audited atomically.
  Awaiting the fifth round.
- **Fifth review round, of 9a2bba9 (2026-11-16): fit as the base for the next piece**, no
  blocker or major. Its two "require first" items are done: a test for an environment-only
  old directory that already has a supervisor, and the upgrade is recorded once even when
  two commands open the same old database at once. Minor items done too (trust decision and
  key check written together; key check written once the data proves the key; clearer
  messages for a missing key and a stale key file). These last changes have not been
  reviewed. Left for later: a `csg init` killed half-way leaves a directory no command can
  repair; whether every stored secret should be checked against the key at start; the
  audit-action table in CONTRACT §10.
- **Agreed next (owner, 2026-11-14):** (1) a person sign-in for `csg` with supervisor commands
  for everything except adding a cloud account, which stays console-only; (2) remote MCP over
  HTTPS with OAuth-style sign-in so an agent connects with just a URL.
- **Known gaps:** the console has no button for the supervisor's emergency stop (API only);
  README and QUICKSTART are rewritten, the other v0.1 pages carry an out-of-date banner; real
  Alibaba Cloud is untested.
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
- **Address / artifact:** `build/csg` (single binary), demo on `http://127.0.0.1:18787`.
- **Final demo:** `make demo` → S1–S9 pass; console screenshots captured by verifier.
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
| Run console | `./build/csg init --demo --data-dir .demo/data && ./build/csg serve --data-dir .demo/data` |
| Server/API contract checks | Go httptest suites in `internal/server`, `internal/mockcloud`; verifier probes |
| Performance budget | not triggered (no hot-path optimization target) |

## Target applicability and access

- Execution mode: coordinated Lead delegates implementation to DSH Agent Teams workers;
  Lead owns contract, integration and combined checks. No production target, no operator
  heartbeat required (CLI/library-style local artifact + local demo server).
- Operator applicability: **not_applicable** for v0.1 (local-only artifact; no monitored
  background service), recorded via `arvey-develop operator configure` in
  `.agent/operator.json`. Revisit when deployed.
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
