# Cloud Safeguard v0.1 — Independent Verification Report

**Verdict: PASS on the verifiable mock/demo acceptance scope (A1–A16), with the
environmental NOT-RUN items listed in §7 and the low-severity findings in §5.**
No blocking defect or security hole was found. All evidence below was produced by the
independent verifier from a fresh clone and real runs; the verifier did not modify product
code, tests or other owners' documentation.

- **Candidate commit (verified):** `a509c1c9868bfbed458ee07789c1a6191bc10bd0`
  (`main` HEAD; base `122f4c8`; the `37e53d1 → a509c1c` delta is a mechanical
  `internal/vault` → `internal/vaultcrypto` directory rename + import/doc path updates,
  confirmed by `git diff --stat`: 9 files, no logic change).
- **Fresh clone used:** `/tmp/csg-verify/candidate` (`git clone` + `git checkout a509c1c`).
  The original repo working tree was clean and was not committed to.
- **Captured:** 2026-11-08T14:06–14:13 UTC (macOS arm64).
- **Environment:** `go1.24.4 darwin/arm64`, `Node v26.7.0`, `npm 11.19.0`,
  `playwright-core 1.65.0` + cached Chromium 1228 (headless, 1440×900 / 1024×768),
  loopback-only throwaway instances. Playwright tooling installed under `/tmp` only.
- **Method:** fresh-clone static/build checks → scripted demo S1–S8 (twice) → black-box
  CLI+HTTP security probes on throwaway data dirs → audit-tamper probe on a DB copy →
  secret-at-rest/log/bundle scans → real-browser console E2E → docs command spot-checks.

Evidence files (all in this repo, plain text, no secrets/tokens):
`scripts/verify/build.log`, `demo-transcript.log`, `api-probes.log`, `runtime-server.log`,
`console-e2e.log`, `docs-check.log`, `make-targets.log`, `deployment-receipt.md`,
repro scripts `probe-api.sh`, `run-console-e2e.sh`, `console-e2e.mjs`, `docs-check.sh`,
and `docs/screenshots/*.png`.

> **Lead note (evidence relocation):** after verification, the evidence artifacts were moved
> from `scripts/verify/`, `docs/screenshots/` and `docs/VERIFICATION.md` into
> `changes/cloud-safeguard-v0.1/evidence/` (`verify/`, `screenshots/`, `report/`) so they live
> in the delivery evidence directory and stay outside the product source identity. Paths
> mentioned inside this report refer to the original verifier paths; the same files now live
> under the evidence directory with identical content.

---

## 1. Acceptance criteria A1–A16

Legend: **PASS** = independently exercised with real runs and exact evidence; **PARTIAL** =
main behavior passes, a named sub-item was not runnable in this environment; **NOT RUN** =
not exercised (reason given). No criterion is FAIL.

| # | Criterion | Result | Evidence (command → key output) |
| --- | --- | --- | --- |
| A1 | `csg init --demo --json`: 0700 data dir, `master.key`/DB 0600, admin token, 5 caps / 1 provider / 2 agents; tokens once; re-init refused; `--force` rotates admin token | **PASS** | `./bin/csg init --demo --json --data-dir …` → exit 0, `provider_ids=1`, `capability_ids=5`, `agents=2`; `stat -f %Lp` → dir `700`, `master.key 600`, `csg.db 600`; key size 32 B. Second init → exit 1, `error: … already initialized; refusing to overwrite it (use --force …)`, no token in output. `--force` → exit 0, new admin token (`csg_adm_tiCO…` ≠ old `csg_adm_coSy…`), DB still 1 provider/2 agents/5 caps, old admin token → 401, and the pre-force agent token still authenticates (`GET /agent/me` 200). See `api-probes.log` A1 block + **finding F1** (force rotation not audited) |
| A2 | `make build` produces `bin/csg`; `csg serve` serves `/healthz`, `/api/v1/…`, built dashboard `/`; graceful SIGINT shutdown | **PARTIAL** | Clone `make build` → `bin/csg` (11 MB), `./bin/csg version` → `csg 0.1.0`; `GET /healthz` → `200 {"status":"ok","version":"0.1.0"}`; `GET /` → HTML with `id="root"`, hashed `/assets/index-*.js` 200; unknown non-API GET `/agents` → SPA index 200; `/api/v1/agent/me` unauthenticated → 401; SIGINT → process exits, port released, log `shutting down: control plane stopped`. **Default addr 8787 NOT RUN**: port 8787 is held by an unrelated Python process in this environment (would require killing a non-verifier process); every other A2 property was exercised on explicit `--addr` instances (`api-probes.log`, `build.log`, `make-targets.log`) |
| A3 | Auto-approve S1 end-to-end; Alibaba-Cloud-shaped STS env | **PASS** | `POST /api/v1/agent/leases` (`aliyun.cloud.read`, 300 s) → **201**, `status=active`, `decision.outcome=auto_approve`, `approved_by=auto`, 15 explainable reasons incl. `auto_approve`; `POST …/credential` → 200 with exactly 6 env vars in order `ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET, ALIBABA_CLOUD_SECURITY_TOKEN, CSG_LEASE_ID, CSG_SERVER, CSG_CAPABILITY`; AK `LTAI…`, token `cgk1.…`; mock cloud `GET /mock-cloud/v1/ecs/instances` → **200**, 3 instances; lease JSON contains no credential/token. CLI path too: `csg request --wait 30s` → `status=active decision=auto_approve ttl=900` (`api-probes.log` A3; `docs-check.log`) |
| A4 | Least privilege: out-of-policy action → 403; TTL/agent/global/concurrency/rate limits with explicit rule keys; sweeper expires leases and scrubs credentials | **PASS** | Same valid read credential: `POST /mock-cloud/v1/ecs/…/restart` → **403 `Forbidden.RAM`**. Denials carry explicit durable rule keys + numeric detail: `ttl_within_capability` (requested 3600 s > cap max 1800 s), `ttl_within_agent` (agent max 60 s), `ttl_within_global` (global lowered to 600 s), `concurrency_available` (agent max 1, 2nd lease denied), `rate_limit` (7th creation in 60 s denied). 5 s-TTL lease: token works immediately (200), after 6.5 s → **401 `InvalidSecurityToken.Expired`**, after sweeper → `GET lease status=expired`, credential fetch → **409 `lease_not_active`**, DB `encrypted_credential` cleared (`0/0`). `api-probes.log` A4 block |
| A5 | Enforcement is server-side: forged/expired/revoked tokens 401; admin↔agent token domains separated; cross-agent lease 404; suspended agent blocked; rotated token invalidates old | **PASS** | forged agent token → 401 `unauthorized`; garbage → 401; admin token on agent route → 401; agent token on admin route → 401; old admin token after `--force` → 401; revoked mock token → 401 `InvalidSecurityToken.Revoked`; expired mock token → 401 `InvalidSecurityToken.Expired`; malformed mock token → 401; cross-agent lease read/credential → **404**; suspended agent → **403 forbidden** on requests and `/agent/me`; agent token rotation → old 401, new 200. `api-probes.log` A5 block |
| A6 | Approval (S4) and denial (S5) from **both** CLI and web console; break-glass without flag denied, with flag pending+critical severity; approve then revoke kills mock token live | **PASS** | `csg leases approve ID --note …` → exit 0, lease `active`, `approved_by=admin`; scoped DNS write `POST …/dns/zones/arveykao.com/records` → **200**, ECS restart with same credential → 403. HTTP `POST /admin/leases/{id}/approve` → 200 active. `csg leases deny` → exit 0 denied; HTTP deny → 200 denied; pending/denied credential fetch → **409**. Break-glass without flag → denied rule `break_glass_required`; with flag → pending; approve → `lease.approved` audit event severity **critical**; token works; admin revoke → token → **401**. Web console approval is covered by A13 E2E (`03-approve-modal.png` → status active/approved_by admin/credential 200). `api-probes.log` A6 block; `console-e2e.log` |
| A7 | Audit chain verifies on clean DB; verification fails after a row is tampered with | **PASS** | `GET /admin/audit/verify` → 200 `ok=true`; `csg audit verify` → exit 0 `ok=true events=82` (probe instance). On a **copy** of the DB, `UPDATE audit SET metadata_json='{"tampered":true}' WHERE seq=2` → verify returns 200 `ok=false first_invalid_seq=2 message="audit chain hash mismatch at seq 2"`; CLI verify exits nonzero with `ok=false first_invalid_seq=2`. Go test coverage confirmed: `internal/store/store_test.go` (`VerifyAudit did not detect a tampered row`). `api-probes.log` A7/A7b |
| A8 | No plaintext broker secret / STS secret / agent token in DB files, server access log, other API responses, or JS bundle | **PASS** | Canary broker AK/secret added via `csg providers add`; exact strings then scanned: SQLite `csg.db` + `-wal` + `-shm`, server access log, CLI outputs, all captured API responses (`/admin/overview|providers|leases|agents|audit|capabilities|policy`, `/agent/leases|caps`), and committed `web/dist` bundle — **0 hits** for broker secret, broker AK, 4 distinct mock STS tokens, admin token, old admin token, and 3 agent tokens. Provider API returns only `access_key_id_masked` (e.g. `CANA****3456`), no secret field; agent B's lease list contains only its own leases (0 foreign). `api-probes.log` A8 block |
| A9 | Vault encrypts broker credentials; wrong AAD fails; provider credential never returned by any API | **PASS** | `go test -v ./internal/vaultcrypto` → all pass incl. `TestDecryptAADMismatch`, `TestRoundTrip`, `TestEncryptUsesFreshNonce`, `TestNewWrongKeySize`, `TestNewCopiesKey`. DB `providers.encrypted_credential` and `leases.encrypted_credential` are `v1:`-prefixed AES-GCM ciphertext (base64); master key 32 B/0600. No API response exposes a credential except the lease-owner credential endpoint (A8 scan). `api-probes.log` A9 block |
| A10 | Policy editable and effective (auto-approve medium), invalid settings 400, change audited | **PASS** | Baseline: medium `aliyun.dns.manage` lease → `pending`; `csg policy set --auto-approve-max-risk medium` → exit 0; same request → `status=active decision=auto_approve`. `PUT /admin/policy` with `auto_approve_max_risk="bogus"` → **400** `invalid_request`. Audit `action=policy.updated` present (warning). Defaults restored after probe. `api-probes.log` A10 block |
| A11 | Provider credential rotation works, is audited, old leases unaffected, new leases mint, no agent changes | **PASS** | `csg providers rotate ID --access-key-id … --access-key-secret-file …` → exit 0 (secret never echoed), provider `access_key_id_masked` updated (`LTAI****nary`), audit `provider.credential_rotated` ≥1, `csg providers test` → `ok=true`; pre-rotation lease's mock token still works against mock cloud → 200; a new lease mints `active` afterwards with the unchanged agent token. `api-probes.log` A11 block |
| A12 | Agent token rotation invalidates old token; suspend blocks agent; limits (concurrency + per-minute) enforced with explicit reasons | **PASS** | `POST /admin/agents/{id}/token/rotate` → old token 401, new token 200; suspend → 403 on requests + `/agent/me`, activate restores; per-agent max TTL denial rule `ttl_within_agent`, concurrency rule `concurrency_available`, per-minute rule `rate_limit` — each with numeric detail (A4). `api-probes.log` A4/A5/A12 |
| A13 | Web console: login, real overview counts, approve a pending lease from UI, one-time agent token, audit verify, no uncaught console errors; approval visible in API | **PASS** | Playwright against the shipped embedded bundle: 34/34 checks, **0 FAIL**, **0 uncaught console/page errors**. Overview pending queue matches `/admin/overview` count (3 queued, 3 rendered); console approval with TTL override + note → API lease `active`, `approved_by=admin`, `credential_available=true`, credential fetch 200; one-time token modal shown and the screenshot-visible token was immediately rotated/invalidated; audit page "Verify chain" → "Audit chain verified / intact"; all 7 nav pages render; logout clears `localStorage` token; SPA deep link `GET /leases` works; 1024×768 responsive without horizontal overflow. Screenshots in `docs/screenshots/` (01–12). `console-e2e.log` |
| A14 | `make test` passes, `go vet` clean, web typecheck+build pass | **PASS** | On `a509c1c`: `gofmt -l .` empty; `go vet ./...` clean; `go build ./...` ok; `go test ./...` → all packages `ok` (`capcatalog, cli, mockcloud, policy, provider, server, store, vaultcrypto`); `go test -race ./internal/store ./internal/vaultcrypto ./internal/policy ./internal/server` → all `ok`, no data race; `cd web && npm run typecheck && npm run build` → clean, `vite v6.4.5 … built in ~300 ms`; `make build` ok. `scripts/verify/build.log` |
| A15 | Demo S1–S8 passes reproducibly from clean data dirs and leaves no server process | **PASS** | `./scripts/demo.sh --port 18787 --data-dir …` run **twice** from removed data dirs → both `demo summary: 8 passed, 0 failed`, `EXIT_CODE=0`, all `PASS S1..S8`; after each run 0 listeners on 18787 and no demo `csg serve` process. `make demo` (documented entry point) also 8/8 and cleaned up. `scripts/verify/demo-transcript.log` (+ `/tmp/csg-verify/demo-run1.log`), `make-targets.log` |
| A16 | Docs accurate: every practical README/QUICKSTART command runs; PRODUCT/SECURITY/ARCHITECTURE match shipped behavior and honestly list limitations | **PASS (practical scope)** | 48 documented commands executed against a real instance (`csg version/login/whoami/caps/agents/request/credential/mock/exec/leases/audit/providers/policy/…`) — all succeed with documented behavior; documented exit codes verified: bad token → 3, missing flag → 2, wait timeout → 4, operation failure → 1; `make test`/`make demo` targets work. Docs command/flag names match shipped `--help`. SECURITY.md residual-risk claims were checked against code/behavior and are accurate: mock mode is **not** a security boundary and is loopback/demo-only; real STS session revocation is not instant (mock-mode revocation is immediate); master key protects secrets **at rest only**; audit chain is tamper-**evident**, not tamper-proof. ARCHITECTURE/PRODUCT numbers match behaviour (8 console pages, 5 built-in capabilities, 10 s sweeper, `fmt`, default TTL/limits). **NOT RUN:** QUICKSTART §real Alibaba Cloud `sts` setup and any live-cloud command (no cloud account/credentials in this environment — documented limitation). `scripts/verify/docs-check.log`, `make-targets.log` |

Supporting demo detail (A3/A4/A6/A7 scenario evidence): S1 auto-read 201/active/auto_approve;
S2 restart 403; S3 DNS pending; S4 approval → DNS write 200 / ECS restart 403; S5 denial durable
+ audited; S6 ungranted capability denied; S7 break-glass gating + critical audit + revoke kills
token live; S8 audit verify `ok=true` — `scripts/verify/demo-transcript.log` and
`api-probes.log`.

---

## 2. Security probes — detail

All probes were black-box (CLI + HTTP) against a fresh `--demo` instance. Tokens are masked in
evidence; no probe token appears in any committed file.

- **AuthN/AuthZ:** forged/garbage/empty bearer → 401; wrong token kind rejected in **both**
  directions (admin→agent 401, agent→admin 401); unknown agent token 401; suspended agent 403
  on every agent endpoint; token rotation invalidates the old token immediately; agent tokens
  survive `init --force` (data intact); agent B cannot read/fetch agent A's lease (404) and only
  sees its own leases.
- **Credential isolation:** only `POST /agent/leases/{id}/credential` returns secret material,
  only to the owning active agent; no other endpoint/response exposes credentials, broker
  secret, or other agents' data.
- **Cloud-side enforcement (mock):** mock cloud re-validates signature, token expiry, provider
  mode, live lease status, and IAM policy on every call; `Forbidden.RAM` for out-of-scope
  actions; revoked/expired tokens rejected with Aliyun-shaped 401 codes.
- **Audit chain:** verify OK on clean DB; tampering a copied DB row → verify fails with
  `first_invalid_seq` (endpoint + CLI); the Go store test also covers tamper detection.
- **At-rest/log hygiene:** canary broker secret, broker AK, four mock STS tokens, admin token,
  old admin token and three agent tokens were searched as exact byte strings across
  `csg.db`, `csg.db-wal`, `csg.db-shm`, access log, CLI outputs, all API responses gathered
  during the run, and `web/dist` — 0 hits. The access log contains only
  `method path status duration_ms`.

## 3. Console E2E (A13) — screenshots

`docs/screenshots/`: `01-login.png`, `02-overview-pending-queue.png`, `03-approve-modal.png`,
`04-after-approval-overview.png`, `05-leases.png`, `06-agents.png`, `07-agent-token-once.png`,
`08-capabilities.png`, `09-providers-vault.png`, `10-audit-verify.png`, `11-settings.png`,
`12-responsive-1024.png`. (The agent token shown in `07` is deliberately invalidated by a
token rotation immediately after the screenshot, and the E2E log records that check; the
console never stores agent tokens beyond the one-time modal.)

## 4. Candidate-update note

The Lead replaced candidate `37e53d1` with `a509c1c` mid-verification (vault directory
rename required for the delivery source-identity classifier). `git diff --stat 37e53d1..a509c1c`
shows 9 files: package-directory rename with unchanged Go package/API, import-path and
docs-map updates only. **All evidence in this report is from `a509c1c`** except the two early
`37e53d1` demo runs (`/tmp/csg-verify/demo-run1.log`, `demo-run2.log`), which are not used for
the final verdict; the final demo/full probe/E2E/docs runs were all re-executed on `a509c1c`.

## 5. Findings (none blocking)

| Sev | Finding | Evidence / repro | Assessment |
| --- | --- | --- | --- |
| Low | **`csg init --force` admin-token rotation is not audited.** A forced re-init rotates the admin token but appends no audit event (`audit` table rows = 0 after force; there is also no bootstrap event for the initial admin token). CONTRACT §10 defines no audit action for admin bootstrap/rotation, so this is a contract gap rather than a contract violation; docs do not claim it is audited. | `api-probes.log` line `OBSERVE force-rotation-audit: audit rows before=0 after=0`; verified in `internal/server/init.go` (no audit call in Init) | Low. Recommend defining `admin.token_rotated` / bootstrap audit events in a future contract rev; not required by A1–A16 as written |
| Low | **`POST /admin/capabilities` always creates `enabled=true`**; a caller cannot create a disabled capability in one call (create then PATCH). | `internal/server/admin.go:502` (`in.Enabled = true // creation implies enabled; use PATCH to disable`); behaviour consistent with tooling (PATCH supports `enabled`) | Low/polish. Contract does not specify create-time `enabled`; known owner-reported limitation, confirmed |
| Low | **Approve does not revalidate agent status.** A pending lease of a now-suspended agent can still be approved and minted; the agent is blocked from all agent endpoints (403) so it cannot fetch the credential, but the credential exists encrypted until revoke/expiry. CONTRACT §4 only requires capability-enabled + provider-active revalidation. | `internal/server/leases.go` approve path; A5 suspend tests | Low. Known limitation, consistent with contract; consider contract clarification |
| Info | **Audit timestamps truncated to ms before hashing** (`Time.UTC().Truncate(time.Millisecond)` in `internal/store/audit.go:126`, stored as `time_ms`); the hash covers the truncated time. Two same-ms events are still distinguished by `seq`. | code inspection + schema (`time_ms INTEGER`) | Informational; consistent and verifiable |
| Info | **`csg exec --help` prints a usage error (exit 2)** instead of a help page (its documented form is `csg exec … -- CMD`). Not referenced by README/QUICKSTART as a help command. | `docs-check.log` flags section | CLI polish only |
| Info | **Mock cloud returns `InvalidDomainRecord.NotFound` (404) for unknown records**, while CONTRACT §8.3 lists only the instance/domain not-found codes for its error inventory. Aliyun-shaped and consistent with the delete-record contract in §8.3's table. | `internal/mockcloud/handlers.go`; A6 DNS record flow | Informational; sensible behavior, doc inventory could be completed |

## 6. Independently assessed owner-reported limitations (confirmed)

- **Real Alibaba Cloud STS success path not exercised against a live account** — confirmed:
  in-tree RPC-v1 signer is unit-tested with a golden signature vector (`TestSignatureKnownVector`),
  signed `AssumeRole` request shape against a fake STS `httptest` endpoint
  (`TestAssumeRoleAgainstFakeSTS`), credential/error mapping, validation and transport
  sanitisation. **Live-cloud A3/A11 STS success path: NOT RUN (no cloud account/credentials).**
  README/SECURITY state this honestly.
- **Audit timestamps truncated to ms before hashing** — confirmed (see F4).
- **`POST /admin/capabilities` always creates enabled=true** — confirmed (F2).
- **Approve does not revalidate agent status** — confirmed (F3); contract-consistent.
- **Mock cloud returns `InvalidDomainRecord.NotFound` for unknown records** — confirmed (F6).
- **`make demo` default port 18787** — confirmed (`make demo` healthy-service pre-check rejects a
  busy 18787; used by the documented demo entry point).
- **`--force` rotation not audited** — new observation added as F1 (not listed by owners).

No defect was found in: server-side authorization boundaries, lease state machine, credential
scrubbing on expire/revoke, mock-cloud policy enforcement, cross-agent isolation, audit chain
tamper detection, secret-at-rest/log/bundle hygiene, or demo reproducibility.

## 7. Limitations of this verification / NOT RUN

1. **Live Alibaba Cloud `sts` mode** (real RAM role, real AssumeRole success, real-cloud
   revocation semantics) — NOT RUN: no cloud account or credentials in the verification
   environment; the documented limitation matches. Mitigated by provider unit tests (golden
   signer vector + fake STS endpoint) reviewed and passing.
2. **A2 default listen `127.0.0.1:8787`** — NOT RUN: an unrelated Python service holds port 8787
   on this host; the verifier did not kill non-owned processes. All A2 properties were verified
   on explicit loopback ports (18787/18891/18893).
3. **A16 QUICKSTART real-cloud setup section** — NOT RUN for the same reason as (1); all
   mock/demo and console commands in README/QUICKSTART were executed.
4. Browser E2E ran on the cached Chromium (headless) only; no Safari/Firefox matrix, no
   accessibility (WCAG) audit, no load/performance testing — out of MVP scope.
5. Audit tamper probe: DB-row tamper on a copy; not a test of an attacker with full
   rewrite-and-recompute ability (documented as tamper-evident, not tamper-proof).
6. Production-hardening items (TLS terminator, multi-user SSO, OS-level key separation, network
   exposure) are explicitly out of v0.1 scope and were not tested.

## 8. Overall verdict

**PASS** for the stated v0.1 acceptance scope on the documented verification path
(mock/demo/mock-cloud, loopback): A1–A16 pass with real black-box runs, no blocking defect and
no security hole found; the four low-severity findings above are contract/doc gaps or known
limitations, not acceptance failures. The only NOT-RUN items are environmental
(live Alibaba Cloud STS path + the 8787 default-port check), both explicitly documented as
limitations and neither weakening the verified security properties of the shipped artifact.

Verifier write scope only: `scripts/verify/**`, `docs/screenshots/**`, `docs/VERIFICATION.md`.
No product code, tests or other owners' docs were modified; nothing was committed.
