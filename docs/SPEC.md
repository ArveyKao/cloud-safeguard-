# Cloud Safeguard — Product & Delivery Specification (MVP v0.1)

Status: frozen for the v0.1 build. Owner: Lead. Date: 2026-11-08.
Canonical implementation contract: [`docs/CONTRACT.md`](CONTRACT.md). Shared Go types:
`internal/model/model.go`. Owners map: §8.

---

## 1. Why this product exists

An AI coding agent (Claude Code, Cursor, Codex, DSH, …) can now operate a real cloud
account: create DNS records, rotate certificates, restart ECS instances, open security
groups. The convenient way to enable that is to hand the agent **one long-lived
AK/SK pair with broad permissions**. That is how the founding user's own setup worked
until it became a problem:

- The broker AccessKey was copied into **two places on a server** (`~/.aliyun/config.json`
  for the Alibaba Cloud CLI and `~/.acme.sh/account.conf` for certificate DNS-01 renewals),
  plus the agent's own tooling. Rotating it means finding and editing every copy.
  Miss one = silently broken certificate renewal months later.
- The only thing that avoided endless IAM fiddling was `AdministratorAccess`. One leaked
  key (agent logs, a pasted transcript, a compromised host) is a **full account takeover**.
- The cloud's native audit trail (ActionTrail) shows *a* RAM user did something; it does
  not show **which agent, which task, which approved intent**.
- Every new task ("add this TXT record", "restart that instance") triggers a manual
  permission-granting loop: console → RAM policy → wait → test → repeat. Slow enough
  that everyone gives up and goes back to full admin.

**The real tension is not "credentials vs no credentials". It is convenience vs least
privilege vs accountability.** Existing tools force a choice:

| Approach | Convenience | Least privilege | Audit / revocation | Verdict |
| --- | --- | --- | --- | --- |
| Full-admin AK/SK handed to agents | High | None | Cloud-level only | Fast until it isn't; unacceptable blast radius |
| One RAM user + policy per task | Low (heavy setup each time) | Good | Weak attribution | Friction pushes people back to admin |
| Human approves every shell command | Very low | Good | Chat logs | Agent becomes useless |
| **JIT credential broker (this product)** | **High** (auto-grant low risk) | **Good** (per-lease scoped STS) | **Strong** (per-agent, per-lease, tamper-evident) | **Chosen** |

### The insight

Agents do not need credentials. Agents need **capabilities**: a named, least-privilege
permission bundle, for a specific resource, for a short time, with a reason and an
approval trail. The long-lived AK/SK should live in exactly one place — an encrypted
vault inside a control plane — and be used only to mint **short-lived, narrowly scoped**
credentials (Alibaba Cloud STS `AssumeRole` with an inline policy). Low-risk capabilities
are granted instantly by policy; risky ones wait for one-click human approval; everything
is auditable and revocable.

Product tagline: **“Capabilities, not credentials.”**

## 2. Product definition

**Cloud Safeguard** is a self-hosted control plane that sits between AI agents and cloud
accounts. It is the authority layer for non-human cloud access.

### Personas

- **Owner / operator** — the human (Arvey). Holds the long-lived cloud AccessKey once,
  defines guardrails, approves risky requests from a console, rotates credentials in one
  place, reads the audit trail.
- **Agent** — an AI worker (Claude Code, Cursor, DSH, a CI bot). Authenticates with its own
  scoped agent token, requests capabilities, receives short-lived credentials, does work.
- **Reviewer** — the person who approves. In v0.1 this is the same human as the owner.

### Core concepts

| Concept | Meaning |
| --- | --- |
| **Provider** | A cloud account (Alibaba Cloud) wired in with one encrypted broker AccessKey + a RAM role. Modes: `sts` (real cloud) or `mock` (built-in demo cloud). |
| **Capability** | Named least-privilege permission bundle with a risk tier, a parameterized IAM policy template, and TTL limits. Example: `aliyun.dns.manage` scoped to one domain. |
| **Agent** | Non-human identity with a one-time-shown bearer token, granted capability IDs, and per-agent TTL / concurrency limits. |
| **Lease** | The central object: an agent's request for a capability for N minutes with a reason. Policy engine returns auto-approve / require-approval / deny with explainable reasons. Active leases hold one encrypted short-lived credential. |
| **Approval** | Human decision on a pending lease, from the console or CLI, with optional TTL and note. |
| **Audit event** | Append-only, hash-chained record of every security-relevant action, including each mock-cloud API call. |
| **Vault** | AES-256-GCM envelope encryption for the broker AccessKey and lease credentials, keyed by a master key stored outside the database. |

### Promised outcomes

1. **No long-lived cloud credential outside the vault.** Agents and hosts only ever see
   short-lived STS credentials, or nothing (agent tokens are platform tokens, not cloud keys).
2. **One-click (or zero-click) least privilege.** Read-only work is auto-approved in
   milliseconds; risky work takes one console approval, not a RAM-console session.
3. **Automatic expiry + instant revocation.** Every lease dies on its TTL; revoking an
   agent or lease kills access immediately (mock mode enforces it live; real STS mode
   denies renewal and requires role-policy rotation — see security doc).
4. **Accountability.** Every request, decision, issuance, fetch, revoke and cloud API call
   is attributable to an agent + lease, and the audit log is tamper-evident.
5. **One-place rotation.** Rotate the broker AccessKey once in the console; no agent,
   script, server or cron entry needs to change.

### Key user journeys (must work in the demo)

- **J1 — Zero-friction read:** agent requests `aliyun.cloud.read`; auto-approved; credential
  fetched; mock cloud list succeeds; a write call with the same credential is `403`.
- **J2 — One-click risky change:** agent requests `aliyun.dns.manage` for `arveykao.com`;
  pending; operator approves in console; agent adds a record; an ECS restart with the same
  credential is `403`.
- **J3 — Refusal:** agent has no grant for a capability → immediate durable denial with an
  explainable reason, no credentials.
- **J4 — Break-glass:** agent requests `aliyun.iam.break_glass`; requires `break_glass:true`
  + human approval; audit marked critical; operator revokes; credential dies immediately.
- **J5 — Rotation:** operator rotates the provider credential once; existing agents keep
  working with no changes; rotation is audited.

## 3. Scope

### In scope for v0.1 (this delivery)

- Single Go binary `csg`: `init`, `serve`, agent CLI, admin CLI.
- Single-tenant control plane: SQLite store, AES-256-GCM vault, master key file 0600 or
  env override.
- Alibaba Cloud provider in two modes:
  - `sts`: real `AssumeRole` with inline scoped policy + broker RAM AccessKey (RPC
    signature v1 implemented in-tree, no cloud SDK dependency).
  - `mock`: locally signed short-lived tokens accepted by the built-in mock cloud, which
    enforces the same policy document. Full demo/test path without cloud access.
- Built-in capability catalog (5 capabilities, exact definitions in CONTRACT §7).
- Risk-based policy engine with explainable decisions + guardrail settings editable from
  the console.
- Human approval queue; agent/admin bearer tokens; per-agent limits; lease expiry sweeper;
  revoke; credential scrubbing.
- Tamper-evident hash-chained audit log + verification.
- Web console (React + Vite, embedded in binary): login, overview, approvals, leases,
  agents, capabilities, providers/vault, audit, policy settings.
- End-to-end demo script + Go unit/integration tests + docs.

### Explicitly out of scope (v0.1)

- Multi-tenant / SaaS, user accounts, SSO, RBAC for humans, email/Slack/Feishu approval
  (roadmap P2; chat-on-call hook should be noted as an extension point).
- Kubernetes/Helm deployment, HA, external database, external KMS/Vault/HSM integration.
- **Credential-free proxy mode** where agents never see even STS tokens (P1, see §4.4).
- Cloud providers other than Alibaba Cloud; automatic policy generation from ActionTrail.
- Per-parameter grant constraints (an agent granted `aliyun.dns.manage` may pass any valid
  domain param; P1 adds `grant.params` constraints).
- Billing, license enforcement, marketplace.

## 4. Architecture

### 4.1 Components (single binary, single process)

```
┌───────────────────────────── humans & agents ─────────────────────────────┐
│  Web console (React, embedded)        csg CLI (agent side / admin side)    │
└───────────────────────────────┬───────────────────────────────┬───────────┘
                                │ HTTPS/HTTP + Bearer token     │
┌───────────────────────────────▼───────────────────────────────▼───────────┐
│                         csg control plane (Go)                            │
│  HTTP API (agent + admin)   policy engine   lease manager   sweeper       │
│  audit hash-chain writer    mock cloud API  static dashboard              │
│  ┌───────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐ │
│  │ vault (AES)   │  │ SQLite store     │  │ provider minters            │ │
│  │ secrets at    │  │ agents/caps/     │  │  aliyun STS (real)          │ │
│  │ rest          │  │ leases/audit     │  │  mock STS (HMAC token)      │ │
│  └───────────────┘  └──────────────────┘  └──────────────┬──────────────┘ │
└───────────────────────────────────────────────────────────┼───────────────┘
                                                            │ AssumeRole + inline policy
                                                   ┌────────▼─────────────┐
                                                   │ Alibaba Cloud STS/   │
                                                   │ RAM role + resources │
                                                   └──────────────────────┘
```

Package map (see §8 for owners): `internal/model` (shared types), `internal/store`
(SQLite), `internal/vaultcrypto` (Go package `vault`), `internal/policy`, `internal/audit` (hash chain; may
live in store), `internal/server` (HTTP + sweeper + bootstrap), `internal/provider`
(aliyun STS / mock), `internal/capcatalog`, `internal/mockcloud`, `internal/token`,
`internal/cli`, `cmd/csg`, `web/` (React console embedded via `web.FS()`).

### 4.2 Lease flows

**Auto-approve (J1):**
1. Agent `POST /api/v1/agent/leases` with capability + params + reason.
2. Server authenticates agent token, loads capability/provider, validates params.
3. Policy engine: grant present, agent active, provider active, TTL within limits, reason
   present, no rate/concurrency violation, risk ≤ auto-approve threshold, TTL ≤ auto TTL
   → `auto_approve`.
4. Lease manager renders policy JSON (`capcatalog.RenderPolicy`), mints credential via
   provider (`provider.Mint`), stores it encrypted with AAD `lease/<id>/credential`,
   marks lease active with `issued_at`/`expires_at`, records `lease.requested` +
   `lease.auto_approved` + `lease.credential_issued` audit events, returns lease.
5. Agent `POST .../credential` → one audit event per fetch → uses STS token against cloud
   (or mock cloud) until `expires_at`.

**Human approval (J2):**
1–2. Same; policy returns `require_approval` → lease `pending` + audit `lease.requested`.
3. Operator reviews pending lease in console (risk, params, reason, requested TTL) and
   approves with optional TTL + note (`POST /admin/leases/{id}/approve`).
4. Server revalidates limits, mints, marks active, audits `lease.approved` +
   `lease.credential_issued`.
5. Agent polls lease (or CLI `--wait`) and fetches credential.

**Expiry/revocation:** background sweeper every 10s expires timed-out pending leases and
past-TTL active leases, scrubs credential ciphertext, audits `lease.expired`. Revoke is
immediate: status `revoked`, credential scrubbed, mock cloud validates lease state on
every call → instant 401 in demo; real STS mode is documented residual risk.

### 4.3 Audit chain

Every security-relevant action appends an event with `seq` (monotonic), `prev_hash`,
`hash = SHA-256("csg-audit-v1\n" + prev_hash + "\n" + canonical_event_json)`.
`GET /admin/audit/verify` recomputes the chain and reports the first invalid seq.
Full formula + event catalog: CONTRACT §10.

### 4.4 Why STS tokens instead of a credential-free proxy (MVP)

The strongest design is a transparent cloud-API proxy: agent talks to `csg`, `csg` injects
the broker credential, so no cloud credential ever reaches the agent. That is the P1
direction. For v0.1 we issue **short-lived, scoped STS credentials** because it keeps the
product usable with any existing Alibaba Cloud CLI/SDK (`aliyun`, Terraform, SDKs) and the
blast radius is already bounded by TTL + inline policy + session name + audit. Residual
risks and the proxy roadmap are documented in `docs/SECURITY.md`.

## 5. Security model (summary)

Guarantees: broker AK/SK encrypted at rest and never returned by the API; agents hold
platform tokens only; STS credentials are policy-scoped, TTL-bounded, attributable via
`RoleSessionName` and revocable/renewal-deniable; full audit chain; secrets never logged.

Residual risks (documented, not hand-waved): an exfiltrated *agent token* can request
leases within that agent's grants until revoked; an exfiltrated *STS credential* is usable
until its short expiry (real cloud cannot revoke a single STS session instantly); the
master key on disk protects at-rest secrets only; mock mode is for demo/testing and is not
a security boundary; admin token is a root credential for the control plane.
Hardening checklist and rotation runbook: `docs/SECURITY.md`.

## 6. Demo and acceptance criteria

### 6.1 Exact demo environment

- macOS (this machine), repo `/Users/arveykao/code/cloud-safeguard`.
- Go 1.24+, Node 20+ (local: Go 1.24.4, Node 26.7), no real cloud credentials needed.
- `make demo` (i.e. `./scripts/demo.sh --port 18787 --data-dir .demo/data`) creates a
  throwaway data dir, `csg init --demo`, starts `csg serve` on `127.0.0.1:18787`, runs
  S1–S8, prints `PASS`/`FAIL` lines, exits 0 on all-pass, cleans up the server process.
- Manual demo: `make build && ./bin/csg init --demo --data-dir .demo/data && ./bin/csg serve --data-dir .demo/data --addr 127.0.0.1:18787`, then open
  `http://127.0.0.1:18787` and log in with the printed admin token.

### 6.2 Demo scenarios (all must pass end-to-end)

| # | Scenario | Expected observable result |
| --- | --- | --- |
| S1 | `claude-code` requests `aliyun.cloud.read`, reason given | HTTP 201, lease `active`, decision `auto_approve` with reasons; credential fetch returns `ALIBABA_CLOUD_SECURITY_TOKEN`; mock cloud `GET /v1/ecs/instances` → 200 |
| S2 | Same credential attempts `POST /v1/ecs/instances/i-2ze0demo001/restart` | 403 `Forbidden.RAM` (write action not in read policy) |
| S3 | `claude-code` requests `aliyun.dns.manage` domain=`arveykao.com`, ttl=10m | lease `pending`, decision `require_approval`; no credential yet |
| S4 | Operator approves S3 via CLI with note | lease becomes `active`; agent fetches credential; `POST /v1/dns/zones/arveykao.com/records` → 200; ECS restart → 403 |
| S5 | Operator denies a second DNS lease | lease `denied`; credential fetch returns `409/410`; audit contains request + denial |
| S6 | `hermes-researcher` (only `aliyun.cloud.read`) requests `aliyun.ecs.instance.ops` | lease `denied` immediately, reason rule `capability_not_granted`, no credential possible |
| S7 | `claude-code` requests `aliyun.iam.break_glass` without `--break-glass` then with it | first `denied` rule `break_glass_required`; second `pending`; after approval audit severity `critical`; after revoke mock cloud returns 401 for the previously working token |
| S8 | Operator runs `csg audit verify` | `ok=true`, event count > 0 |

### 6.3 Acceptance criteria (verifier must test each independently)

| # | Criterion |
| --- | --- |
| A1 | `csg init --demo --json` creates data dir with 0700 perms, `master.key` 0600, SQLite DB, admin token, 5 built-in capabilities, 1 mock provider, 2 demo agents; tokens shown exactly once; refuses to re-init without `--force`. |
| A2 | `make build` produces `bin/csg`; `csg serve` serves `/healthz`, `/api/v1/...`, and the real built dashboard at `/`; graceful shutdown on SIGINT. |
| A3 | Auto-approve flow (S1) works end-to-end via CLI and returns an Alibaba-Cloud-shaped STS env. |
| A4 | Least privilege holds: out-of-policy action with a valid credential → 403 (S2/S4); TTL/limits are enforced (over-limit request denied with explicit reason; sweeper expires leases). |
| A5 | Enforcement is server-side: duplicate/forged/expired/revoked mock tokens are rejected 401; admin routes reject agent tokens and vice versa; agent B cannot read agent A's leases (404). |
| A6 | Human approval (S4) and denial (S5) work from **both** CLI and web console, with audit trail. |
| A7 | Audit chain verifies on a clean DB and verification fails after a row is tampered with (Go test). |
| A8 | No plaintext broker secret, STS secret or agent token appears in the SQLite DB files, server access logs, HTTP responses for other objects, or the JS bundle (test/scan). |
| A9 | Vault encrypts broker credentials; wrong AAD fails to decrypt; provider credential never returned by any API. |
| A10 | Policy settings are editable and effective (e.g. auto-approve medium → medium lease auto-approves), invalid settings rejected 400, change audited. |
| A11 | Provider credential rotation works, is audited, old lease credentials are unaffected, new leases mint with new credential, no agent changes needed. |
| A12 | Agent token rotation invalidates the old token; suspend blocks the agent; limits (concurrency + per-minute) enforced with explicit reasons. |
| A13 | Web console: login with admin token, overview loads real counts, approve a pending lease from the UI (verifier E2E), agent creation shows token once, audit page verifies chain; no uncaught console errors on main pages. |
| A14 | `make test` passes (`go test ./...`), `go vet ./...` clean, web `npm run build` + typecheck pass. |
| A15 | Demo script S1–S8 passes reproducibly from a clean data dir and leaves no server process running. |
| A16 | Docs are accurate: every command in README/QUICKSTART runs; PRODUCT/SECURITY/ARCHITECTURE match the shipped behavior and honestly list limitations. |

## 7. Success metric

For an agent needing read-only access, time-to-credential < 2 s with zero human actions.
For a scoped write, time-to-credential < 30 s including human approval.
For the operator, credential rotation = one command/console action and zero agent changes.
Security: zero long-lived cloud credentials outside the vault, 100% of lease requests and
cloud API calls attributable in the audit chain. **v0.1 is accepted only if A1–A16 pass.**

## 8. Ownership, base commit, and working agreement

| Owner (teammate) | Write scope | Deliverables |
| --- | --- | --- |
| **lead** | `docs/SPEC.md`, `docs/CONTRACT.md`, `Makefile`, `go.mod`, `go.sum`, `web/embed.go`, `.agent/**`, final integration commits | Frozen contract, shared types, integration, final verification, report |
| **core-api** | `internal/store/**`, `internal/vaultcrypto/**`, `internal/policy/**`, `internal/server/**`, additive changes to `internal/model/**` (only via Lead) | Store+vault+policy+audit+HTTP API+sweeper+Init+demo seed; unit/integration tests |
| **agent-toolkit** | `internal/provider/**`, `internal/capcatalog/**`, `internal/mockcloud/**`, `internal/cli/**`, `cmd/csg/**`, `scripts/demo.sh` | Aliyun STS signer + mock provider + catalog + mock cloud + full CLI + demo script + tests |
| **console-ui** | `web/**` (except `web/embed.go`), `web/dist/**` | React dashboard (all pages), API client, design system, build passes, mock-server for local dev |
| **product-docs** | `README.md`, `docs/PRODUCT.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/QUICKSTART.md`, `docs/API.md`, `docs/DECISIONS.md` | Product narrative (problem → platform → value/roadmap), security model, architecture, accurate quickstart/API docs |
| **verifier** (spawned after build) | `scripts/verify/**`, `docs/VERIFICATION.md` (report only; no product-code edits) | Independent black-box verification of A1–A16, security probes, Playwright UI E2E + screenshots, docs accuracy, PASS/FAIL evidence |

Working agreement:
- Frozen exported signatures in `internal/model`, `internal/store` (Store interface), `internal/vaultcrypto`, `internal/provider`, `internal/capcatalog`, `internal/mockcloud`, `internal/server` must be kept; replace stub files, add files freely. Contract changes go through Lead.
- Only Lead edits `go.mod`/`go.sum`; if a dependency is truly needed, message Lead. The target is stdlib + `modernc.org/sqlite` only.
- Teammates use their own ports/data dirs for local runs: core-api `:18801`, agent-toolkit `:18802`, console-ui Vite `:18803`; demo/verifier `:18787`. Kill your own processes after testing.
- Teammates do not run `git commit`, do not touch other owners' files, and do not ask the user anything; message Lead with progress, blockers, or contract gaps.
- Definition of done per owner: their packages compile (`go build ./...`), their tests pass (`go test ./...`), no secrets in code/logs, demo path works for their surface, and a completion report (files, commands, evidence, limitations) is sent to Lead.
- Evidence discipline: report exact commands + observed output; never claim a check that was not run. Verifier findings are routed to owners; Lead reruns the combined checks.

## 9. Defaults and decisions frozen for the build

- Product name Cloud Safeguard, module `github.com/arveykao/cloud-safeguard`, version `0.1.0`.
- Default listen: `127.0.0.1:8787` (loopback only); data dir default `./data` for the binary,
  `.demo/data` for the demo.
- SQLite via `modernc.org/sqlite v1.34.5` (pure Go, pinned; Go 1.24.4).
- Tokens: 32-byte CSPRNG, base64url, prefixes `csg_agt_` / `csg_adm_`, SHA-256 hashed at rest.
- Master key: 32 bytes, `<dataDir>/master.key` mode 0600, or `CSG_MASTER_KEY` (base64).
- Identifiers: `prv_` provider, `cap_` capability, `agt_` agent, `lea_` lease, `evt_` audit.
- All timestamps stored UTC (unix milliseconds in SQLite, RFC3339 in JSON).
- Built-in capabilities/TTL/risk, policy defaults, mock fixtures, API details, audit format,
  CLI flags: **CONTRACT.md is normative**.
