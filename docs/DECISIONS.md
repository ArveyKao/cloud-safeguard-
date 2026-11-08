# Cloud Safeguard — Architecture Decision Records (v0.1)

Short ADRs for the decisions frozen in [SPEC.md](SPEC.md) and [CONTRACT.md](CONTRACT.md).
Status for all: **Accepted for v0.1**. Changing a decision means changing the contract
(Lead-owned) and recording a superseding ADR here.

Format: context → decision → consequences → alternatives considered.

---

## ADR-001 — Single Go binary, no cloud SDK

**Context.** The deliverable is a self-hosted control plane an engineer can run locally and
verify in minutes. Cloud SDKs add dependency churn, credential-provider magic and a large
surface to review for a security-sensitive product.

**Decision.** One statically linked Go binary `bin/csg` (stdlib + pure-Go SQLite only).
Alibaba Cloud RPC signature v1 (`AssumeRole`, `GetCallerIdentity`) is implemented in-tree.
The web console is embedded in the binary.

**Consequences.**
- Simple deploy/rollback: one file plus a data dir; no service mesh or container needed.
- The STS signer is small, reviewable, and unit-tested against a fake STS endpoint with a
  known signature vector; it is our code, not a dependency.
- We own protocol details: signature quirks, error mapping and API changes are ours to
  maintain. Only Alibaba Cloud is supported (other providers are roadmap work).
- No cgo → trivial cross-platform builds.

**Alternatives.** Alibaba Cloud Go SDK (rejected: dependency surface for one API call);
Node/Python control plane (rejected: distribution complexity, weaker single-binary story);
container-first deployment (rejected for v0.1: HA/K8s is explicitly out of scope).

---

## ADR-002 — SQLite (pure-Go `modernc.org/sqlite`) as the only datastore

**Context.** State is small (a handful of agents, hundreds of leases, append-only audit).
The product is a local self-hosted artifact with no external infrastructure.

**Decision.** SQLite via `modernc.org/sqlite v1.34.5`, one database file in the data dir,
schema migrations in-process (`schema_version=1`). The store is behind the frozen
`store.Store` interface so the persistence engine can be replaced.

**Consequences.**
- Zero extra services to run or secure; backup is an offline copy of the data dir.
- Single writer: no horizontal scaling, no multiple `csg serve` processes per data dir,
  no HA. Fine for intended v0.1 scale; documented as a limit.
- Audit seq/hash computed transactionally in one place — easier to keep correct than a
  distributed log.
- If the product grows, the `Store` interface is the seam for Postgres/cloud SQL.

**Alternatives.** Postgres (rejected: operational burden, contradicts local single-binary
goal); embedded KV like BoltDB (rejected: weaker query/aggregation story for audit/lease
filters, though viable); JSON files (rejected: no transactions, unsafe concurrency).

---

## ADR-003 — JIT STS credentials instead of a credential-free proxy in v0.1

**Context.** The strongest design is a transparent cloud-API proxy: the agent calls `csg`,
`csg` injects the broker credential, and no cloud credential ever reaches the agent. But
agents already use the Alibaba Cloud CLI, Terraform and SDKs (that is the point of letting
an agent manage real infrastructure).

**Decision.** For v0.1, mint short-lived (`900–3600 s` real STS; `5–3600 s` mock), narrowly
scoped STS credentials with an inline session policy and a `csg-<agentID>-<leaseID>`
session name. Implement proxy mode as the P1 roadmap item.

**Consequences.**
- Works with any existing toolchain: credentials are already the standard
  `ALIBABA_CLOUD_ACCESS_KEY_ID/SECRET/SECURITY_TOKEN` env vars.
- Blast radius is bounded by TTL + inline policy + role-policy ceiling + session-name
  attribution, but an exfiltrated STS credential is usable until it expires — the cloud
  cannot revoke one session instantly. Documented residual risk.
- The proxy is the better long-term security posture; keeping the lease/mint pipeline
  behind the `provider.Minter` and credential-envelope contracts keeps that path open.

**Alternatives.** Proxy-only in v0.1 (rejected: incompatible with most real agent
workflows on day one, and the proxy is a larger surface to get right); long-lived scoped
RAM users (rejected: the exact problem being solved); OIDC/federation direct to cloud
(postponed: needs identity-provider work, P2).

---

## ADR-004 — Risk-tiered policy engine: auto-approve, approval queue, deny

**Context.** Two naive extremes fail: full admin (no least privilege) and approving every
command (no automation). The founding pain was that approval friction pushes users back to
full permission.

**Decision.** Every request runs a deterministic ordered rule set (CONTRACT §6) producing
`auto_approve` / `require_approval` / `deny` with per-rule explanations. Defaults:
auto-approve risk ≤ `low` and TTL ≤ `900 s`; human approval above that; break-glass always
human-approved and audited at `critical`. Guardrails are editable and audited.

**Consequences.**
- Routine read-only work is zero-friction (success metric: < 2 s with no human).
- Risky work costs exactly one click (target < 30 s including approval).
- Policy is explainable and testable rule-by-rule; decisions are attributable.
- Risk tiers are coarse: a capability's risk is static, and v0.1 cannot pin grants to
  parameter values (P1).

**Alternatives.** A general policy language/OPA (rejected: overkill for 15 rules and hurts
explainability in the UI); per-command human approval (rejected: kills the product's value);
pure IAM as policy engine (rejected: friction, no lease/agent semantics).

---

## ADR-005 — One-time bearer tokens, hashed at rest

**Context.** Agents are non-human identities that need a simple, universal credential for
HTTP. We need to avoid storing reusable plaintext secrets in the DB.

**Decision.** 32-byte CSPRNG bearers, base64url, distinct prefixes (`csg_agt_`, `csg_adm_`);
only SHA-256 hashes are stored; plaintext is shown exactly once (admin at init, agent at
create/rotate); agent/admin token kinds are separated and server-enforced; rotation
invalidates the old token immediately.

**Consequences.**
- A DB read does not yield usable tokens; leaked hashes cannot be replayed.
- Tokens are bearer credentials: anyone who obtains one has that identity until it is
  rotated/suspended. Short of proxy/SSO, that is inherent.
- Simple to use from any language (one Authorization header), no signing/key distribution.
- Display prefix (`csg_agt_7f3a`) aids support without exposing meaningful entropy.

**Alternatives.** mTLS client certs (rejected: operational friction for local agents, cert
distribution); JWT with server signing keys (rejected: more moving parts, revocation
problems); opaque tokens stored in plaintext (rejected: DB leak = identity theft).

---

## ADR-006 — A built-in mock cloud as a first-class provider mode

**Context.** The full security story (revocation is immediate, least privilege is real)
must be demonstrable and testable without a live cloud account, in CI and on a laptop.
Automated acceptance cannot spend money or depend on network/cloud state.

**Decision.** `mock` mode: the mock provider mints a locally signed (`HMAC-SHA256` with a
key derived from the master key) `cgk1.` token embedding the rendered IAM policy; the
built-in mock cloud validates signature, expiry, live lease state and the policy on every
call. Demo mode seeds it, plus 3 ECS fixtures and 2 DNS zones.

**Consequences.**
- The end-to-end lease → credential → cloud call → audit loop runs offline, deterministically.
- Revocation/expiry are enforced live against the store, which makes the security demo
  honest and instant (unlike real STS).
- It is not a security boundary and must not be exposed or used in production; documents
  repeat this. Mock-only deployments cannot validate real STS behavior.
- Mock token format is frozen so provider, mock cloud and tests agree.

**Alternatives.** Emulating Alibaba Cloud entirely (rejected: unbounded); recording/replay
of real calls (rejected: needs a real account, not deterministic); skipping the demo cloud
and relying on unit mocks (rejected: can't show a real end-to-end loop).

---

## ADR-007 — Hash-chained append-only audit log

**Context.** The product's promise includes accountability: who requested what, who
approved it, which cloud calls used which lease. Existing cloud audit trails cannot do this
attribution.

**Decision.** Append-only audit events with monotonic `seq`, `prev_hash` and
`hash = SHA-256("csg-audit-v1\n" + prev_hash + "\n" + canonical_event_json)`. Verify
endpoint/CLI recomputes the chain. Every security-relevant action (auth, provider,
capability, agent, lease, policy, cloud call) is recorded with non-secret metadata and
severity.

**Consequences.**
- Partial or accidental DB tampering is detectable; lease/agent/cloud actions are
  attributable and reviewable in the console.
- The chain is not a signature and not anchored off-box: an attacker with full DB write
  access can recompute it. Off-box shipping/external anchoring is roadmap.
- No retention policy or export yet; DB backups are the retention mechanism.

**Alternatives.** Plain audit table (rejected: no integrity signal); external append-only
log first (rejected for v0.1: infrastructure burden; roadmap); signed events per actor
(rejected: key management overhead before the basic chain is proven).

---

## ADR-008 — AES-256-GCM envelope vault with master key outside the DB

**Context.** The long-lived broker AccessKey must live somewhere. Storing it plaintext in
the DB would make any DB copy a full account takeover.

**Decision.** AES-256-GCM with a random 12-byte nonce per ciphertext, serialized `v1:` +
base64; AAD binds each ciphertext to its record (`provider/<id>/credential`,
`lease/<id>/credential`); master key is 32 random bytes in `<dataDir>/master.key` (0600),
or injected via `CSG_MASTER_KEY`. Key fingerprint (SHA-256 prefix) is exposed, never the
key.

**Consequences.**
- DB theft alone does not reveal broker/lease credentials; ciphertext cannot be moved
  between rows (AAD mismatch fails).
- Master key and DB must be backed up separately; losing the key loses vault contents
  (recoverable by re-rotating provider credentials), and leaking both compromises the
  vault.
- No external KMS/HSM in v0.1 and no re-key command; rotate-and-reencrypt is manual.

**Alternatives.** Env-only secrets (rejected: no at-rest rotation story, leaks into
process env); external Vault/KMS (rejected for v0.1: deployment burden; P2); encrypting
with the DB-stored key (rejected: no protection).

---

## ADR-009 — Embedded React console in the binary

**Context.** Operators need approvals, rotation, vault status and audit visibility. The
artifact must remain one binary and work offline.

**Decision.** Vite + React + TypeScript, plain CSS, no heavy UI kit or external CDNs/fonts;
`web/dist` is embedded via `web/embed.go` (`web.FS()`); the SPA talks same-origin to
`/api/v1` with the admin token from `localStorage`; a dev mock exists only for local UI
development.

**Consequences.**
- One artifact; console cannot drift from the API version it ships with; offline-capable.
- `make build` requires Node ≥ 20 at build time (not at runtime); the committed `dist`
  keeps `go build`/tests working.
- Console XSS would expose the admin token in `localStorage`; single token, no SSO — see
  security doc.

**Alternatives.** Server-rendered Go templates (rejected: poorer UX for polling dashboards
and approval flows); separate frontend deployment (rejected: two artifacts, CORS, version
skew); hosted SaaS console (rejected: contradicts self-hosted requirement).

---

## ADR-010 — Lease as the central authorization object with an explicit state machine

**Context.** Many designs treat "credentials" as the object to manage. The product promise
is capability-level authorization with explainable decisions and a lifecycle.

**Decision.** `Lease` is persisted for every request (including denials), with a policy
decision, params, TTL, approver/reason fields and optional encrypted credential. Explicit
state machine: `pending → active → expired/revoked`, `pending → denied/expired/revoked`,
`active → failed` on mint error; terminal states are `denied/expired/revoked/failed`.
Revoke/expire/deny always scrub the credential; fetch only for active, unexpired leases;
sweeper every 10 s.

**Consequences.**
- One object explains the entire lifecycle (why granted, by whom, for how long, what
  happened) and is the audit correlation key (`session_name`).
- A durable record exists even for refused requests — useful for security review.
- Credentials are ephemeral secrets behind the lease, never first-class API objects.
- The state machine is small enough for exhaustive tests.

**Alternatives.** Ephemeral lease records (rejected: destroys the accountability trail);
statuses mixed with credential records (rejected: complicates revocation and scrubbing);
event-sourced leases (overkill for v0.1).

---

## ADR-011 — Provider selection: first created `aliyun` provider (no routing in v0.1)

**Context.** The lease needs one provider to mint from, and there may be multiple providers
in the store (e.g. a demo mock provider plus a real one). Multi-cloud/multi-account
routing is not in scope.

**Decision.** Server-side provider selection: the first provider with
`Type == capability.provider_type`, ordered by `created_at ASC`; none → deny reason
`provider_available`. Real use should initialize **without** `--demo` and register a single
real `sts` provider.

**Consequences.**
- Deterministic and simple to reason about; no ambiguous routing logic in v0.1.
- Mixing a mock provider with a real one in the same install is a footgun (the older
  provider wins): initialization guidance avoids it, and production must not use mock.
- Multi-account routing is explicit roadmap work rather than accidental complexity.

**Alternatives.** Route per capability param/tenant (deferred to multi-tenant design);
pick first active provider with fallback (would silently change which account is used —
worse for audit determinism); explicit provider_id per lease request (API/UX complexity
not justified for v0.1).

---

## ADR-012 — Periodic sweeper instead of per-lease timers

**Context.** Leases expire (TTL or pending timeout) and must transition to `expired` with
credentials scrubbed, even if no agent calls in. In-process timers scale poorly and are
lost on restart.

**Decision.** A single goroutine scans pending/active leases every 10 s, expires timed-out
ones, scrubs credentials and appends warning-severity audit events. Expiry is authoritative
in the store and re-checked at credential fetch (and in the mock cloud), so the sweeper
only controls when the status flips, not whether access is possible.

**Consequences.**
- Survives restarts; sweep cost is a bounded scan at v0.1 scale.
- A listing can show `active` for up to ~10 s past expiry; fetch/use is already denied.
- No per-lease timer explosion; debuggable from the DB.
- If the process is down, nothing expires — but nothing serves either; restart resumes.

**Alternatives.** `time.AfterFunc` per lease (rejected: restart-loss, memory growth);
DB scheduled jobs (no external scheduler); lazy expiry only on access (rejected: leaves
credentials/stored secrets lingering and status misleading).

---

## ADR-013 — A single admin token, no human accounts in v0.1

**Context.** The platform needs a human operator identity for approvals, provider
rotation, agent management and audit review. Building user accounts, login flows, RBAC and
SSO is a large product surface that would dominate a security MVP — and get the security
details wrong without users to test them.

**Decision.** One admin bearer token, generated at `csg init` (32-byte CSPRNG,
`csg_adm_` prefix), stored as a SHA-256 hash, shown once, constant-time compared. Rotation
is a local operation: `csg init --force` re-prints a fresh admin token while keeping data.
There are no human accounts, roles, MFA or SSO in v0.1; the reviewer persona is the owner.

**Consequences.**
- The operator experience is trivial: one token pasted into `csg login` or the console.
- Single root-of-control-plane credential: no per-human attribution, no MFA, no way to
  revoke one person without rotating for everyone. The token lives in a password manager
  (and in browser `localStorage` while logged in).
- Fine for a single-operator v0.1; a real team deployment needs the P2 identity work
  (SSO/RBAC/multi-tenant) before the console is exposed beyond a trusted operator.

**Alternatives.** Local user database with password hashing (rejected: extra auth code to
get right, still no SSO); OIDC/SSO from day one (rejected: external IdP setup contradicts
local demo goal; P2); CLI-only approvals with no console (rejected: one-click approval is
part of the product's value).

---

## How decisions change

1. Propose the change to the Lead (contract/persistence/security changes affect SPEC or
   CONTRACT).
2. If accepted, update `docs/CONTRACT.md` / `docs/SPEC.md` first (the normative source),
   then code, tests and these ADRs in the same change.
3. Mark the old ADR "Superseded by ADR-NNN"; do not silently rewrite history.
4. Any change touching credential handling, audit integrity or policy semantics needs an
   independent review — these are the product's security promises.
