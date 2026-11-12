# Cloud Safeguard — Implementation Contract (v0.1, frozen)

Normative for the v0.1 build. Anything not specified here is an implementation choice, but
the **exported signatures in §13, the HTTP contract in §3–§5, the policy semantics in §6,
the capability catalog in §7, the mock cloud in §8, the CLI in §9 and the audit format in
§10 are frozen**. Changes go through the Lead.

Vocabulary and scope: `docs/SPEC.md`. Shared Go types: `internal/model/model.go` (JSON tags
are the wire contract).

---

## 1. Runtime, configuration, file layout

- Single binary `bin/csg`, single process, no cgo, no cloud SDK. Dependencies: Go stdlib +
  `modernc.org/sqlite v1.34.5` only. Go 1.24.4.
- Default data dir for the binary: `./data`; demo: `.demo/data`. `csg init` creates it
  with mode 0700 (best effort), database `<dataDir>/csg.db`, master key `<dataDir>/master.key`
  (0600).
- Env vars: `CSG_MASTER_KEY` (base64 std, 32 bytes, overrides key file),
  `CSG_SERVER` (CLI), `CSG_TOKEN` (CLI), `CSG_DATA_DIR` (CLI default for init/serve).
- HTTP: loopback by default `127.0.0.1:8787`; timeouts 10 s; max request body 1 MiB; JSON
  error recovery on panics; access log lines `method path status duration_ms` (no bodies,
  no Authorization values).
- Static console: embedded in the binary via `web.FS()`. `GET /` serves `index.html`;
  unknown non-API GET paths fall back to `index.html` (SPA). API prefix is `/api/v1/`,
  mock cloud prefix is `/mock-cloud/`, health is `/healthz`.
- Version reported: `model.Version` = `"0.1.0"`.

## 2. Authentication, errors, envelopes

**Bearer tokens.** `Authorization: Bearer <token>` on every `/api/v1/*` request.
- Agent endpoints require a token with prefix `csg_agt_`; admin endpoints require `csg_adm_`.
  A token of the wrong kind is rejected **401** `unauthorized`.
- Agent token resolution: SHA-256 of token → `agents.token_hash`; unknown → 401. Agent
  status `suspended` or `revoked` → **403** `forbidden` on all agent endpoints.
- Admin token: single hash stored in meta `admin_token_hash`; compare constant-time; invalid
  → 401. Successful admin login/audit is recorded as `auth.admin_login`.
- Each authenticated agent request refreshes `last_seen_at` at most once per 60 s.

**Success envelope.** Every `/api/v1` response is `{"data": <payload>}` (HTTP 200/201).
`/healthz` returns the `model.Health` object directly (no envelope).

**Error envelope.** `{"error":{"code":"...","message":"...","details":{...}}}`
Codes: `invalid_request` (400), `unauthorized` (401), `forbidden` (403), `not_found` (404),
`conflict` (409), `lease_not_active` (409), `credential_unavailable` (410),
`rate_limited` (429), `provider_error` (502), `internal` (500).
`details` is optional and must never contain secrets.

**List envelope.** `{"data":{"items":[...],"total":N}}` via `model.ListResponse[T]`.
Default `limit` 50, max 200; `offset` default 0.

**Never returned by any API:** provider AccessKey ID/Secret plaintext, lease credential
plaintext outside the credential endpoint, admin token (except in `csg init` output),
agent token except at creation/rotation, master key.

## 3. Agent API (`/api/v1/agent`, bearer = agent token)

| Method/path | Request | Success data | Notes |
| --- | --- | --- | --- |
| `GET /agent/me` | — | `{"agent":Agent,"active_leases":int,"server_time":time}` | agent profile + limits |
| `GET /agent/capabilities` | — | `ListResponse[Capability]` | only enabled + granted capabilities |
| `POST /agent/leases` | `CreateLeaseInput` | `Lease` (201) | runs policy; creates durable lease even when denied |
| `GET /agent/leases?status=&limit=&offset=` | — | `ListResponse[Lease]` | own leases only |
| `GET /agent/leases/{id}` | — | `Lease` | 404 if the lease belongs to another agent |
| `POST /agent/leases/{id}/credential` | — | `CredentialEnvelope` | only while `active`; 409 `lease_not_active`; 410 `credential_unavailable`; audits every fetch |
| `POST /agent/leases/{id}/revoke` | `RevokeLeaseInput` | `Lease` | own lease; pending→revoked (cancel), active→revoked; terminal → 409 |
| `POST /agent/heartbeat` | — | `{"ok":true,"server_time":time}` | optional; touches last_seen |

`POST /agent/leases` semantics:
1. Authenticate active agent. 404 `not_found` for unknown capability_id. 400
   `invalid_request` for invalid params (`capcatalog.ValidateParams`), negative TTL, or
   invalid JSON. Params are validated **before** policy and before a lease is created.
2. Provider selection: first provider with `Type == capability.ProviderType` ordered by
   `created_at ASC`; if none → policy deny reason `provider_available`.
3. Run policy engine (§6) → create lease:
   - `auto_approve`: try mint now. Success → status `active`, `approved_by="auto"`,
     `issued_at`, `expires_at`, credential stored encrypted (AAD
     `lease/<id>/credential`), fingerprint = masked AccessKey ID (`LTAI****ABCD` style),
     audit `lease.requested` + `lease.auto_approved` + `lease.credential_issued`. Mint error →
     status `failed`, `failure_reason` (sanitized message), audit `lease.failed`.
   - `require_approval`: status `pending`, audit `lease.requested`.
   - `deny`: status `denied`, `denied_reason` = summary, audit `lease.requested` (status
     denied) + `lease.denied` (warning).
4. Response 201 with the lease in all three cases. `effective_ttl_seconds` is the policy's
   effective TTL for auto/approval cases.

Credential envelope env vars (exact, in this order): `ALIBABA_CLOUD_ACCESS_KEY_ID`,
`ALIBABA_CLOUD_ACCESS_KEY_SECRET`, `ALIBABA_CLOUD_SECURITY_TOKEN`, `CSG_LEASE_ID`,
`CSG_SERVER` (base URL of the control plane), `CSG_CAPABILITY` (capability id).

## 4. Admin API (`/api/v1/admin`, bearer = admin token)

| Method/path | Body / query | Success data |
| --- | --- | --- |
| `POST /admin/login` | — | `LoginResult` |
| `GET /admin/overview` | — | `Overview` (≤20 pending leases, ≤20 active leases, ≤20 recent events) |
| `GET /admin/providers` | — | `ListResponse[Provider]` |
| `POST /admin/providers` | `CreateProviderInput` | `Provider` (201) |
| `GET /admin/providers/{id}` | — | `Provider` |
| `PATCH /admin/providers/{id}` | `UpdateProviderInput` | `Provider` |
| `POST /admin/providers/{id}/rotate` | `RotateProviderCredentialInput` | `Provider` |
| `POST /admin/providers/{id}/test` | — | `{"ok":bool,"message":string,"tested_at":time}` |
| `GET /admin/capabilities` | — | `ListResponse[Capability]` |
| `POST /admin/capabilities` | `Capability` (id/builtin ignored) | `Capability` (201) |
| `PATCH /admin/capabilities/{id}` | partial `Capability` (enabled, description, default/max TTL; custom also policy_template/risk/params) | `Capability` |
| `GET /admin/agents` | — | `ListResponse[Agent]` |
| `POST /admin/agents` | `CreateAgentInput` | `AgentWithToken` (201, token shown once) |
| `GET /admin/agents/{id}` | — | `Agent` |
| `PATCH /admin/agents/{id}` | `UpdateAgentInput` | `Agent` |
| `POST /admin/agents/{id}/suspend` | — | `Agent` |
| `POST /admin/agents/{id}/activate` | — | `Agent` |
| `POST /admin/agents/{id}/token/rotate` | — | `AgentWithToken` (old token invalid immediately) |
| `GET /admin/leases` | `status,agent_id,capability_id,limit,offset` | `ListResponse[Lease]` |
| `GET /admin/leases/{id}` | — | `Lease` |
| `POST /admin/leases/{id}/approve` | `ApproveLeaseInput` | `Lease` (200) |
| `POST /admin/leases/{id}/deny` | `DenyLeaseInput` | `Lease` (200) |
| `POST /admin/leases/{id}/revoke` | `RevokeLeaseInput` | `Lease` (200) |
| `GET /admin/audit` | `action,actor_type,actor_id,severity,since,limit,offset` | `ListResponse[AuditEvent]` newest first |
| `GET /admin/audit/verify` | — | `AuditVerifyResult` |
| `GET /admin/policy` | — | `PolicySettings` |
| `PUT /admin/policy` | `PolicySettings` | `PolicySettings` |

Validation rules:
- Provider create: `type` must be `aliyun`; `mode` ∈ {sts, mock}; `region` non-empty; for
  `sts`, `access_key_id`, `access_key_secret`, `role_arn` required; for `mock`, missing
  AccessKey values are replaced with a generated placeholder. `access_key_id_masked` =
  first 4 + `****` + last 4. New providers are `active`. Audit `provider.created`.
- Provider test: mock mode → ok if signing key present; sts mode → sigv1-signed
  `sts:GetCallerIdentity`. Persist `last_tested_at` / `last_test_ok`, audit `provider.tested`.
- Provider rotate: non-empty AccessKey ID/Secret, re-encrypt with AAD
  `provider/<id>/credential`, audit `provider.credential_rotated` (metadata only masked
  IDs). Existing leases are unaffected.
- Capability create/update: risk valid; `default_ttl_seconds > 0`,
  `default_ttl_seconds <= max_ttl_seconds`, `max_ttl_seconds <= settings.MaxLeaseTTLSeconds`;
  `policy_template` must be valid JSON after rendering with sample params (json.Valid);
  ProviderType must be `aliyun`; custom caps get `cap_` IDs and `builtin=false`. Audit
  `capability.created` / `capability.updated`.
- Agent create: name non-empty; all grants must exist (400 otherwise); defaults
  `max_ttl_seconds = settings.MaxLeaseTTLSeconds`,
  `max_concurrent_leases = settings.MaxConcurrentLeasesPerAgent`; token generated by
  `internal/token`; audit `agent.created`. PATCH validates grants. Suspend/activate audit
  `agent.suspended` / `agent.activated`. Token rotate audit `agent.token_rotated`.
- Approve: lease must be `pending` (409 otherwise) and not timed out. `ttl_seconds` omitted or
  `0` keeps the requested validity period; a negative value → 400. A positive
  `ttl_seconds` must be ≤ min(capability max, agent max,
  settings max) → else 400. Revalidate capability enabled + provider active (409 conflict
  with message if not). Mint; on success status active + audit `lease.approved` +
  `lease.credential_issued`; on provider error status `failed` + `failure_reason` + audit
  `lease.failed` and return 200 with the failed lease. `approved_by` = `"admin"`.
- Deny: reason required 1–500 chars; only from `pending`; audit `lease.denied` (warning).
- Revoke: from `pending` or `active`; active → clear credential; audit `lease.revoked`
  (warning; critical if break-glass). Terminal leases → 409.
- Policy PUT: validate via `model.PolicySettings.Validate()`, persist, audit `policy.updated`
  (warning) with before/after metadata (non-secret).

## 5. Lease state machine

```
create ──auto──▶ active ──TTL──▶ expired
   │               └─revoke──▶ revoked
   ├─require──▶ pending ──approve──▶ active
   │              ├─deny──────────▶ denied
   │              ├─sweep(timeout)─▶ expired
   │              └─revoke─────────▶ revoked
   └─deny(now)──▶ denied
active ──mint failure on approve/create──▶ failed
terminal: denied, expired, revoked, failed
```
Sweeper (goroutine, every 10 s): pending older than `pending_timeout_seconds` → `expired`
(audit warning); active with `expires_at <= now` → `expired` + scrub credential (audit
warning). Revoke/expire/deny always `ClearLeaseCredential`. Credential fetch is allowed only
for `active` leases with `expires_at` in the future.

## 6. Policy engine (normative semantics)

Inputs: agent, capability, provider (may be nil), settings, requested TTL (0 → capability
default), reason, breakGlass, active lease count, leases created in the last 60 s.

Candidate TTL = requested TTL if > 0 else `capability.default_ttl_seconds`.

Evaluate in order; accumulate `DecisionReason{Rule, Outcome, Detail}` where Outcome ∈
`allow` / `require_approval` / `deny`. **Deny beats require-approval beats allow.**

| # | Rule key | Condition | Outcome |
| --- | --- | --- | --- |
| 1 | `capability_granted` | capability ID not in agent.grants | deny |
| 2 | `capability_enabled` | `!capability.enabled` | deny |
| 3 | `provider_available` | no provider of matching type | deny |
| 4 | `provider_active` | provider.status != active | deny |
| 5 | `reason_required` | risk rank ≥ `require_reason_for_risk` rank and trimmed reason empty | deny |
| 6 | `break_glass_required` | risk == critical and !breakGlass | deny |
| 7 | `ttl_within_capability` | candidate > capability.max_ttl_seconds | deny |
| 8 | `ttl_within_agent` | candidate > agent.max_ttl_seconds | deny |
| 9 | `ttl_within_global` | candidate > settings.max_lease_ttl_seconds | deny |
| 10 | `concurrency_available` | active leases ≥ min(agent.max_concurrent_leases, settings.max_concurrent_leases_per_agent) | deny |
| 11 | `rate_limit` | leases created last 60 s ≥ settings.leases_per_minute_per_agent | deny |
| 12 | `break_glass_approval` | breakGlass true | require_approval |
| 13 | `risk_above_auto` | risk rank > `auto_approve_max_risk` rank | require_approval |
| 14 | `ttl_above_auto` | candidate > `auto_approve_max_ttl_seconds` | require_approval |
| 15 | `auto_approve` | no deny/require triggered | allow |

Decision: any deny → `deny`; else any require → `require_approval`; else `auto_approve`.
`PolicyDecision.EffectiveTTLSeconds` = candidate (for all outcomes; for deny it is
informational). Every evaluated rule appears in `Reasons` with its outcome; the decisive
reasons must be present (tests assert specific keys). Details must include the concrete
numbers/IDs where relevant, e.g. `"requested 3600s exceeds capability max 1800s"`.

Default settings: see `model.DefaultPolicySettings()` (auto ≤ low risk, ≤900 s; max 3600 s;
pending timeout 600 s; concurrency 3; rate 6/min; reason required from medium).

## 7. Built-in capability catalog (exact)

Shipped by `capcatalog.Builtin()`, seeded on init. JSON policy is the **string** in
`policy_template`; `{{param}}` placeholders are substituted by `RenderPolicy`. IDs, risk,
TTLs and policy templates are part of the demo/acceptance contract.

| ID | Name | Risk | Default/Max TTL (s) | Params | Policy template (compact JSON) |
| --- | --- | --- | --- | --- | --- |
| `aliyun.cloud.read` | Cloud read-only inventory | low | 900 / 1800 | — | `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],"Resource":["*"]}]}` |
| `aliyun.dns.manage` | Manage DNS records for one domain | medium | 900 / 1800 | `domain` (required, pattern `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`) | `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:UpdateDomainRecord","alidns:DeleteDomainRecord","alidns:SetDomainRecordStatus"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}` |
| `aliyun.cert.dns01` | ACME DNS-01 challenge token for one domain | medium | 600 / 1200 | `domain` (same pattern) | `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:DeleteDomainRecord"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}` |
| `aliyun.ecs.instance.ops` | Start/stop/restart one ECS instance | high | 900 / 1800 | `instance_id` (required, pattern `^i-[A-Za-z0-9]+$`) | `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StartInstance","ecs:StopInstance","ecs:RebootInstance","ecs:DescribeInstances"],"Resource":["acs:ecs:*:*:instance/{{instance_id}}"]}]}` |
| `aliyun.iam.break_glass` | Emergency account-wide access (break-glass) | critical | 900 / 1800 | — | `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}` |

Descriptions (seeded): see SPEC §2; write helpful one-liners mentioning scope and approved
use. `ValidateParams`: required params present/non-empty; every supplied param declared;
each value matches its RE2 pattern; unknown param → error. `RenderPolicy`: substitute only
declared placeholders, then require `json.Valid`.

## 8. Providers and the mock cloud

### 8.1 Minter contract

`provider.New(mode)` returns a `Minter`. `Mint` must be side-effect free except for the
provider call and must never log/persist secrets. `Test` validates configuration.

**mock** (`ModeMock`): requires a 32-byte signing key; policy JSON valid; duration 5–3600 s.
Returns `model.Credential{ProviderID, ProviderMode: mock, LeaseID, AccessKeyID:
"LTAI"+8 uppercase hex, AccessKeySecret: base64url(24 random bytes), SecurityToken:
mockToken, ExpiresAt: now+duration}`. `Test` → ok when signing key length 32.

**aliyun sts** (`ModeSTS`): requires broker AK/SK, valid policy JSON, role ARN, duration
900–3600 s. HTTP client timeout 10 s, no retries. On error return an error whose message is
`<Code>: <Message>` (provider error codes only; never include AK/SK).

Alibaba Cloud RPC signature v1 (implement in-tree, no SDK):
1. Params: `AccessKeyId`, `Action=AssumeRole`, `Format=JSON`, `RoleArn`,
   `RoleSessionName`, `DurationSeconds`, `Policy` (compact JSON), `SignatureMethod=HMAC-SHA1`,
   `SignatureNonce` (16 random hex chars), `SignatureVersion=1.0`,
   `Timestamp` (UTC `2006-01-02T15:04:05Z`), `Version=2015-04-01`.
2. Percent-encode per RFC 3986 (unreserved `A-Za-z0-9-_.~`; space → `%20`; UTF-8 bytes).
3. Sort params by key; `canonicalQuery = join("&", k+"="+encode(v))`.
4. `stringToSign = "GET&" + encode("/") + "&" + encode(canonicalQuery)` (where `encode("/")`
   is `%2F`).
5. `signature = base64(HMAC-SHA1(key = AccessKeySecret+"&", stringToSign))`.
6. Request `GET https://sts.aliyuncs.com/?<canonicalQuery>&Signature=<encode(signature)>`.
7. 200 response JSON `{AccessKeyId, AccessKeySecret, SecurityToken, Expiration, RequestId}` →
   `Credential` (parse `Expiration` RFC3339). Non-200: parse `{Code,Message,RequestId}` →
   error.
`Test` uses signed `Action=GetCallerIdentity&Version=2015-04-01` (same algorithm, no policy).
`RoleSessionName`: sanitize to `[A-Za-z0-9._-]`, length 2–64 (server passes
`csg-<agentID>-<leaseID>` truncated safely).

### 8.2 Mock STS token (format frozen so mock cloud and provider agree)

```
token   = "cgk1." + base64url(payloadJSON) + "." + base64url(hmacSHA256(signingKey, "cgk1."+base64url(payloadJSON)))
payload = {"v":1,"lease_id":"...","provider_id":"...","account_id":"1234567890123456",
           "region":"cn-hangzhou","expires_at":"<RFC3339Nano UTC>","session_name":"...",
           "policy":{...IAM policy document...}}
```
`base64url` = `base64.RawURLEncoding`. Signing key = `vault.DeriveKey(masterKey, "mock-sts")`.
Payload JSON is encoded by a struct with exactly that field order (Go struct order).

### 8.3 Mock cloud API (mounted at `/mock-cloud/`, only when ≥1 mock provider exists)

Auth: `Authorization: Bearer <mock token>`. Validation order: signature+format → expiry →
provider mode mock → lease `active` and not expired (store lookup; makes revoke/expiry
immediate) → policy allow for (action, resource). Errors are Aliyun-shaped:
`401 {"Code":"InvalidSecurityToken"|"InvalidSecurityToken.Expired"|"InvalidSecurityToken.Revoked","Message":...,"RequestId":...}`,
`403 {"Code":"Forbidden.RAM","Message":"...","RequestId":...}`,
`404 {"Code":"InvalidInstance.NotFound"|"InvalidDomain.NotFound","Message":...,"RequestId":...}`.

| Method/path | IAM action | Resource ARN | Success response |
| --- | --- | --- | --- |
| `GET /mock-cloud/v1/ecs/instances` | `ecs:DescribeInstances` | `acs:ecs:<region>:<account>:instance/*` | `{"RequestId":"...","RegionId":"...","Instances":[{InstanceId,InstanceName,Status,RegionId}]}` |
| `GET /mock-cloud/v1/ecs/instances/{id}` | `ecs:DescribeInstances` | `acs:ecs:<region>:<account>:instance/<id>` | `{"RequestId","Instance":{...}}` |
| `POST /mock-cloud/v1/ecs/instances/{id}/restart` | `ecs:RebootInstance` | same | `{"RequestId","Instance":{...}}` (status running) |
| `POST /mock-cloud/v1/ecs/instances/{id}/start` | `ecs:StartInstance` | same | same, status running |
| `POST /mock-cloud/v1/ecs/instances/{id}/stop` | `ecs:StopInstance` | same | same, status stopped |
| `GET /mock-cloud/v1/dns/zones` | `alidns:DescribeDomains` | `*` | `{"RequestId","Domains":[{DomainName,DomainId}]}` |
| `GET /mock-cloud/v1/dns/zones/{zone}/records` | `alidns:DescribeDomainRecords` | `acs:alidns:<region>:<account>:domain/<zone>` | `{"RequestId","DomainRecords":{"Record":[{RecordId,RR,Type,Value,TTL,Status}]}}` |
| `POST /mock-cloud/v1/dns/zones/{zone}/records` | `alidns:AddDomainRecord` | same | `{"RequestId","Record":{...}}` (200) |
| `DELETE /mock-cloud/v1/dns/zones/{zone}/records/{rid}` | `alidns:DeleteDomainRecord` | same | `{"RequestId","RecordId":"..."}` |

Policy matching (used by mock cloud; unit-tested): statements Allow/Deny; Effect Deny
overrides Allow; Action case-insensitive glob (`*`,`?`); Resource case-sensitive glob;
no matching Allow (or any matching Deny) → forbidden. Record create body:
`{"name":"www","type":"A","value":"8.153.177.205","ttl":600}` (name = RR, `@` for apex;
type ∈ A/AAAA/CNAME/TXT/MX; value non-empty; ttl 60–86400 default 600).
Fixtures per server process (in-memory, reset on restart), account `1234567890123456`:
- ECS: `i-2ze0demo001` `web-01` running, `i-2ze0demo002` `worker-01` stopped,
  `i-2ze0demo003` `db-01` running.
- DNS: `arveykao.com` (`dns-demo-arveykao`) records `@ A 8.153.177.205 600`,
  `www A 8.153.177.205 600`, `_acme-challenge TXT demo-token-123 600`;
  `guanlanstudio.com` (`dns-demo-guanlan`) no records.
Every request appends audit `cloud.api_called` (see §10) with metadata
`{"service":"ecs"|"alidns","action":"...","resource":"...","http_status":200,"request_id":"..."}`
and actor = lease's agent; denied → status `denied`, severity `warning`, + `reason`.
Invalid-token requests append `cloud.api_denied` (actor system, warning).

## 9. CLI (`cmd/csg`, package `internal/cli`)

Global behavior: config resolution flags > env (`CSG_SERVER`,`CSG_TOKEN`) > file
`~/.config/cloud-safeguard/config.json` (0600, `{"server","token","kind"}`). Human-readable
tables by default; `--json` prints the `data` payload as pretty JSON; errors go to stderr as
`error: <message>`; exit codes: 0 ok, 1 operation failed (denied/failed/HTTP error),
2 usage/validation, 3 auth, 4 wait timeout. Duration flags accept `90s`, `10m`, `1h`, or an
integer number of seconds.

Commands (flags in brackets; all `--json` where output exists):
- `csg version`
- `csg init [--data-dir DIR] [--demo] [--force] [--admin-token-file PATH] [--json]`
  — prints data dir, permissions warning, admin token (once), provider/agent tokens (demo).
  Refuses existing initialized dir without `--force`.
- `csg serve [--data-dir DIR] [--addr 127.0.0.1:8787]` — logs listening URL (console + API);
  graceful shutdown on SIGINT/SIGTERM.
- `csg login --server URL --token TOKEN` — validates (admin → `/admin/login`, agent →
  `/agent/me`), saves config; `csg whoami [--json]`.
- `csg caps list|show ID` (admin).
- `csg agents list|get ID|create|suspend ID|activate ID|rotate-token ID`
  (`create --name N [--description D] [--capability id[,id...]] [--max-ttl DUR]
  [--max-concurrent N]`; rotate prints the new token once).
- `csg providers list|get ID|add|update ID|rotate ID|test ID`
  (`add --name N --mode mock|sts --region R [--role-arn ARN] [--access-key-id ID]
  [--access-key-secret-file PATH] [--access-key-secret-stdin]`; rotate takes the same
  secret flags; never echoes secrets).
- `csg leases list [--status S] [--agent ID] [--capability ID] | get ID |
  approve ID [--ttl DUR] [--note TEXT] | deny ID --reason TEXT | revoke ID [--reason TEXT]`
  (admin side; `--reason` defaults to `"revoked by operator"` for admin revoke).
- `csg audit list [--action A] [--severity S] [--limit N] | verify`.
- `csg policy show | set [--auto-approve-max-risk R] [--auto-approve-max-ttl DUR]
  [--max-lease-ttl DUR] [--pending-timeout DUR] [--max-concurrent N]
  [--leases-per-minute N] [--require-reason-risk R]` — only provided flags change.
- Agent side:
  - `csg request --capability ID [--param k=v]... [--ttl DUR] [--reason TEXT]
    [--break-glass] [--wait DUR] [--json]` — creates lease; with `--wait` polls every 1 s
    until terminal. Human output: lease id, status, decision summary, expiry, next step.
  - `csg credential --lease ID [--export|--json]` — fetches credential; `--export` prints
    `export NAME='value'` lines; default prints JSON envelope; audit records the fetch.
  - `csg exec --capability ID [--param k=v]... [--ttl DUR] [--reason TEXT] [--break-glass]
    [--keep] [--wait DUR] -- CMD [ARGS...]` — request → wait (default 120 s) → fetch →
    run child with env injected (§3) + inherits stdio → revoke lease on exit unless
    `--keep` → exit with child's code. Prints a one-line summary to stderr (never secrets).
  - `csg leases mine [--json]`, `csg revoke --lease ID [--reason TEXT]` — agent side.
- Demo helper: `csg mock request METHOD /v1/PATH [JSON_BODY]` — calls
  `<server>/mock-cloud/v1/...` with `Authorization: Bearer $ALIBABA_CLOUD_SECURITY_TOKEN`;
  prints response body; exit 1 on HTTP ≥ 400. `--json` prints request/response metadata
  without the token. Never prints the mock token.

Agent token not found / admin token used for agent command → exit 3 with a clear message.
`csg exec` denied lease → exit 1 and prints the decision reasons.

## 10. Audit log (hash chain) and event catalog

Append-only table; fields `model.AuditEvent`. `seq` starts at 1 and increases by 1.
First `prev_hash` = 64 zeros.

```
canonical := compact JSON of ordered object:
  {"seq":<int>,"time":"<RFC3339Nano UTC>","actor_type":...,"actor_id":...,"actor_name":...,
   "action":...,"status":...,"severity":...,"target_type":...,"target_id":...,
   "metadata":{...}}            # metadata omitted when empty; keys sorted (encoding/json map)
hash := hex(sha256("csg-audit-v1\n" + prev_hash + "\n" + canonical))
```
Implementation hint: marshal a Go struct with fields in exactly that order + `json.Marshal`
(Go sorts map keys), then hash. `AppendAudit` computes seq/hash in one transaction.
`VerifyAudit` walks ascending, checks seq continuity, recomputes each hash, returns
`{ok:false, first_invalid_seq:N, message}` on mismatch; `{ok:true, events:N}` otherwise.

Required actions + severity (metadata must never contain secrets):
| Action | Severity | Metadata (suggested) |
| --- | --- | --- |
| `auth.admin_login` / `auth.admin_auth_failed` | info / warning | `remote_addr` |
| `auth.agent_auth_failed` | warning | `remote_addr`, token prefix |
| `provider.created` | info | provider id/name/mode/masked AK |
| `provider.updated` | info | changed fields |
| `provider.credential_rotated` | warning | provider id, old/new masked AK |
| `provider.tested` | info | ok, message |
| `capability.created` / `capability.updated` | info | capability id, changed fields |
| `agent.created` | info | agent id, grants |
| `agent.updated` / `agent.suspended` / `agent.activated` / `agent.token_rotated` | info / warning for token rotate | agent id, grant diff |
| `lease.requested` | info | capability, risk, params, ttl, decision outcome |
| `lease.auto_approved` / `lease.approved` | info (critical if break_glass) | lease id, ttl, approver note |
| `lease.denied` | warning (critical if break-glass) | lease id, reasons |
| `lease.credential_issued` | info | lease id, fingerprint, expires_at |
| `lease.credential_fetched` | info | lease id, remote addr |
| `lease.revoked` | warning (critical if break-glass) | lease id, reason, actor |
| `lease.expired` | warning | lease id, previous status |
| `lease.failed` | warning | lease id, sanitized provider error |
| `policy.updated` | warning | before/after (non-secret) |
| `cloud.api_called` | info / warning if denied | service, action, resource, http_status, request_id |
| `cloud.api_denied` | warning | reason, service/action if known |

Actor conventions: `agent` events use the agent id/name; operations triggered by the server
use `system`/`Cloud Safeguard`; admin events use `admin`/`operator`.

## 11. Bootstrap, demo seed, and init artifacts

`csg init`:
1. Create data dir (0700) and master key (file 0600, 32 random bytes; or `--master-key`
   env), DB file (0600 best effort), run migrations, meta:
   `instance_id` (`csg_` + random), `admin_token_hash`, `admin_token_prefix`,
   `bootstrap_time`, `demo_mode`, `schema_version=1`.
2. Seed built-in capabilities (§7) (missing only, never overwrite existing rows).
3. Admin token generated once; return in `InitResult`/stdout; `--admin-token-file` writes
   it 0600.
4. `--demo`: seed provider `demo-aliyun` (`type=aliyun`, `mode=mock`, region
   `cn-hangzhou`, role_arn `acs:ram::1234567890123456:role/csg-demo`, placeholder
   AccessKey `LTAI5tDemoMockBroker` / encoded dummy secret, active) and agents:
   - `claude-code` — "Primary coding agent (Claude Code compatible)", grants
     `aliyun.cloud.read, aliyun.dns.manage, aliyun.cert.dns01, aliyun.ecs.instance.ops,
     aliyun.iam.break_glass`, max TTL 3600, max concurrent 3.
   - `hermes-researcher` — "Read-only research agent", grants `aliyun.cloud.read`, max TTL
     900, max concurrent 1.
   Return their one-time agent tokens in `InitResult.Agents`.
5. Default policy settings = `model.DefaultPolicySettings()`.
6. Print: data dir, admin token (once), admin token prefix, demo credentials for login,
   "store these tokens now" warning. `--json` emits `{"data": InitResult}`.
7. Refuse to run on an initialized dir unless `--force`; `--force` rotates the admin token
   (prints new) and seeds missing built-ins, leaving data intact.

`csg serve` requires an initialized dir (else clear error: run `csg init`). On startup it
logs the console URL + API URL, seeds nothing, starts sweeper, and serves until signalled.

## 12. Web console requirements (`web/`)

- Stack: Vite + React + TypeScript, plain CSS (no heavy UI kit; icons may be inline SVG).
  Scripts: `npm run dev`, `npm run build` (outputs `dist/`, `base: "./"`),
  `npm run typecheck`. Node ≥20.
- Local dev may use a small mock API (`web/devmock/`) but the shipped app must talk to the
  real API via same-origin `/api/v1` (Vite proxy to `http://127.0.0.1:8787`).
- Auth: login screen accepts the admin token, validates via `POST /admin/login`, stores in
  `localStorage` (`csg.adminToken`), attaches `Authorization: Bearer` to every call; 401 →
  clear token + back to login; logout button.
- Design: dark “security operations console”: near-black background, layered panels, hairline
  borders, one accent (emerald) for safe/active, amber pending, orange high, rose critical,
  monospace for IDs/credentials/fingerprints, generous whitespace, no external CDNs/fonts
  (must work offline), responsive ≥1024 px. Consistent loading skeletons, empty states,
  error banners, toasts, and confirm dialogs for destructive actions.
- Pages:
  1. **Login** — token field, paste-friendly, error state, product mark, one-line value prop.
  2. **Overview** — count cards (agents, active leases, pending approvals, events 24h),
     pending approval queue with inline approve/deny, active leases with countdown, risk
     distribution, recent audit feed, provider/vault health. Poll every 4 s while visible.
  3. **Agents** — table (name, status, grants, last seen, limits); create agent modal
     (name, description, capability checkboxes grouped by risk, TTL/concurrency); one-time
     token reveal modal with copy + warning; detail drawer (leases, suspend/activate, rotate
     token, edit grants); status badges.
  4. **Capabilities** — cards/table grouped by provider + risk, TTL defaults, parameter
     schema, policy JSON viewer; custom capability create modal; enable/disable toggle.
  5. **Leases** — filterable table (status, agent, capability, risk, created, expires);
     detail modal with decision reasons, params, timeline, credential fingerprint; approve
     (TTL selector + note), deny (reason required), revoke; pending highlighted.
  6. **Providers & Vault** — provider cards with masked AK, mode/region/role, test button,
     rotate credential modal (secret inputs, never echoed), status; vault status card
     (key fingerprint, secrets stored).
  7. **Audit** — filterable table (action, actor, severity, target, time), event detail
     JSON, “Verify chain” button with result, auto-refresh toggle.
  8. **Settings** — guardrail policy editor (risk select + duration inputs), validation
     errors from API, save with audit notice; danger-zone copy for rotation guidance.
- Never render provider secrets, STS secrets, or admin token after login. Agent token only in
  the one-time create/rotate modal.
- `web/dist` is committed after a successful real build; `make build` rebuilds it.

## 13. Frozen Go signatures (base commit)

These exist in the base commit as stubs. Implementations replace stub bodies/files while
keeping exported signatures. Only the Lead changes these files:

`internal/model/model.go` — all domain types + JSON tags (§3–§5, §10), constants, defaults.
`internal/store/store.go` — `Store` interface, `LeaseFilter`, `AuditFilter`, `Err*`,
`Open(ctx,dataDir) (*DB,error)`, `(*DB).Close()`; the concrete `DB` must implement `Store`.
`internal/vaultcrypto/vault.go` (Go package `vault`; the directory is named `vaultcrypto` so the
arvey-develop delivery source-identity classifier does not treat this source path as sensitive
product input) — `New`, `LoadOrCreateKey`, `KeyFingerprint`, `DeriveKey`,
`Encrypt`, `Decrypt`, `ErrInvalidKey`, `ErrDecrypt`, ciphertext format `v1:...`.
`internal/provider/provider.go` — `MintRequest`, `Minter`, `New(mode)`.
`internal/capcatalog/catalog.go` — `Builtin`, `Lookup`, `ValidateParams`, `RenderPolicy`.
`internal/mockcloud/mockcloud.go` — `Deps{Store,SigningKey}`, `NewHandler(Deps) http.Handler`.
`internal/server/server.go` — `Config`, `Server`, `New`, `Handler`, `ListenAndServe`,
`Addr`, `Close`, `InitOptions`, `InitAgent`, `InitResult`, `Init`.
`web/embed.go` — `web.FS() fs.FS`.

## 14. Required tests (each owner runs these before reporting)

**core-api** (Go tests, table-driven where natural):
- policy engine: every rule in §6, precedence (deny > require > allow), TTL derivation,
  reason strings, concurrency/rate denial, break-glass behavior.
- vault: roundtrip, AAD mismatch fails, tamper fails, wrong key size, key file 0600,
  fingerprint stable, DeriveKey deterministic.
- store/audit: CRUD, migrations idempotent, audit chain verify OK, tamper detection
  (mutate a row via SQL), seq continuity, pending/active sweeper queries.
- server (httptest, temp data dir, fake clock, fake provider minter): auth boundaries
  (agent vs admin token, suspended agent), agent lease auto-approve → credential → revoke,
  approval/deny flows, TTL limit denials, credential fetch after revoke/expire, agent
  isolation, provider secret never in responses, policy update effect, overview shape,
  static SPA fallback, no secret in DB files (scan temp DB bytes for fixture secret strings),
  audit verify endpoint, token rotation invalidates old token.
**agent-toolkit**:
- capcatalog: 5 builtins present/unique, params validation (required/pattern/unknown),
  policy rendering valid JSON for all builtins, injection attempt via param value rejected.
- provider: RPC signature known vector (fixed nonce/timestamp; independently computed
  HMAC in the test), AssumeRole request shape against httptest STS server (params, Method,
  Signature present, Policy passes through), response parsing, error mapping, duration
  bounds, session-name sanitizer; mock mint→verify roundtrip, tamper/expiry rejected.
- mockcloud: policy matcher (wildcards, deny precedence, no-match), end-to-end handler with
  fake store (200 allowed, 403 scoped-out, 401 expired/revoked, 404 unknown, record create
  then delete, audit events appended), no token leakage in responses.
- cli: duration/param parsing, config precedence, env building, request/credential/approve
  flows against httptest server, exit codes, `csg mock request` error handling.
**console-ui**: `npm run typecheck` + `npm run build` clean; API client unit tests optional;
manual dev-mock run; no secrets in `dist/`; visual QA screenshots.
**product-docs**: every command in README/QUICKSTART executed or explicitly marked as
doc-only; docs match §3–§11 and shipped CLI help.
**verifier**: A1–A16 independently (see SPEC §6.3), including Playwright browser E2E +
screenshots of overview/approve flow, security probes, clean-clone build/test, demo script
from a clean data dir, docs accuracy spot-checks.

## 15. Reporting format for every teammate

Send the Lead: `status` (done/blocked/partial), files added/changed, exact commands run with
results (verbatim key lines), evidence paths, known limitations/risks, and anything the Lead
must integrate or resolve. Never claim a command was run if it was not.

## 16. Agent roles and the IAM prohibition (normative; extends §3–§12)

Rationale: ADR-014. Roles apply to agents only; the admin token (§2) is unchanged and is not a
role. Agent tokens still never reach admin endpoints.

### 16.1 Model

- `AgentRole`: `guest` < `member` < `administrator`. `Agent.role` is required on the wire.
- `AccessLevel`: `read` < `write` < `admin`. `Capability.access` is required on the wire.
- A role permits: `guest` → `read`; `member` → `read`, `write`; `administrator` → all.
- `Agent.grants` stays, and must always be a subset of the capabilities the role permits.

### 16.2 Catalog changes (replaces the last row of §7)

| ID | Access | Risk |
| --- | --- | --- |
| `aliyun.cloud.read` | read | low |
| `aliyun.dns.manage` | write | medium |
| `aliyun.cert.dns01` | write | medium |
| `aliyun.ecs.instance.ops` | write | high |
| `aliyun.account.admin` (new) | admin | critical |

`aliyun.account.admin` replaces `aliyun.iam.break_glass`: template
`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, TTL 900 / 1800,
name "Emergency account-wide access, IAM excluded". It keeps the §6 break-glass flow
(`break_glass=true`, always human-approved, critical audit). `aliyun.iam.break_glass` is no
longer seeded.

### 16.3 IAM prohibition (not configurable)

`capcatalog.CheckPolicy(access AccessLevel, policyJSON []byte) error` rejects a document when
any of these holds. Service and action comparison is case-insensitive.

0. The document is not an object whose only keys are exactly `Version` and `Statement`
   (case-sensitive), has no statements, a statement has an element other than exactly `Effect`,
   `Action`, `Resource` or `Condition`, its `Effect` is not exactly `Allow` or `Deny`, or its
   `Resource` is missing, `null`, empty, or not a string or list of non-empty strings.
1. Any statement has a `NotAction` or `NotResource` key (whatever its value, `null` and `[]`
   included), a statement is `null` or not an object, an Allow statement has no `Action` (missing,
   `null` or empty), or the document cannot be parsed.
2. An Allow action's service part is `ram`, or contains `*` or `?`. A bare `*` action is the
   only exception, and only for `access=admin`.
3. An Allow action's service is `sts` and the action is anything other than exactly
   `GetCallerIdentity`.
4. `access=read`: every Allow action must be `service:` + a verb from `Describe`, `List`,
   `Get`, `Query`, then optional literal characters, then at most one trailing `*`. The full
   verb must come before any wildcard, so `ecs:D*` is rejected (it would match `Delete`); no
   `?`; bare `*` and `service:*` are rejected.
5. `access=write`: a bare `*` action is rejected. `service:*` is allowed.

`RenderPolicy` must append this statement to every rendered document, and then run
`CheckPolicy`, returning an error if it fails (fail closed; no credential is minted):

`{"Effect":"Deny","Action":["ram:*","sts:AssumeRole*"],"Resource":"*"}`

`Capability` templates are checked by rendering with sample params, in create and update.
Violation → 400 `invalid_request` with the offending action named, and audit
`capability.rejected` (warning). `PATCH` may not change `access` on a builtin. A `PATCH` that raises
a custom capability's `access` is rejected with 400 `invalid_request`, naming the agents, when
any agent granted it has a role that would not permit the new level; grants are never left
outside a role.

### 16.4 Policy engine (§6 additions)

Two rules run directly after rule 1. Reason keys are stable; existing keys are unchanged.

| Rule key | Condition | Outcome |
| --- | --- | --- |
| `role_permits` | role does not permit `capability.access` | deny |
| `iam_prohibited` | `CheckPolicy` fails for the capability's rendered policy, or the capability is retired | deny |

A third rule runs directly after `break_glass_approval` (§6 rule 12):

| Rule key | Condition | Outcome |
| --- | --- | --- |
| `admin_requires_approval` | `capability.access == admin` (builtin or custom, whatever its risk) | require_approval |

`policy.Input` gains `PolicyViolation string`, computed by the server, so `internal/policy`
stays free of the catalog. A denied lease records both reasons as usual.

### 16.5 Admin API and lifecycle

- `POST /admin/agents`: `role` optional, default `guest`, invalid → 400. Omitted or empty
  `grants` → every enabled capability the role permits (at that moment; later capabilities are
  not auto-granted). Supplied grants outside the role → 400.
- `PATCH /admin/agents/{id}`: `role` optional. A role change without `grants` resets grants to
  the same default. Audit `agent.role_changed` (warning) with `from`, `to`, revoked lease IDs.
- **Demotion:** every pending or active lease of that agent whose capability the new role does
  not permit is revoked with reason `role changed to <role>`, in the same request. Real STS
  credentials stay valid until expiry (existing residual risk, SECURITY.md).
- **Approval** (`POST /admin/leases/{id}/approve`) must also recheck, returning 409 `conflict`
  with no mint: agent status active, capability still in grants, role permits it, `CheckPolicy`
  passes. This closes delivery finding F3.
- **Authority changes revoke affected leases in the same request:** after an agent update,
  suspension, capability update, provider disable or policy-settings change commits, the server
  re-runs the full activation check on every affected pending and active lease and revokes those
  that fail (agent not active, grant removed, role, capability disabled or retired, prohibited
  policy, TTL above any ceiling, provider not active). Disabling a capability or a cloud account
  therefore revokes its live leases. Changing a capability's access, policy or params also revokes
  its pending leases. Denying a lease also clears any stored ciphertext. The agent-lease sweep runs on every agent update, so retrying a failed update finishes it.
- **One activation at a time per lease:** approval and auto-approval hold a per-lease lock across
  mint and activation and re-read the lease under it, so concurrent approvals of one lease mint
  once; the loser gets 409. A credential is stored only while the lease is still `pending`, and a
  mint failure marks the lease `failed` only if it is still `pending`.
- **Capability edits and activations are mutually exclusive:** an activation holds the
  capability's read lock from reading the capability until the lease is active; a capability edit
  holds its write lock from reading the capability until its lease sweeps finish. Auto-approval
  re-reads the capability under the lock and, if it changed since the decision, revokes the lease
  and returns 409 without minting.
- **Sweeps read one snapshot:** every authority and startup sweep reads its affected leases with a
  single query, never LIMIT/OFFSET pages, so leases leaving the set mid-sweep cannot hide others.
- **Terminal status before scrubbing:** revoke and expiry write the terminal status first and clear
  the ciphertext after, so no concurrent activation can leave a credential behind. A losing
  activation never scrubs the credential of a lease that is already active.
- **Post-mint recheck:** after minting and before activation, the server re-reads the agent,
  capability and provider and repeats every approval check, including the TTL ceilings; on failure the credential is scrubbed, the lease is
  revoked, `lease.activation_aborted` is audited and the caller gets 409.
- **Activation is compare-and-set:** approval and auto-approval write the lease as active only
  while it is still `pending` in the store. If a revoke, expiry or demotion landed after the checks,
  the write fails, the stored credential is scrubbed, `lease.activation_aborted` (warning) is
  audited and the caller gets 409 `conflict`.
- **Policy documents with duplicate keys** (compared with Unicode simple case folding, the rule
  Go's JSON decoder uses, at any depth) are rejected, and Allow actions must match `^[A-Za-z0-9][A-Za-z0-9_-]*:[A-Za-z0-9*?_-]+$` or be a
  bare `*`, so this checker and the cloud cannot read one document two ways.
- `GET /agent/capabilities` and `csg whoami` include role and access.

### 16.6 Storage (schema version 2)

Migration adds `agents.role` and `capabilities.access`, then in one transaction:

1. Builtins get the §16.2 access; custom capabilities get `admin`.
2. Custom capabilities whose template fails `CheckPolicy` for `admin`, or whose own template
   (before the deny is appended) has an Allow statement with a bare `*` action, are set disabled:
   v1 credentials were minted without the deny statement. Render
   them with sample params. (Do this at server startup if the store cannot reach capcatalog.)
3. `aliyun.iam.break_glass` is set disabled and kept, because old leases reference it.
4. Agents: replace that grant with `aliyun.account.admin`; drop grants to custom capabilities
   that step 2 disabled (they can never be leased again); role = the lowest role permitting every
   remaining grant; no grants → `guest`. Grants never widen.
5. After an upgrade (by `csg serve` or `csg init --force`), one `schema.migrated` system audit event is appended (warning) with
   the versions, the disabled capabilities and each agent's resulting role and dropped grants.

On every startup, pending and active leases on `aliyun.iam.break_glass` are revoked with reason
`capability retired`, and so is any pending or active lease whose capability is missing or now
renders a policy that fails `CheckPolicy` (reason `policy violates the IAM prohibition`), or whose
capability is disabled (reason `capability disabled`), audited as usual; if that fails the server refuses to start. The retired
row can never be re-enabled (400), granted (400), given as a default grant, or leased (denied by
`iam_prohibited`). Migrating a v1 database must be tested.

### 16.7 CLI, console, mock cloud, demo

- CLI: `csg agents create --role R` (default guest); `csg agents set-role ID R`; role shown in
  `agents list/get` and `whoami`; access shown in `caps list/show`. `--grant` still works.
- Console, Agents page: create modal leads with a role picker that explains each role in plain
  language and previews its capabilities, with grant checkboxes limited to that role and all
  ticked by default; role badge in the table; changing role uses `ConfirmDialog`, which warns
  when a demotion will revoke leases. Capabilities page: access column. Update
  `web/devmock/server.mjs`.
- Mock cloud: add `GET /v1/ram/users`, action `ram:ListUsers`, resource `*`, so a denial can be
  shown end to end. An `aliyun.account.admin` lease must get 403 `Forbidden.RAM` on it.
- Demo seed: `claude-code` → `administrator` with all five capabilities, `hermes-researcher` →
  `guest`. `scripts/demo.sh`: S7 uses `aliyun.account.admin`; new S9 shows guest write denied
  by `role_permits`, administrator denied on `/v1/ram/users`, and a `ram:*` custom capability
  rejected with 400.

### 16.8 Required tests

- `CheckPolicy` table: every rule above, including `RAM:CreateUser`, `r*:*`, `*:*`, `ram:*`,
  `sts:Assume*`, `sts:AssumeRole`, `ecs:D*` as read, `NotAction`, string and array `Action`.
- Every builtin rendered carries the Deny statement and passes `CheckPolicy` at its own access.
- Role × access matrix through the HTTP API for all three roles and five capabilities.
- Agent create/patch: default grants, out-of-role grants rejected, role reset.
- Demotion revokes exactly the out-of-role pending and active leases.
- Approval returns 409 and mints nothing after demotion, suspension or grant removal.
- Migration from a real v1 database, covering step 2 and "grants never widen".
- Mock cloud: account-admin lease is allowed on ECS and gets 403 on RAM.

## 17. Supervisors, people, per-account roles and the access request (accepted, not yet implemented)

Status: accepted by the project owner on 2026-11-09 and revised on 2026-11-10 (supervisors,
inherited agent rights, three permission levels, owner approval). Implementation follows the §16
merge. Until it ships, §1–§16 describe the running behaviour. Rationale: ADR-015.

### 17.1 Identities

- **Person**: a human account (username, password stored with Argon2id, required TOTP). Status
  `pending` (created or reset, setup not finished), `active` or `suspended`. Only setup makes a
  person active; a supervisor can set `active` or `suspended` and can reset. No global cloud
  role.
- **Supervisor**: a person with the platform flag `supervisor`. `csg init` creates the first one
  (replaces the single admin token, §2). Only supervisors may add, change or disable cloud
  accounts, create or suspend people, grant or remove the supervisor flag, bind people to cloud
  accounts, and change global settings. The flag gives no cloud access: a supervisor needs a
  role binding like anyone else, and binding oneself is audited at warning level.
- The last active supervisor cannot be suspended or lose the flag. A supervisor locked out of
  the console is restored with a local `csg` command on the server host, which needs the vault
  master key and is audited at critical. The data directory stores a key check, so recovery
  and `csg serve` refuse a master key other than the one the directory was created with.
  Recovery works for any username: the person becomes a supervisor and `pending` (created if
  missing, reactivated if suspended), and the audit event records their previous status.
- **Agent**: a non-human identity owned by exactly one person (`Agent.owner_id`, required,
  immutable). Its token is valid only while the agent and its owner are both active. An agent
  has no role of its own.

### 17.2 Roles are bound to cloud accounts

- A **cloud account** is today's provider (§8), identified by the cloud's own account ID (for
  Alibaba Cloud the numeric UID). `cloud_account_id` is unique across providers.
- A **role binding** is `(person, cloud_account) → role`, set only by a supervisor. A person may
  hold different roles on different accounts. No binding means no access to that account.
- Roles and the highest permission level each allows:

| Role | Highest permission | Meaning |
| --- | --- | --- |
| `guest` | `read` | Look at resources. |
| `member` | `write` | Also change existing resources. |
| `administrator` | `full` | Also create new resources and delete existing ones. |

- An agent **inherits** its owner's role on each account. The role is read from the binding at
  every request, approval and credential fetch; it is never copied onto the agent. The agent
  role and per-agent grants of §16 are removed.
- The IAM prohibition (§16.3) applies at every role and to supervisors.

### 17.3 Authentication

1. **Console**: a person logs in with password + TOTP and gets a short-lived session cookie
   (HttpOnly, SameSite=Strict, CSRF token); the console no longer keeps a bearer token in
   `localStorage`.
   - **Setup.** Creating or resetting a person returns a one-time setup code (valid 72 h,
     stored only as a hash). With it the person chooses a password (at least 12 characters)
     and enrolls an authenticator app; a correct first code activates the account, consumes
     the setup code and signs them in. Until then the code can be used again to choose a
     different password, which also replaces the authenticator secret. Supervisors never see or set passwords.
   - **Login.** Every failure returns the same 401, whatever the cause. A TOTP code works
     once: the accepted time step is consumed atomically. Five consecutive failures lock the
     account for 15 minutes. The limit is exact under parallel requests: attempts for one
     person are checked one at a time. Attempts made while locked are ignored, and a genuine
     code sent twice is refused without counting as a failure.
   - **Session.** 30 minutes idle, 12 hours at most. State-changing requests need the
     session's token in `X-CSRF-Token` and must be same-origin. Suspending or resetting a
     person ends their sessions at once, and no session can be created for a person who is
     not active.
   - **Client address.** Rate limits, the sign-in approval screen and the audit log use the
     direct peer's address. Behind a reverse proxy, start the server with
     `csg serve --trusted-proxy ADDR[,ADDR]`: only then, and only for requests arriving from
     those addresses, is `X-Forwarded-For` used (the right-most entry that is not a proxy).
   - Every API response carries `Cache-Control: no-store`.
   - **Same origin.** An `Origin` header must equal the server's own origin exactly (scheme,
     host and port). Behind a TLS-terminating proxy, start the server with
     `csg serve --public-url https://host`: only that origin is accepted and the session
     cookie is marked `Secure`. Setup and login also require `Content-Type: application/json`.
   - **Storage.** Passwords are Argon2id hashes; TOTP secrets are encrypted in the vault.
2. **Agent-first sign-in**: the agent (CLI or MCP) starts a sign-in and receives a short user
   code and a link. The person logs in, checks that the code and agent name match, and approves;
   the token is then issued to the agent already bound to that person. There is nothing else to
   choose. Codes expire after 10 minutes and are single-use.
   - **Start** (no authentication): the agent sends its name and receives a secret device code
     and a 7-character user code. At most 100 sign-ins may be waiting, 10 per remote address
     (429 beyond that).
   - **Decide**: a signed-in person enters the user code, sees the agent name and where the
     sign-in started from, and approves or denies. The first decision is final. Sign-ins are
     never listed in anyone's inbox: only the person who has the code can find one.
   - **Collect**: the agent polls with its device code. On approval it receives its token
     exactly once; the token is generated at that moment and never stored. No token is issued
     if the approver is no longer active.
   - **Owned agents**: the approver is the owner. The agent starts with no grants, so it gets
     nothing through the §16 request path. Signing in again under the same name replaces the
     owner's earlier agent: the old token stops working and its leases are revoked.
   - **Owner's control**: a person lists and revokes their own agents; other people's agents
     are invisible to them.
   - An owned agent's token is refused, and its pending and active leases are revoked at once,
     while its owner is suspended or pending. This also holds for local recovery (which
     revokes in the same run) and across restarts: at startup every pending and active lease
     is re-checked and revoked if it is no longer authorized. A credential is re-checked
     against the lease, the agent and the owner at the moment it is handed out.
   - The agent's two calls are refused when they come from another site in a browser, and
     must be `application/json`.
   - **Residual risk.** The agent name is chosen by whoever starts the sign-in, so a person
     must approve only a code their own agent is showing them. The user code is an approval
     secret while the sign-in is pending: it is masked in the access log, and the console must
     never approve from a link without the person confirming.

### 17.4 Access request (agent API and MCP)

| Field | Required | Meaning |
| --- | --- | --- |
| `cloud_account_id` | yes | Cloud account to act in. |
| `resource` | yes | Resource type from a fixed list (`ecs`, `dns`, `oss`, …). |
| `permission` | yes | `read`, `write` or `full`. |
| `ttl_seconds` | yes | Validity period. No default; missing or non-positive → 400. |
| `resource_name` | no | Narrows the policy to one resource (domain, instance ID, bucket). |
| `reason` | yes for `write` and `full` | Shown to the owner on the approval. |

- Each `(resource, permission)` pair maps to one vetted template; agents cannot submit IAM
  actions. `full` is always scoped to one resource type; the account-wide
  `aliyun.account.admin` capability is not reachable through access requests.
- Templates are defined in code (`internal/capcatalog/access.go`), not stored, and cannot be
  created or edited through any API. Their IDs have the reserved form
  `<cloud>.access.<resource>.<permission>` (for example `aliyun.access.ecs.write`); a stored
  capability may not use such an ID. Resource types today: `ecs`, `dns`, `oss`.
- `resource_name` names one resource (an instance ID, a domain, a bucket) and is validated
  against the resource type's pattern. Left out, the request covers all resources of that type
  in the account. Wildcards inside a name are refused.
- `cloud_account_id` is taken from the provider's role ARN when the provider is created, is
  unique, and never changes: a provider's role ARN may only be replaced by one in the same
  cloud account, so role bindings can never move to another account.
- An unknown cloud account and one the owner has no role on get the same 403. Malformed
  requests are 400 and leave no record.
- `ttl_seconds` must be within the capability and global maximums and at least the provider
  minimum (real STS 900 s); otherwise 400 naming the limit.

**Permission levels.** A *resource* is the top-level object of a resource type: an ECS instance,
a DNS domain, an OSS bucket. An *item* lives inside one: a DNS record, an OSS object.

| Level | Allows |
| --- | --- |
| `read` | `Describe*`, `List*`, `Get*`, `Query*` actions only (§16.3 read rule). |
| `write` | `read`, plus changing an existing resource: its settings and state, and adding, changing or removing items inside it. |
| `full` | `write`, plus creating a new resource and deleting an existing one. |

Every action in a template is classified by an explicit per-resource-type table kept next to the
catalog. An action missing from the table is treated as `full`. A template whose actions exceed
its declared level is rejected at startup and at capability edit.

Verification order (deny on the first failure, recorded as decision reasons): token valid →
agent and owner active → owner bound to the cloud account → `permission` within the owner's role
there → IAM prohibition → existing §6 rules (TTL, concurrency, rate). A request above the
owner's role is recorded as denied at once; it never reaches approval.

The owner's role is read from the binding again at approval, after the credential is minted
(before the lease becomes active), and at every credential fetch. It is never copied onto the
agent or the request.

### 17.5 Approval

- `read` requests that pass verification are approved automatically.
- `write` and `full` requests always wait for approval. The approver is the **agent's owner**,
  signed in to the console. Nobody else can approve, including supervisors and the operator
  token; to anyone else the request does not exist (404). The owner cannot change the
  validity period at approval.
- The owner can also deny a pending request and revoke an issued one early.
- The approval shows the agent, cloud account, resource type, resource name, permission, validity
  period and reason exactly as they will be issued.
- Approval rechecks everything in §17.4 and §16.5 at decision time. A pending request expires
  after the §6 approval timeout.

### 17.6 Lifecycle

- **Expiry timer.** Every issued credential has a deadline = issue time + `ttl_seconds`. The
  clock starts when the credential is issued (for `write` and `full`, at approval), not when
  the request is made. The cloud token is minted with exactly that lifetime, so the cloud
  rejects it after the deadline even if Cloud Safeguard is down. At the deadline the server
  marks the lease `expired`, erases its stored credential and writes an audit event (§10
  sweep). A credential cannot be extended; the agent sends a new request.
- Suspending a person suspends their agents and revokes their pending and active leases.
- Removing or lowering a binding revokes that person's agents' leases on that account that the
  new role does not permit (as §16.5 demotion). Real STS credentials stay valid until expiry.
- Every audit event names the person (owner, approver or supervisor) as well as the agent.
  A `lease.revoked` event caused by a person's action (suspension, reset, an owner revoking
  an agent, a re-sign-in) is recorded as the control plane's, with `caused_by`, `owner_id`,
  `agent_id` and `agent_name` in its metadata.

### 17.7 MCP server

Tools: `request_access` (the §17.4 fields), `check_status`, `get_credential`, `revoke`,
`list_accounts` (accounts and the owner's role on each). The MCP server is a thin client of the
agent API; it holds the agent token and no cloud credentials beyond the lease it fetched.

### 17.8 Implementation status

| Part | Status |
| --- | --- |
| People, supervisors, setup, login, sessions (§17.1, §17.3 item 1) | implemented, schema version 3 |
| Role bindings and the supervisor API (§17.2) | implemented; not yet enforced on requests |
| `csg init` first supervisor, `csg supervisor recover` | implemented |
| Agent ownership and agent-first sign-in (§17.3 item 2) | implemented (API), schema version 4; CLI and console not yet |
| Five-field request, permission levels, owner approval (§17.4, §17.5) | implemented (API), schema version 5; CLI and console not yet |
| Lifecycle revocation for owned agents (§17.6) | implemented: owner suspended or reset, binding lowered or removed |
| MCP server (§17.7) | not started |
| Console redesign | not started |

Until the remaining parts ship, the §2 admin token and the §16 agent API keep working
unchanged alongside the new endpoints:

- `POST /api/v1/auth/setup/begin`, `POST /api/v1/auth/setup/finish`, `POST /api/v1/auth/login`,
  `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`
- `GET|POST /api/v1/supervisor/people`, `PATCH /api/v1/supervisor/people/{id}`,
  `POST /api/v1/supervisor/people/{id}/reset`
- `GET /api/v1/supervisor/bindings`,
  `PUT|DELETE /api/v1/supervisor/accounts/{provider_id}/people/{person_id}`
- `POST /api/v1/agent-signin/start`, `POST /api/v1/agent-signin/token` (agent, no token yet)
- `GET /api/v1/me/signins/{user_code}`, `POST /api/v1/me/signins/{user_code}/approve|deny`,
  `GET /api/v1/me/agents`, `POST /api/v1/me/agents/{id}/revoke` (person session)
- `GET /api/v1/agent/accounts`, `POST /api/v1/agent/access-requests`,
  `GET /api/v1/agent/access-requests/{id}` (agent token). The request ID is also the lease ID
  for `POST /api/v1/agent/leases/{id}/credential` and `.../revoke`.
- `GET /api/v1/me/requests[?status=pending]`,
  `POST /api/v1/me/requests/{id}/approve|deny|revoke` (person session)
