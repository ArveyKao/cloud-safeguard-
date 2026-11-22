# Cloud Safeguard — Implementation Contract (v0.1, frozen)

Normative for the v0.1 build. Anything not specified here is an implementation choice, but
the **exported signatures in §13, the HTTP contract in §3–§5, the policy semantics in §6,
the capability catalog in §7, the mock cloud in §8, the CLI in §9 and the audit format in
§10 are frozen**. Changes go through the Lead.

Vocabulary and scope: `docs/SPEC.md`. Shared Go types: `internal/model/model.go` (JSON tags
are the wire contract).

> **Read §17 first.** The admin token and the agent model of §3, §4, §6, §7, §9, §11 and §16
> were removed on 2026-11-15 (§17.7a). Those sections are kept as the record of v0.1 and are
> no longer the running behaviour. §2 is rewritten for the current authentication. What
> still applies from the others is listed in §17.7a. In §10 the hash chain is current; its
> table of audit actions still lists v0.1's and is not complete for §17.

---

## 1. Runtime, configuration, file layout

- Single binary `bin/csg`, single process, no cgo, no cloud SDK. Dependencies: Go stdlib +
  `modernc.org/sqlite v1.34.5` only. Go 1.24.4.
- Default data dir for the binary: `./data`; demo: `.demo/data`. `csg init` creates it
  with mode 0700 (best effort), database `<dataDir>/csg.db`, master key `<dataDir>/master.key`
  (0600).
- Env vars: `CSG_MASTER_KEY` (base64 std, 32 bytes; used instead of the key file and proved
  against the data, see §17.7a),
  `CSG_SERVER` (CLI), `CSG_TOKEN` (CLI), `CSG_DATA_DIR` (CLI default for init/serve).
- HTTP: loopback by default `127.0.0.1:8787`; timeouts 10 s; max request body 1 MiB; JSON
  error recovery on panics; access log lines `method path status duration_ms` (no bodies,
  no Authorization values).
- Static console: embedded in the binary via `web.FS()`. `GET /` serves `index.html`;
  unknown non-API GET paths fall back to `index.html` (SPA). API prefix is `/api/v1/`,
  mock cloud prefix is `/mock-cloud/`, health is `/healthz`.
- Version reported: `model.Version` = `"0.1.0"`.

## 2. Authentication, errors, envelopes

**Who calls what** (§17.3). People use a console session (cookie plus CSRF token) on
`/api/v1/auth/`, `/api/v1/me/` and `/api/v1/supervisor/`. Agents send
`Authorization: Bearer <token>` on `/api/v1/agent/`. There is no admin token.
- An agent token has the prefix `csg_agt_`. Anything else is rejected **401** `unauthorized`.
- Agent token resolution: SHA-256 of token → `agents.token_hash`; unknown → 401. An agent
  that is `suspended` or `revoked`, has no owner, or whose owner is not active → **403**
  `forbidden` on all agent endpoints.
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
plaintext outside the credential endpoint, an agent token except once to the agent when its
sign-in is approved, a setup code except once when it is issued, passwords, TOTP secrets,
the master key.

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
`CSG_SERVER` (base URL of the control plane), `CSG_CAPABILITY` (capability id). For an AWS
request (§17.13) the first three are instead `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, followed by `AWS_REGION` and `AWS_DEFAULT_REGION`.

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
  Scripts: `npm run dev`, `npm run build` (outputs `dist/`, `base: "/"` because routes are
  nested), `npm run typecheck`. Node ≥20. One runtime dependency besides React:
  `qrcode-generator` (MIT) for the authenticator QR code.
- The app talks to the real API via same-origin `/api/v1` (in development a Vite proxy to
  a running `csg serve`).
- Since the §17 redesign the console signs people in (password + authenticator code, §17.3)
  and uses the session cookie and its CSRF token; it never stores a token in `localStorage`.
  Screens: Inbox (requests waiting for the person, approve/deny/revoke), agent sign-in
  approval (`/?signin=CODE`, the link `csg login` prints), Agents, Cloud accounts (everyone's
  own roles and their approval mode on each, §17.11; for supervisors also every account with
  people, roles, connection test, key replacement, disable, and a three-step add wizard),
  Activity (the person's own requests; the audit log for supervisors), People (supervisors),
  Settings (command-line sign-ins; platform limits for supervisors). The older admin-token console below is
  removed; the remaining requirements in this section describe that older console.
- Every response carries `X-Frame-Options: DENY`, a `Content-Security-Policy` that allows only
  the console's own files and `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`. Actions that change authority or cannot be undone (role
  changes, removing a role, the automatic level, disabling an account, suspend, reset,
  supervisor flag, revoking a credential, raising the approval mode) ask for confirmation and
  say what will happen. Approving an agent sign-in needs the person to confirm the code matches
  their terminal, and says when it replaces an agent of the same name. Saving the approval mode
  keeps the end of a temporary mode unless the person picks another. Console tests:
  `cd web && npm test`.
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

## 17. Supervisors, people, per-account roles and the access request (implemented)

Status: accepted by the project owner on 2026-11-09 and revised on 2026-11-10 (supervisors,
inherited agent rights, three permission levels, owner approval). Implemented; §17.8 lists
each part. This section is the running behaviour. Rationale: ADR-015.

### 17.1 Identities

- **Person**: a human account (username, password stored with Argon2id, required TOTP). Status
  `pending` (created or reset, setup not finished), `active` or `suspended`. Only setup makes a
  person active; a supervisor can set `active` or `suspended` and can reset. No global cloud
  role.
- **Supervisors are Administrator on every cloud account** (owner's decision, 2026-11-14): no
  role binding is needed, and their agents may ask for up to `full` on every account; their
  approval mode on each account (§17.11) still decides what waits for them.
  Removing the flag revokes what their agents hold beyond their own role bindings.
- **Supervisor**: a person with the platform flag `supervisor`. `csg init` creates the first one.
  Only supervisors may add, change or disable cloud accounts, create or suspend people, grant
  or remove the supervisor flag, bind people to cloud accounts, and change global settings.
  Granting or removing the flag is audited at critical level, because it also gives or takes
  Administrator on every cloud account.
- The server does not start when no person holds the supervisor flag (an install upgraded
  from a version that had only the admin token): it says to run `csg supervisor recover`.
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
  every request, approval and credential fetch; it is never copied onto the agent. An agent
  has no role or grants of its own. Every agent belongs to a person: an agent without an
  owner is refused on every agent route (403), and a lease that is not an access request is
  never handed out and is revoked at the next re-check or start.
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
   - **Who holds the code.** A setup code is a bearer secret: whoever uses it first sets the
     password, so the supervisor who issued it could complete the setup and act as that
     person. This is accepted (owner's decision, 2026-11-12): supervisors are trusted to hand
     codes over. It is traced instead: every person records who issued their current setup
     code, how (`created`, `reset`, `recovered`, `bootstrap`) and when (`setup_issued` on the
     person, visible to the person in `GET /auth/me` and to supervisors in the people list),
     and the `person.setup_completed` audit event names the issuer. The console shows the
     person who created or reset their account, so a person who did not set their own
     password can tell another supervisor.
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
   - **Ownership**: the approver is the owner. Signing in again under the same name replaces the
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
  capability may not use such an ID. Resource types today: `ecs`, `dns`, `oss` on Alibaba
  Cloud, `s3` on AWS (§17.13).
- `resource_name` names one resource (an instance ID, a domain, a bucket), is at most 253
  characters and is validated against the resource type's pattern. Left out, the request
  covers all resources of that type in the account. Wildcards inside a name are refused.
- ECS `write` is start, stop and reboot. `ecs:ModifyInstanceAttribute` is in no template: it
  can set an instance's login password, which gives a shell on the instance and with it the
  credentials of any RAM role attached to that instance, a way around the IAM prohibition.
- Limits are exact under parallel requests: an agent's requests are checked one at a time.
  Requests waiting for approval count towards the agent's limit on active credentials, and
  the limit is checked again at approval.
- `cloud_account_id` is taken from the provider's role ARN when the provider is created, is
  unique across clouds (agents name an account by it alone, so an Alibaba Cloud UID and an
  AWS account ID that happen to be equal cannot both be connected), and never changes: a provider's role ARN may only be replaced by one in the same
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

- **Approval mode.** *Replaced by §17.11: the mode is now per cloud account and the account's
  highest automatic level is removed; the rest of this item describes the earlier design.*
  Each person chooses one mode for all their agents: `read` (default),
  `write` or `full`. A request at or below the mode is issued automatically; a request above
  it waits for approval.

  | Mode | Issued automatically | Waits for the owner |
  | --- | --- | --- |
  | `read` | read | write, full |
  | `write` | read, write | full |
  | `full` | read, write, full | nothing |

  - Only the person sets their own mode, in a console session. No agent, supervisor or API
    token can set it. A mode above `read` may carry an expiry; after it the mode is `read`.
  - Each cloud account has a **highest automatic level** set by a supervisor (default
    `read`). On that account nothing above it is automatic, whatever the person's mode.
  - What is automatic for a request = the lower of the person's mode and the account's
    highest automatic level. The role check comes first and is unaffected: a mode never
    lets an agent get more than its owner's role allows.
  - The mode is one per person and applies to **every** agent that person owns; a temporary
    raise is visible to all of them at once.
  - Mode and level are read once, when the request is made: the decision is a snapshot.
    Raising either later does not approve requests already waiting; lowering either does not
    revoke credentials already issued or stop one being issued at that moment. Lowering a mode
    or level is therefore **not an emergency stop**: use revoke, suspension or removing the
    role binding for that.
  - Agents are told how far they are issued automatically (`automatic_up_to` in
    `GET /agent/accounts`, already capped by the role) but never the owner's mode or the
    account's level themselves. API responses show a person's mode as it applies now: an
    expired mode is shown as `read`.
  - A new cloud account always starts at level `read`. Resetting a person or recovering a
    supervisor puts their mode back to `read`, and the audit event records the previous mode.
  - Changes of a mode or of an account's level are audited; an automatic issue records the
    mode and level that allowed it.
- A request that waits is approved by the **agent's owner**, signed in to the console. Nobody
  else can approve, supervisors included; to anyone else the request does not exist (404). A
  supervisor approves the requests of their own agents like any other owner. The owner
  cannot change the validity period at approval.
- The owner can also deny a pending request and revoke an issued one early.
- A supervisor can see, deny and revoke anyone's access requests as a safety control, with
  every such action audited, and can never approve another person's. The note an owner
  writes at approval is not shown to the agent.
- The approval shows the agent, cloud account, resource type, resource name, permission, validity
  period and reason exactly as they will be issued.
- Approval rechecks everything in §17.4 at decision time, and again after the credential is
  minted. A pending request expires after the approval timeout (10 minutes by default).
- The limits (longest validity, credentials per agent, requests per minute) are the
  supervisor's current settings. They apply to every agent at once, whenever it signed in.

### 17.6 Lifecycle

- **Expiry timer.** Every issued credential has a deadline = issue time + `ttl_seconds`. The
  clock starts when the credential is issued (for `write` and `full`, at approval), not when
  the request is made. The cloud token is minted with exactly that lifetime, so the cloud
  rejects it after the deadline even if Cloud Safeguard is down (the cloud's own deadline is
  later than the server's by the time minting took, normally under a second). At the deadline the server
  marks the lease `expired`, erases its stored credential and writes an audit event (§10
  sweep). A key cannot be extended; within its refresh window the agent can have a new key
  issued under the same request (§17.12), and after it the agent sends a new request.
- Suspending a person suspends their agents and revokes their pending and active leases.
- Removing or lowering a binding revokes that person's agents' leases on that account that the
  new role does not permit. Real STS credentials stay valid until expiry.
- Every audit event about a request or credential names the agent and its owner, and the
  person who caused it when there is one (the owner, an approver or a supervisor). Events
  the control plane causes itself (a deadline, the check at start, local recovery) are
  recorded as `system` with what triggered them, one event per credential.
  A `lease.revoked` event caused by a person's action (suspension, reset, an owner revoking
  an agent, a re-sign-in) is recorded as the control plane's, with `caused_by`, `owner_id`,
  `agent_id` and `agent_name` in its metadata.

### 17.7 MCP server and agent CLI

`csg mcp` runs the MCP server on stdio (protocol revisions 2025-06-18, 2025-03-26, 2024-11-05).
It is a thin client of the agent API and holds only the agent token saved by `csg login`.

| Tool | Does |
| --- | --- |
| `list_accounts` | Cloud accounts the agent may ask for, with the inherited role, highest permission and `automatic_up_to`. |
| `request_access` | The §17.4 fields: `cloud_account_id`, `resource`, `permission`, `ttl_seconds`, optional `resource_name`, `reason` and `max_lifetime_seconds` (§17.12). |
| `check_status` | Status of a request, with `expires_at` and, once issued, `refresh_until`, `max_lifetime_seconds` and `refresh_count`. |
| `get_credential` | Writes the credential to `~/.config/cloud-safeguard/credentials/<request id>.env` (directory 0700, file 0600) as `export` lines and returns only the path, expiry and `source <path>`. The secret is never returned to the model, so it stays out of transcripts, logs and model-provider requests. |
| `refresh_credential` | A new key under the same request (§17.12), then handed over as `get_credential` does. |
| `revoke` | Ends the request and deletes its credential file. |

Request IDs are validated (`lea_` + 32 hex) before use, so a tool argument can never name another
file. Expired credential files are deleted when the server starts and before each new one is
written; `csg revoke` deletes the file too. A notification (a message without an id) never acts,
batches are answered, and one message over 1 MiB is refused without ending the session.

What the client takes from the server is checked: a credential may only set variables named
`ALIBABA_CLOUD_*`, `AWS_*` or `CSG_*` (in the credential file, `--export` and `csg exec`), so a
compromised server cannot inject shell code or variables such as `LD_PRELOAD`; text shown in the
terminal is stripped of control characters; a sign-in link on another host than `--server` is
called out; only an agent token (`csg_agt_`) is saved, written to a 0600 file that replaces the
old one atomically. Sign-in requests never carry a saved token.

Agent CLI, same flow from a terminal:

- `csg login --server URL [--name NAME]` runs the agent-first sign-in: it prints the link and
  the short code, waits for a person to approve, and saves the agent token (0600). The device
  code and the token are never printed. There is no way to paste a token in.
- `csg accounts`, `csg access request --account ID --resource R --permission P --ttl DUR
  [--name] [--reason] [--wait]`, `csg access status ID`.
- `csg exec --account ID --resource R --permission P --ttl DUR -- CMD` asks for access, runs
  CMD with the credential environment and revokes it when CMD exits (unless `--keep`). An
  interrupt (Ctrl-C, SIGTERM, SIGHUP) is passed on to CMD and always revokes, `--keep` or not;
  so does every way it gives up (approval timeout, credential fetch failure, CMD not starting).
  CMD does not inherit `CSG_TOKEN`.
- `csg credential --lease ID --export` and `csg revoke --lease ID` work with a request ID.

### 17.7a Removal of the admin token and the §16 agent model (decided 2026-11-14, done 2026-11-15)

- The admin token, `/api/v1/admin/*`, `csg login --token` and the admin CLI commands (`caps`,
  `agents`, `providers`, `policy`, `audit`, `request`, `leases list|approve|deny|revoke`) are
  removed. Every removed route answers 404. A token with the old `csg_adm_` prefix is not a
  credential anywhere.
- `csg init` creates the master key, the database, the default limits and the first
  supervisor's setup code, plus a mock cloud account with `--demo`. It creates no token, no
  agent and no stored capability. It refuses any directory that already holds a `master.key`
  or a database; there is no `--force`. An existing data directory is upgraded when
  `csg serve` opens it, and a locked-out supervisor uses `csg supervisor recover`.
- The §16 agent model is removed: agents created by the operator, agent roles and grants,
  capability leases (`POST /agent/leases`, `GET /agent/capabilities`), stored and custom
  capabilities, break-glass and the risk-tier policy engine. Access requests (§17.4) with the
  code-defined templates are the only way to get a credential. The settings a supervisor can
  change are the longest validity, the approval timeout, the number of credentials an agent
  holds at once and the requests per minute.
- Upgrade (schema version 8). The migration deletes the admin token, revokes every agent
  without an owner and clears the role and grants stored on every agent; the
  `schema.migrated` audit event says whether an admin token was deleted
  (`deleted_admin_token`, true or false) and lists the revoked agents. The report is kept
  in the database, written in the same transaction as each upgrade step, until it has been
  written to the audit log; the event and forgetting the report are one transaction too. So
  it is recorded exactly once by the first command that gets past the master-key check,
  `csg serve` or `csg supervisor recover`, even if an earlier command ran the upgrade and
  then stopped or was killed, and even if two commands open the same old database at the
  same moment (each upgrade step runs once, and only the command that removes the kept
  report writes the event).
  At every start the server revokes each pending or active lease
  that is not an access request, with one `lease.revoked` event each. People sign their
  agents in again with `csg login`. An install that never had a supervisor does not start
  until `csg supervisor recover --username NAME` creates one.
- The master key. `csg serve` and `csg supervisor recover` only read it: from
  `$CSG_MASTER_KEY` when that is set (a value of only spaces counts as not set), otherwise
  from `master.key`. They never create a key. The key is then proved against the data:
  - when something encrypted exists (the key check, a stored AccessKey, a TOTP secret) the
    key must decrypt it, and a supplied key that does wins over a `master.key` that does not;
  - when nothing encrypted exists (a directory from before the key check that never stored a
    secret) and there is a `master.key`, that file is the key and the key check is written
    with it; any other key is refused;
  - when nothing encrypted exists and there is no `master.key`, the key cannot be told from
    a mistyped one. The command is refused unless it is run once with `--trust-master-key`,
    which writes the key check and a `vault.master_key_trusted` audit event together.
  A key the data proves right also gets a key check written if the directory had none, so
  it stays verifiable. When a database exists but neither `master.key` nor
  `$CSG_MASTER_KEY` is there, the commands say the key is missing, not that the directory
  is not initialized. `csg init` with `$CSG_MASTER_KEY` set writes no `master.key` and says so.
- Supervisors are Administrator on every cloud account (§17.1). A cloud account must be
  added with a RAM role ARN; a request without one is refused. A provider an older upgrade
  left without a cloud account ID can be given one by setting a role ARN in an account that
  is not connected yet, or disabled. Giving it one removes the roles set on it before, in
  the same step, and the audit event lists them; a refused attempt changes nothing and is
  recorded. No role can be given on a provider that has no cloud account ID.
- Edits of a cloud account are applied one at a time. A connection test and a key
  replacement write only their own fields, so they never undo an edit made meanwhile.
- The limit on active credentials per agent is exact under parallel requests and parallel
  approvals.
- The connection test of an `sts` account checks the AccessKey (`GetCallerIdentity`) and then
  assumes the role once for 15 minutes with a policy that allows nothing useful.
- A path under `/api/` that matches no route answers 404 for every method. Under `/api/v1/agent/`,
  `/api/v1/me/` and `/api/v1/supervisor/` the caller is authenticated first, so without a
  valid credential the answer is 401 whatever the path.
- Still in force from §1–§16: the file layout and configuration (§1), envelopes and error
  codes (§2), the lease states (§5), providers and the mock cloud (§8), the audit hash chain
  (§10) and the IAM prohibition (§16.3).
- Next: a remote MCP endpoint over HTTPS with OAuth sign-in so an agent connects with a URL.

### 17.9 People on the command line (decided 2026-11-17)

The owner's decisions: a person signs in to `csg` by approving a short code in the console,
and a command-line session is **guarded**, because agents often run on the same machine
and could read it.

**Sign-in.** `csg person login --server URL [--name NAME]` works like the agent sign-in:
- `POST /api/v1/person-signin/start` `{client_name}` → `{device_code, user_code,
  verification_url, expires_at, interval_seconds}`. The code is valid for 10 minutes.
- The person opens the link (`/?cli-signin=CODE`) in the console, where they are signed in
  with password and authenticator, checks the code and approves:
  `GET /api/v1/me/cli-signins/{code}`, `POST /api/v1/me/cli-signins/{code}/approve|deny`.
  Only a console session can approve; a command-line session cannot approve another one.
- `POST /api/v1/person-signin/token` `{device_code}` → on approval, once:
  `{status, token, person, expires_at}`. The client keeps the token (`csg_ses_…`) in
  `~/.config/cloud-safeguard/person.json` (0600); the server stores only its hash.
- The approver can withdraw an approval until the client collects it
  (`POST /api/v1/me/cli-signins/{code}/cancel`). Suspending or resetting a person also ends
  every agent or command-line sign-in they approved that was not collected yet.
- The sign-in code is masked in the access log and the audit log, like the agent's.
- It is a session of the approving person, with the console's limits: 30 minutes idle,
  12 hours at most. It ends at `csg person logout`, when the person is suspended or reset,
  or when the person revokes it in the console (`GET /api/v1/me/cli-sessions`,
  `POST /api/v1/me/cli-sessions/{id}/revoke`). It is sent as `Authorization: Bearer` on
  `/api/v1/auth/me|logout`, `/api/v1/me/` and `/api/v1/supervisor/`; it needs no CSRF token.
  It never works on `/api/v1/agent/`, and an agent token never works as a session.

**What a command-line session may do.**
- Everything that reads.
- Everything that lowers access, as is: deny or revoke a request or credential, revoke
  one's own agent, lower a role (to any lower role) or remove it, suspend a person, remove
  the supervisor flag,
  disable a cloud account, lower an approval mode to read, lower an account's highest
  automatic level to read, test a connection, sign out.
- Anything that raises access needs a fresh authenticator code of the signed-in person on
  that request (`X-CSG-Authenticator-Code`): add a person, reset a person (it issues a setup
  code), activate a person, make a supervisor, give a role higher than the person has now
  (no role counts as below guest, but giving guest needs no code), change a cloud account
  other than disabling or renaming it, replace its AccessKey, raise its highest automatic
  level, change the limits unless every value is lowered, set an approval mode other than
  read. The server decides from the current value and writes under the same lock, so a
  change made meanwhile cannot turn a lowering into a raise. A wrong code counts towards the sign-in lockout (5 failures lock the
  person for 15 minutes); a code is accepted once. The CLI asks for the code when it runs
  in a terminal, or takes `--code`.
- Console only, with or without a code: approving an access request, approving an agent
  sign-in or a command-line sign-in, adding a cloud account, and giving a provider that an
  upgrade left without one its first cloud account (that makes a new account usable). A command-line session gets
  403 for these, so an agent that reads the session file can never approve itself.
- Console sessions are unchanged.

**Commands.** `csg person login|logout|whoami`; `csg me requests|deny|revoke|agents|
revoke-agent|accounts|mode|sessions|end-session`; `csg supervisor people|roles|accounts|
settings|audit|requests` for the supervisor's work except what is console-only (not yet:
showing one request by ID, changing a display name). `supervisor accounts rotate` reads the
new secret from a pipe or file, never from the terminal.
`csg supervisor recover` stays a local command on the server host.

### 17.10 Remote MCP over HTTPS (decided 2026-11-17)

An agent connects with just a URL: `https://<server>/mcp`. The server follows the MCP
authorization specification (2025-06-18): OAuth 2.1 with PKCE, discovery and dynamic client
registration. The owner chose that the credential is handed over through a one-time link.

**Discovery.**
- `/mcp` without a valid token answers 401 with
  `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"`.
- `GET /.well-known/oauth-protected-resource` (also `…/mcp`): `{resource: "<origin>/mcp",
  authorization_servers: ["<origin>"], bearer_methods_supported: ["header"]}`.
- `GET /.well-known/oauth-authorization-server`: issuer, `/oauth/authorize`, `/oauth/token`,
  `/oauth/register`; response type `code`, grant type `authorization_code`, PKCE `S256` only,
  token endpoint authentication `none` (public clients).

**Registration.** `POST /oauth/register` (RFC 7591), unauthenticated, with a JSON body
(`Content-Type: application/json`, so another website cannot register from a visitor's
browser): a `client_name` (no control or format characters) and
1-10 `redirect_uris`, each `https://…`, `http://` on a loopback host, or a private-use scheme
such as `cursor://` (never `javascript:`, `data:`, `file:` and the like, never a fragment). It
returns a `client_id` (`mcc_…`) for a public client (`token_endpoint_auth_method: none`).
Registering grants nothing. At most 500 registrations that never led to a connection may be
made in 24 hours, 20 from one address; such unused registrations are deleted after 24 hours,
and a registration not used for 90 days is deleted too (the client registers again). Behind
a proxy, the address is the client's only with `--trusted-proxy`; otherwise every client
shares the proxy's address and its limits.

**Sign-in.**
- `GET /oauth/authorize?response_type=code&client_id&redirect_uri&code_challenge&
  code_challenge_method=S256&state[&resource][&scope]`. The redirect URI must be one the
  client registered, exactly, except that the port of a loopback `http` URI may differ
  (RFC 8252) as long as it is a real port. An unknown client or redirect URI gets an error
  page, never a redirect; other errors go back to the client (a `state` over 1000 characters
  as `invalid_request`, without the state). PKCE S256 is required; `resource`, when sent, must be this
  server's `/mcp`. The server keeps the request for 10 minutes (at most 100 waiting, 10 from
  one address) and sends the browser to the console with a random key
  (`/?mcp-connect=KEY`), stored only as a hash; the link survives the console sign-in.
- The person, signed in to the console, sees the client's name, **the host the sign-in is
  sent to** (for a private-use scheme, the whole redirect URI without its query), and an agent
  name to give it, and approves or denies
  (`GET /api/v1/me/mcp-connections/{key}`, `POST …/approve {agent_name}` (console only),
  `POST …/deny`). The answer is the `redirect_url` the console sends the browser to: the
  redirect URI with a one-time `code` (valid 60 seconds) or `error=access_denied`, and `state`
  and `iss` (the issuer the client started at, whatever host the console was opened at).
- `POST /oauth/token` (form-encoded): `grant_type=authorization_code`, `code`, `redirect_uri`,
  `client_id`, `code_verifier` (and optionally `resource`). The code works once, with the
  right client, redirect URI (when sent) and verifier, while the approver is active; a code
  presented with a wrong one is burned. The answer is `{access_token, token_type: "Bearer", scope: "mcp"}`: the
  access token is the token of a new agent that belongs to the approver, exactly as after
  `csg login` (a same-name agent of that person is replaced). It lasts until the agent is
  revoked on the Agents page; there is no refresh token. Errors follow OAuth
  (`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`).
- Suspending or resetting the approver ends approvals not yet exchanged.

**The MCP endpoint.** `POST /mcp`, Streamable HTTP without server-sent events: one JSON-RPC
message or a batch per request, answered as `application/json`; notifications get 202 and
no body. `GET` and `DELETE` answer 405. A request whose `Origin` is not this server is
refused; there is no CORS. Against DNS rebinding this needs `--public-url`, since without it
"this server" follows the `Host` header; the bearer token, which a browser cannot send
cross-site without a preflight that is never granted, is the protection in either case. Protocol versions 2025-06-18, 2025-03-26; an
unknown `MCP-Protocol-Version` header is refused. 1 MiB per request. The tools are those of
`csg mcp` (§17.7) and go through the agent API, with its rules, limits and audit:
`list_accounts`, `request_access`, `check_status`, `revoke`, and `get_credential`, which
returns a **one-time link** instead of the secret:

- before making a link it checks that the request is the agent's and active; an agent has at
  most 20 unused links;
- the link is `<origin>/api/v1/credential-links/{token}`, valid for 60 seconds, usable once,
  with `POST` only (so a link preview cannot use it up);
- using it returns shell `export` lines (`ALIBABA_CLOUD_ACCESS_KEY_ID`, `…_SECRET`,
  `…_SECURITY_TOKEN`, or for AWS `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`; then `CSG_LEASE_ID`, `CSG_SERVER`,
  `CSG_CAPABILITY`, values single-quoted)
  and an `echo` to stderr saying until when it is valid, with `Cache-Control: no-store`; the
  tool tells the agent to run `eval "$(curl -fsS -X POST '<link>')"` (the link shell-quoted) in the shell that runs
  the cloud command, so the secret goes into that shell, not into the conversation; a link
  that is unknown, used or expired gets 404 and only an `echo` to stderr;
- the agent (active, owner active) and every release check of the credential endpoint are
  checked again when the link is used, and the use is audited as a credential fetch; making
  the link is audited too; the link token is stored only as a hash and masked in the logs,
  like the connection key.

### 17.11 Approval mode per cloud account (decided 2026-11-17; replaces the mode and level of §17.5)

A person signs in an agent once; after that, what the agent gets without asking is decided by
one rule per cloud account, which only that person sets.

- **Mode per account.** For each cloud account where a person has a role, the person chooses a
  mode: `read` (default), `write` or `full`. A request at or below the mode on that account is
  issued at once, with no approval and no code; a request above it waits for the person's
  approval in the console (§17.5 approval, unchanged). The role still comes first: what is
  automatic is the lower of the mode and the highest permission the role there allows.
- **The account's highest automatic level is removed.** Supervisors control access through
  roles; there is no second, per-account automatic ceiling. `PUT
  /api/v1/supervisor/accounts/{id}/auto-level` and `max_auto_level` are gone.
- `PUT /api/v1/me/accounts/{provider_id}/mode {mode, expires_in_seconds?}` sets it (person
  session, the person's own accounts only; 404 for an account they have no role on). A mode
  above `read` may carry an expiry (at most 30 days), after which it is `read`. As before, a
  command-line session needs a fresh authenticator code to raise a mode (§17.9); the console
  does not. `PUT /api/v1/me/approval-mode` is gone.
- `GET /api/v1/me/accounts` shows, per account, the role, the mode (`approval_mode`, with
  `approval_mode_expires_at`) and `automatic_up_to`. Agents still see only `automatic_up_to`.
- The mode is read when the request is made (a snapshot), as before. Removing a person's role
  on an account removes their mode there (and losing the supervisor flag removes it where no
  role binding is); resetting or suspending a person, or recovering a supervisor, puts every
  mode back to `read`. Changes are audited (`person.approval_mode_changed`, with the
  account); modes removed by such a change are listed as `removed_modes` in its event.
- **Upgrade.** A person's former single mode becomes their mode on each account where they
  hold a role, lowered to that account's former highest automatic level, with the former
  expiry. Nothing becomes more automatic than it was.

### 17.12 Credential lifetime and refresh (decided 2026-11-17; replaces "cannot be extended" in §17.6)

- **Lifetime of one key.** `ttl_seconds`, declared by the agent, within the limits of §17.4.
  The cloud rejects the key at its deadline even when Cloud Safeguard is down; Cloud Safeguard
  erases its copy then.
- **Refresh window.** A request may also declare `max_lifetime_seconds`: how long the agent
  wants to keep refreshing. Left out, it is 8 hours. It must be at least `ttl_seconds` and at
  most the supervisor setting `max_refresh_lifetime_seconds` (default 24 hours, at most 30
  days); a default above the setting is lowered to it. The window starts when the first key is
  issued: `refresh_until = issued_at + max_lifetime_seconds`. The approval shows it.
- `POST /api/v1/agent/access-requests/{id}/refresh` (agent token, own requests only): while the
  request is active, its current key has not expired and the window is open, Cloud Safeguard
  mints a new key under the same request, with the same policy, for `min(ttl_seconds,
  refresh_until − now)`. Below the provider minimum (900 s for real STS) it answers 409: make a
  new request. A refresh repeats every check of a release (agent and owner active, the owner's
  role still permits it, the account active, the IAM prohibition) but not the approval: a
  request approved above the mode may be refreshed within its window. At most one refresh
  attempt per request per 60 seconds, failed attempts included (429 otherwise). A lowered
  `max_refresh_lifetime_seconds` applies at once: a window is cut to `issued_at` + the
  current limit (but never below one key) at approval and at every refresh. The new key replaces the stored one; the earlier key
  stays valid at the cloud until its own deadline (an STS key cannot be withdrawn). Audited as
  `lease.refreshed` with the masked key ID and the new deadline. Revoking the request ends
  refreshes at once.
- The request view shows `max_lifetime_seconds`, `refresh_until` and `refresh_count`.
- **MCP.** `refresh_credential {request_id}` refreshes and then hands the new key over as
  `get_credential` does (a credential file for `csg mcp`, a one-time link for remote MCP).
- **CLI.** `csg access refresh ID`; `csg credential --lease ID --process aws|aliyun` prints the
  JSON an SDK credential process expects (AWS `credential_process`, Alibaba Cloud CLI
  `External` mode), refreshing first when the key has less than 5 minutes left, so a
  long-running SDK keeps itself supplied within the window.

### 17.13 AWS (decided and implemented 2026-11-17)

- A cloud account of type `aws` is reached the same way as Alibaba Cloud: one broker identity
  that can only call `sts:AssumeRole` on one role (for example `csg-access`), and every key is
  `AssumeRole` with a session policy rendered from a fixed read/write/full template, so the
  key can do only what both the role and the session policy allow. No users, policies or keys
  are created per request.
- The role allows exactly what the templates can ask for and denies `iam:*`,
  `organizations:*` and `sts:AssumeRole`; the console and QUICKSTART §2.9 show it, and a test
  keeps it in step with the templates. Not `AdministratorAccess` or `PowerUserAccess`: the
  broker key could reach everything they allow. The connection test calls
  `GetCallerIdentity`, assumes the role once with a policy that allows nothing useful, and
  once more with a policy that allows only four harmless IAM reads (`GetAccountSummary`,
  `ListUsers`, `ListRoles`, `ListPolicies`); if any succeeds, the role allows IAM and the test
  passes with a warning (`warning` in the result, audited). If the check cannot run, the
  test passes with a warning that says so.
- First resource type: `s3` (bucket; objects are items). `resource_name` is the bucket name
  (3-63 lowercase letters, digits, dots and dashes). read = `s3:GetObject`,
  `s3:GetObjectVersion`, `s3:GetBucketLocation`, `s3:ListBucket`, `s3:ListBucketVersions`,
  `s3:ListBucketMultipartUploads`, `s3:ListMultipartUploadParts` (listed, not `s3:Get*`,
  which would also read bucket policies and ACLs); write adds
  `s3:PutObject`, `s3:DeleteObject`, `s3:AbortMultipartUpload`; full adds `s3:CreateBucket`,
  `s3:DeleteBucket`. Reading or writing bucket policies, ACLs and ownership is in no template,
  and a template may allow only the actions its resource type declares.
- Policies use version `2012-10-17` and the resources `arn:aws:s3:::BUCKET` and
  `arn:aws:s3:::BUCKET/*`. Every session policy also carries
  `{"Effect":"Deny","Action":["iam:*","organizations:*","account:*","sso:*","sso-directory:*","sso-oauth:*","identitystore:*","signin:*","sts:AssumeRole*","sts:GetFederationToken","sts:GetSessionToken","sts:GetServiceBearerToken"],"Resource":"*"}`,
  and the IAM guard refuses those identity and account services of every cloud (and RAM) in
  any capability.
- The region must be a region name (`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`, such as `eu-west-1`;
  Alibaba Cloud regions have their own shape, such as `cn-hangzhou`): it becomes part of the
  STS host name and of `AWS_REGION`. Only the standard partition (`arn:aws:`) is supported;
  `aws-cn` and `aws-us-gov` are refused.
- STS is called at the account's region (`sts.REGION.amazonaws.com`, `us-east-1` by default),
  signed with Signature Version 4; validity 900 s to the role's maximum session duration.
  The account ID is the 12 digits of the role ARN (`arn:aws:iam::ACCOUNT:role/NAME`).
- The credential is handed over as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, `AWS_REGION` and `AWS_DEFAULT_REGION` (plus `CSG_*`), in the
  envelope, `--export`, `csg exec`, the MCP credential file and the one-time link.
- `csg exec` never passes the parent shell's own cloud variables (`AWS_*`, `ALIBABA_CLOUD_*`,
  `ALICLOUD_*`, `ALIYUN_*`, `CSG_*`) to the command: only the request's credential.
- Mock mode: the mock cloud serves `GET /v1/s3/buckets/{bucket}/objects`, `GET|PUT|DELETE
  /v1/s3/buckets/{bucket}/objects/{key}` and `GET /v1/iam/users` (always refused), with the
  fixture bucket `claudecode`. Its S3 and IAM routes accept only tokens of AWS accounts, and
  its ECS, DNS and RAM routes only tokens of Alibaba Cloud accounts.
- The broker identity may later come from the platform instead of a stored key (instance
  role, OIDC federation); the agent side does not change.

### 17.14 Long-lived credentials (decided and implemented 2026-11-17)

Some uses need a key that does not expire (a CDN origin, a bucket sync). Cloud Safeguard can
create a cloud user with an access key for them, under strict control. The owner's decisions:
a separate key per account does this (the broker key never gets IAM rights), and a key is
deleted in the cloud as soon as its owner is no longer allowed to hold it.

**Enabling, per cloud account (supervisor, console only).**
- `PUT /api/v1/supervisor/accounts/{id}/user-admin {access_key_id, access_key_secret}` stores
  a second key, encrypted like the broker key and never shown again (masked ID only). Its own
  policy, shown in the console, allows only:
  - AWS: `iam:CreateUser` and `iam:PutUserPolicy` on
    `arn:aws:iam::ACCOUNT:user/csg/csg-*`
    with the condition `iam:PermissionsBoundary =
    arn:aws:iam::ACCOUNT:policy/cloud-safeguard-boundary`, and `iam:ListAccessKeys`,
    `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `iam:DeleteUserPolicy`, `iam:DeleteUser` on
    `user/csg/csg-*`. The boundary is a customer managed policy `cloud-safeguard-boundary`
    the supervisor creates first; the console shows its content, the role's permission
    policy of §17.13: whatever is put on a `csg` user, it can never do more, and never IAM.
    CreateUser sets the boundary itself; `iam:PutUserPermissionsBoundary` is not needed
    (live-tested), so the key can never change a boundary later.
  - Alibaba Cloud: `ram:CreateUser`, `ram:DeleteUser`, `ram:ListAccessKeys`,
    `ram:CreateAccessKey`, `ram:DeleteAccessKey` on `user/csg-*`; `ram:CreatePolicy`,
    `ram:DeletePolicy` on `policy/csg-*`; and `ram:AttachPolicyToUser`,
    `ram:DetachPolicyFromUser` on both together (a `csg` policy onto a `csg` user only). RAM
    has no permissions boundary, and this key may write `csg` policies with any content:
    whoever holds it can give a `csg` user full access to the account. It is an account
    administrator's key in effect, and the console says so.
- The connection test of the second key checks it can sign a harmless call, and refuses a
  key whose own user is one Cloud Safeguard manages (path `/csg/`, or a name starting with
  `csg-`): such a key could change its own policies.
- `DELETE /api/v1/supervisor/accounts/{id}/user-admin` removes it; refused (409) while
  long-lived credentials of that account exist. Both are audited at critical level.

**Who.** Supervisors, and people a supervisor has allowed (`PATCH
/api/v1/supervisor/people/{id} {long_lived: true}`; a raise, so a command-line session
needs a code). The person must also hold a role on the account that permits the
permission. Anyone else, and their agents, are refused.

**Asking.** `POST /api/v1/me/long-lived` (person session) or `POST
/api/v1/agent/long-lived` (agent token; MCP `request_long_lived_credential`) with
`cloud_account_id`, `resource`, `permission`, optional `resource_name`, and `reason`
(required). An unknown account and one the person has no role on get the same 403, before
the resource is looked at. The checks of §17.4 apply (template, name pattern, role, IAM prohibition), plus
the person's permission and the account's second key. The answer is `{id, status: pending,
link, expires_at}`: a console link `/?long-lived=KEY` valid for one hour. The key is stored
only as a hash and masked in the logs. Nothing is created and no secret goes to the agent.

**Creating (console only).** The agent's owner, or the person who asked, opens the link
signed in to the console (to anyone else it does not exist). The page shows the account,
resource type, name, permission and reason, who asked, and what will be created. The person
confirms (`POST /api/v1/me/long-lived-requests/{key}/create`) or declines (`…/deny`). Every
check runs again. Cloud Safeguard then creates, in the cloud:
- a user `csg-<id>` (AWS: path `/csg/`, with the boundary),
- a policy rendered from the same read/write/full template, with the cloud's IAM deny
  (AWS: an inline user policy; Alibaba Cloud: a custom policy `csg-<id>`, attached),
- an access key,

and answers with the access key ID and secret, once. Cloud Safeguard stores the user name,
the policy name and the access key ID, never the secret. If any step fails, what was created
is deleted again and the request is `failed` with the cloud's error; if that deletion fails
too, the credential is `revoke_failed` (below), named `csg-<id>`. After the cloud calls every
check runs once more: if the right went meanwhile (an automatic deletion skips a credential
still being created), the credential is deleted and the secret is not shown.

**No expiry, and deletion.**
- The key lives until it is revoked: by its owner (`POST /api/v1/me/long-lived/{id}/revoke`)
  or any supervisor (`POST /api/v1/supervisor/long-lived/{id}/revoke`), from the console or
  the command line. Revoking lists the user's access keys and deletes each (so a key whose
  ID was never recorded goes too), then the policy and the user; parts already gone are
  skipped. Only `csg-` users are ever deleted.
- It is revoked automatically, with the same deletion, when its owner is suspended or reset,
  loses the permission (flag removed, or supervisor flag removed without the flag), loses the
  role on the account or keeps a role that no longer permits its permission, or when the
  account is disabled.
- If a deletion fails in the cloud, the credential is `revoke_failed` with the error; a
  supervisor can retry the revoke. It is never shown as gone while the key may still exist.
- At startup, a credential left `creating` or `revoking` by a crash becomes `revoke_failed`
  and is deleted; then every active credential is checked again, like leases, and deleted
  if its owner lost the right while the server was down. Every sweep checks the active ones
  again too, so a change made outside the server (`csg supervisor recover`, a database
  edit) deletes them within a sweep interval.
- `GET /api/v1/me/long-lived` lists a person's own; `GET /api/v1/supervisor/long-lived`
  lists all (account, cloud user, scope, owner, who asked, created, status), at most 500,
  newest first. `expires_at` is the link's expiry and is present only while a request is
  pending (or expired): a created credential has none.
- Every request, create, deny, revoke and failure is audited; create and revoke at critical
  level. The secret and the link key never reach a log or the audit log.

**Mock mode.** For a mock account, no cloud is called: the "secret" is a signed mock token
naming the credential, which the mock cloud accepts while the credential is active, with the
credential's policy.

### 17.8 Implementation status

| Part | Status |
| --- | --- |
| People, supervisors, setup, login, sessions (§17.1, §17.3 item 1) | implemented, schema version 3 |
| Role bindings and the supervisor API (§17.2) | implemented and enforced on every request |
| `csg init` first supervisor, `csg supervisor recover` | implemented |
| Agent ownership and agent-first sign-in (§17.3 item 2) | implemented, schema version 4 |
| Five-field request, permission levels, owner approval (§17.4, §17.5) | implemented, schema version 5 |
| Approval modes and per-account highest automatic level (§17.5) | implemented in schema version 6; replaced by §17.11 |
| Supervisor API for cloud accounts, settings, audit and the emergency stop | implemented |
| Supervisors are Administrator on every cloud account (§17.1) | implemented |
| Removal of the admin token and the §16 agent model (§17.7a) | implemented, schema version 8 |
| Person sign-in for `csg` with guarded sessions (§17.9) | implemented, schema version 9 |
| Remote MCP over HTTPS with OAuth sign-in (§17.10) | done; tried with Claude Code 2.1.221 (sign-in, tools, credential link) |
| Approval mode per cloud account (§17.11), refresh (§17.12) | implemented, schema version 11 |
| AWS (§17.13) | implemented with S3; tested against a fake STS and in mock mode, not against live AWS |
| Long-lived credentials (§17.14) | implemented, schema version 12; tested in mock mode and against fake IAM and RAM, not against a live cloud |
| Lifecycle revocation for owned agents (§17.6) | implemented: owner suspended or reset, binding lowered or removed |
| MCP server (§17.7) and agent CLI (`csg login` sign-in, `accounts`, `access`, `exec --account`) | implemented |
| Console redesign (sign-in, Inbox, Agents, Cloud accounts, Activity, People, Settings) | implemented; the admin-token console is removed |

The HTTP API:

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
  for `POST /api/v1/agent/leases/{id}/credential` and `.../revoke`. `GET /api/v1/agent/me`,
  `GET /api/v1/agent/leases[/{id}]` and `POST /api/v1/agent/heartbeat` complete the agent API.
- `GET /api/v1/me/requests[?status=pending]`,
  `POST /api/v1/me/requests/{id}/approve|deny|revoke` (person session)
- `PUT /api/v1/me/accounts/{provider_id}/mode` (person session; §17.11)
- `GET /api/v1/me/accounts` (person session): the person's own cloud accounts with their
  role, their approval mode there and what their agents get there automatically
- `POST /api/v1/agent/access-requests/{id}/refresh` (agent token; §17.12)
- Supervisor session:
  - cloud accounts: `GET|POST /api/v1/supervisor/accounts`,
    `GET|PATCH /api/v1/supervisor/accounts/{id}`,
    `POST /api/v1/supervisor/accounts/{id}/rotate|test`
  - settings: `GET|PUT /api/v1/supervisor/settings`
  - audit: `GET /api/v1/supervisor/audit`, `GET /api/v1/supervisor/audit/verify`
  - emergency stop: `GET /api/v1/supervisor/leases[/{id}]`,
    `POST /api/v1/supervisor/leases/{id}/deny|revoke`. There is no approve route: a
    supervisor can stop any request or credential, never grant one.
  - Every action is recorded under the supervisor's own name, and deny and revoke events
    also name the agent and its owner. Account edits record the old and new role ARN, region
    and status; a role ARN or status change is a warning. Creating a cloud account gives
    nobody a role on it, its creator included.
- Every state-changing request runs to completion once it has started, even if the client
  disconnects, so a change is never left without its follow-up revocations and audit record.
