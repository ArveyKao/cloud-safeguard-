# Cloud Safeguard — API Reference (v0.1)

This is a concise reference with curl examples. The **normative** contract is
[CONTRACT.md](CONTRACT.md) §2–§10; shared wire types are in `internal/model/model.go`.
If this page and the contract disagree, the contract wins.

- Base URL (default): `http://127.0.0.1:8787`
- All `/api/v1/*` responses are JSON. Send `Content-Type: application/json` on
  `POST`/`PATCH`/`PUT`.
- The embedded web console is served on the same origin at `/`; health at `/healthz`;
  the demo mock cloud at `/mock-cloud/`.

---

## 1. Authentication

Every `/api/v1/*` request needs a bearer token:

```
Authorization: Bearer <token>
```

| Token | Prefix | Used for |
| --- | --- | --- |
| Agent token | `csg_agt_` | `/api/v1/agent/*` only |
| Admin token | `csg_adm_` | `/api/v1/admin/*` only (and `POST /admin/login`) |

- A token of the wrong kind is rejected `401 unauthorized`.
- A suspended/revoked agent is rejected `403 forbidden` on all agent endpoints.
- Tokens are shown once (admin at `csg init`, agent at create/rotate) and stored as
  SHA-256 hashes. There is no endpoint that returns a token again.
- `POST /api/v1/admin/login` validates the admin token (the login screen uses it) and
  returns `{"ok":true,"role":"admin","version":"0.1.0"}`.

Shell setup used by the examples below:

```bash
export CSG_SERVER='http://127.0.0.1:8787'
export ADMIN_TOKEN='csg_adm_...'     # admin token from csg init
export AGENT_TOKEN='csg_agt_...'     # agent token from create/rotate
export AUTH_ADMIN="Authorization: Bearer $ADMIN_TOKEN"
export AUTH_AGENT="Authorization: Bearer $AGENT_TOKEN"
```

The examples pipe JSON through `jq` for readability; it is optional.

---

## 2. Envelopes, pagination, errors

**Success** (HTTP 200/201):

```json
{ "data": { "...": "endpoint-specific payload" } }
```

**List** (`model.ListResponse[T]`):

```json
{ "data": { "items": [ { "...": "..." } ], "total": 42 } }
```

Query parameters: `limit` (default 50, max 200) and `offset` (default 0).

**Error** (`model.ErrorBody`):

```json
{
  "error": {
    "code": "lease_not_active",
    "message": "lease is not active",
    "details": { "status": "pending" }
  }
}
```

`details` is optional and never contains secrets. The `message` is human-readable and not
frozen; the `code` is stable.

| HTTP | `error.code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, invalid/unknown params, invalid duration, invalid policy settings, failed validation |
| 401 | `unauthorized` | Missing/unknown/rotated token, wrong token kind, bad admin token |
| 403 | `forbidden` | Agent suspended/revoked; action not allowed for this identity |
| 404 | `not_found` | Unknown object, or an object owned by another agent (isolation) |
| 409 | `conflict` | State conflict (e.g. approve a non-pending lease, revoke a terminal lease) |
| 409 | `lease_not_active` | Credential fetch/use requires an `active` lease |
| 410 | `credential_unavailable` | Credential was scrubbed (revoked/expired) |
| 429 | `rate_limited` | Per-agent request rate exceeded |
| 502 | `provider_error` | Cloud/STS provider failure while minting/testing |
| 500 | `internal` | Unexpected server error |

**Common object shapes** (full JSON tags in `internal/model/model.go`):

- `Lease`: `id` (`lea_...`), `agent_id/name`, `capability_id/name`, `provider_id/name/mode`,
  `risk`, `params`, `reason`, `requested_ttl_seconds`, `effective_ttl_seconds`, `status`
  (`pending|active|denied|expired|revoked|failed`), `decision{outcome,effective_ttl_seconds,reasons[]}`,
  `break_glass`, `approved_by`, `approval_note`, `denied_reason`, `revoke_reason`,
  `failure_reason`, `session_name`, `credential_available`, `credential_fingerprint`,
  `created_at`, `approved_at`, `issued_at`, `expires_at`, `revoked_at`.
- `DecisionReason`: `rule`, `outcome` (`allow|require_approval|deny`), `detail`.
- `CredentialEnvelope`: `credential{provider_id,provider_mode,lease_id,access_key_id,
  access_key_secret,security_token,expires_at}` + `env[]` of `{name,value}`.

---

## 3. Agent API (`/api/v1/agent`, bearer = agent token)

| Method | Path | Request | Success (`data`) |
| --- | --- | --- | --- |
| GET | `/agent/me` | — | `{agent: Agent, active_leases: int, server_time: time}` |
| GET | `/agent/capabilities` | — | `ListResponse[Capability]` (only enabled + granted) |
| POST | `/agent/leases` | `CreateLeaseInput` | `Lease` (HTTP 201) |
| GET | `/agent/leases?status=&limit=&offset=` | — | `ListResponse[Lease]` (own leases) |
| GET | `/agent/leases/{id}` | — | `Lease` (404 if owned by another agent) |
| POST | `/agent/leases/{id}/credential` | — | `CredentialEnvelope` |
| POST | `/agent/leases/{id}/revoke` | `RevokeLeaseInput` | `Lease` |
| POST | `/agent/heartbeat` | — | `{ok: true, server_time: time}` |

### 3.1 Who am I

```bash
curl -s -H "$AUTH_AGENT" "$CSG_SERVER/api/v1/agent/me" | jq .
```

```json
{
  "data": {
    "agent": {
      "id": "agt_...", "name": "claude-code", "status": "active",
      "grants": ["aliyun.cloud.read", "aliyun.dns.manage"],
      "max_ttl_seconds": 3600, "max_concurrent_leases": 3,
      "token_prefix": "csg_agt_7f3a", "last_seen_at": "2026-11-08T05:40:00Z"
    },
    "active_leases": 1,
    "server_time": "2026-11-08T05:40:00Z"
  }
}
```

### 3.2 List capabilities you can request

```bash
curl -s -H "$AUTH_AGENT" "$CSG_SERVER/api/v1/agent/capabilities" | jq .
```

### 3.3 Create a lease (auto-approved, pending or denied — always 201)

```bash
curl -s -X POST "$CSG_SERVER/api/v1/agent/leases" \
  -H "$AUTH_AGENT" -H 'Content-Type: application/json' \
  -d '{
    "capability_id": "aliyun.dns.manage",
    "params": {"domain": "arveykao.com"},
    "ttl_seconds": 600,
    "reason": "add ACME DNS-01 TXT record",
    "break_glass": false
  }' | jq .
```

`CreateLeaseInput`: `capability_id` (required), `params` (map), `ttl_seconds`
(0 → capability default), `reason`, `break_glass` (must be `true` for `critical`
capabilities; forces human approval).

The same endpoint returns a durable lease in all three outcome cases:
`active` (auto-approve), `pending` (awaiting human), `denied` (policy refusal), or
`failed` (mint error). Read `data.status`, `data.decision.outcome` and
`data.decision.reasons[]` for the explainable result.

### 3.4 List / get your leases

```bash
curl -s -H "$AUTH_AGENT" "$CSG_SERVER/api/v1/agent/leases?status=active&limit=20" | jq .
curl -s -H "$AUTH_AGENT" "$CSG_SERVER/api/v1/agent/leases/lea_..." | jq .
```

### 3.5 Fetch the short-lived credential

Only while the lease is `active` and not expired; each fetch is audited.

```bash
curl -s -X POST -H "$AUTH_AGENT" \
  "$CSG_SERVER/api/v1/agent/leases/lea_.../credential" | jq .
```

```json
{
  "data": {
    "credential": {
      "provider_id": "prv_...", "provider_mode": "mock",
      "lease_id": "lea_...",
      "access_key_id": "LTAI...", "access_key_secret": "<redacted>",
      "security_token": "<redacted>",
      "expires_at": "2026-11-08T05:55:00Z"
    },
    "env": [
      {"name": "ALIBABA_CLOUD_ACCESS_KEY_ID", "value": "..."},
      {"name": "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "value": "..."},
      {"name": "ALIBABA_CLOUD_SECURITY_TOKEN", "value": "..."},
      {"name": "CSG_LEASE_ID", "value": "lea_..."},
      {"name": "CSG_SERVER", "value": "http://127.0.0.1:8787"},
      {"name": "CSG_CAPABILITY", "value": "aliyun.dns.manage"}
    ]
  }
}
```

Errors: `409 lease_not_active` for pending/terminal leases, `410 credential_unavailable`
when the ciphertext was scrubbed. The env var list/order is frozen by CONTRACT §3.

To use it as a shell environment (fetches again, which is audited):

```bash
eval "$(CSG_SERVER=$CSG_SERVER CSG_TOKEN=$AGENT_TOKEN ./bin/csg credential --lease lea_... --export)"
```

### 3.6 Revoke / cancel your own lease

Works from `pending` or `active`; terminal leases return `409`.

```bash
curl -s -X POST -H "$AUTH_AGENT" -H 'Content-Type: application/json' \
  -d '{"reason":"work finished"}' \
  "$CSG_SERVER/api/v1/agent/leases/lea_.../revoke" | jq .
```

### 3.7 Heartbeat (optional)

```bash
curl -s -X POST -H "$AUTH_AGENT" "$CSG_SERVER/api/v1/agent/heartbeat" | jq .
```

---

## 4. Admin API (`/api/v1/admin`, bearer = admin token)

| Method | Path | Body / query | Success (`data`) |
| --- | --- | --- | --- |
| POST | `/admin/login` | — | `LoginResult` |
| GET | `/admin/overview` | — | `Overview` |
| GET | `/admin/providers` | — | `ListResponse[Provider]` |
| POST | `/admin/providers` | `CreateProviderInput` | `Provider` (201) |
| GET | `/admin/providers/{id}` | — | `Provider` |
| PATCH | `/admin/providers/{id}` | `UpdateProviderInput` | `Provider` |
| POST | `/admin/providers/{id}/rotate` | `RotateProviderCredentialInput` | `Provider` |
| POST | `/admin/providers/{id}/test` | — | `{ok:bool, message:string, tested_at:time}` |
| GET | `/admin/capabilities` | — | `ListResponse[Capability]` |
| POST | `/admin/capabilities` | `Capability` | `Capability` (201) |
| PATCH | `/admin/capabilities/{id}` | partial `Capability` | `Capability` |
| GET | `/admin/agents` | — | `ListResponse[Agent]` |
| POST | `/admin/agents` | `CreateAgentInput` | `AgentWithToken` (201) |
| GET | `/admin/agents/{id}` | — | `Agent` |
| PATCH | `/admin/agents/{id}` | `UpdateAgentInput` | `Agent` |
| POST | `/admin/agents/{id}/suspend` | — | `Agent` |
| POST | `/admin/agents/{id}/activate` | — | `Agent` |
| POST | `/admin/agents/{id}/token/rotate` | — | `AgentWithToken` |
| GET | `/admin/leases` | `status,agent_id,capability_id,limit,offset` | `ListResponse[Lease]` |
| GET | `/admin/leases/{id}` | — | `Lease` |
| POST | `/admin/leases/{id}/approve` | `ApproveLeaseInput` | `Lease` |
| POST | `/admin/leases/{id}/deny` | `DenyLeaseInput` | `Lease` |
| POST | `/admin/leases/{id}/revoke` | `RevokeLeaseInput` | `Lease` |
| GET | `/admin/audit` | `action,actor_type,actor_id,severity,since,limit,offset` | `ListResponse[AuditEvent]` (newest first) |
| GET | `/admin/audit/verify` | — | `AuditVerifyResult` |
| GET | `/admin/policy` | — | `PolicySettings` |
| PUT | `/admin/policy` | `PolicySettings` | `PolicySettings` |

### 4.1 Login and overview

```bash
curl -s -X POST -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/login" | jq .
curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/overview" | jq .
```

`Overview` includes `counts` (agents, active agents, capabilities, providers, active
leases, pending leases, events 24h, denied leases 24h), `risk_breakdown`, `policy`,
`vault{configured,key_fingerprint,secrets_stored}`, up to 20 `pending_leases`, up to 20
`active_leases`, up to 20 `recent_events`, `providers`, `version`, `uptime_seconds`,
`server_time`.

### 4.2 Providers

```bash
# list
curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/providers" | jq .

# create (type must be "aliyun"; mode "sts" or "mock")
curl -s -X POST "$CSG_SERVER/api/v1/admin/providers" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{
    "name": "aliyun-prod",
    "type": "aliyun",
    "mode": "sts",
    "region": "cn-hangzhou",
    "role_arn": "acs:ram::<account-id>:role/csg-agent",
    "access_key_id": "LTAI...",
    "access_key_secret": "..."
  }' | jq .

# test connectivity (sts mode: signed sts:GetCallerIdentity)
curl -s -X POST -H "$AUTH_ADMIN" \
  "$CSG_SERVER/api/v1/admin/providers/prv_.../test" | jq .

# rotate the broker credential (new AccessKey; existing leases unaffected)
curl -s -X POST "$CSG_SERVER/api/v1/admin/providers/prv_.../rotate" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{"access_key_id":"LTAI...new","access_key_secret":"..."}' | jq .
```

`Provider` exposes only `access_key_id_masked` (e.g. `LTAI****9f2c`) — never the raw
credential. `PATCH` accepts `name`, `region`, `role_arn`, `status` (`active|disabled`).
For `mock` mode, missing AccessKey values are replaced with generated placeholders.

### 4.3 Capabilities

```bash
curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/capabilities" | jq .

# create a custom capability (id/builtin are ignored; provider_type must be aliyun)
curl -s -X POST "$CSG_SERVER/api/v1/admin/capabilities" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{
    "name": "Read one DNS zone",
    "description": "Describe records in a single domain",
    "provider_type": "aliyun",
    "risk": "low",
    "policy_template": "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"alidns:DescribeDomainRecords\"],\"Resource\":[\"acs:alidns:*:*:domain/{{domain}}\"]}]}",
    "params": [{"name":"domain","description":"DNS domain","required":true,
                "pattern":"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"}],
    "default_ttl_seconds": 900,
    "max_ttl_seconds": 1800,
    "enabled": true
  }' | jq .
```

Validation: valid risk, `default_ttl_seconds > 0`, `default <= max`, `max <=
settings.max_lease_ttl_seconds`, policy template valid JSON after rendering with sample
params. `PATCH` can toggle `enabled`, edit the description/TTLs, and (custom capabilities
only) the policy template, risk and params.

### 4.4 Agents

```bash
# create — response contains the one-time token
curl -s -X POST "$CSG_SERVER/api/v1/admin/agents" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{
    "name": "ops-agent",
    "description": "Manages DNS and ECS",
    "grants": ["aliyun.cloud.read", "aliyun.dns.manage"],
    "max_ttl_seconds": 1800,
    "max_concurrent_leases": 2
  }' | jq .
# → data.agent{...}, data.token: "csg_agt_..." (show once; never retrievable again)

curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/agents" | jq .
curl -s -X POST -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/agents/agt_.../suspend" | jq .
curl -s -X POST -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/agents/agt_.../activate" | jq .
curl -s -X POST -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/agents/agt_.../token/rotate" | jq .
# → new one-time token; the old token is invalid immediately
```

`PATCH /admin/agents/{id}` accepts `name`, `description`, `grants`,
`max_ttl_seconds`, `max_concurrent_leases`, `status`; all grants must be existing
capability IDs. Defaults for new agents are the global settings values.

### 4.5 Leases: review, approve, deny, revoke

```bash
curl -s -H "$AUTH_ADMIN" \
  "$CSG_SERVER/api/v1/admin/leases?status=pending" | jq .

# approve (optional ttl_seconds and note; TTL must be <= capability/agent/global max)
curl -s -X POST "$CSG_SERVER/api/v1/admin/leases/lea_.../approve" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{"ttl_seconds": 600, "note": "ACME renewal"}' | jq .

# deny (reason required, 1–500 chars)
curl -s -X POST "$CSG_SERVER/api/v1/admin/leases/lea_.../deny" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason": "change window not approved"}' | jq .

# revoke (pending or active)
curl -s -X POST "$CSG_SERVER/api/v1/admin/leases/lea_.../revoke" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason": "incident resolved"}' | jq .
```

Approval revalidates capability enabled + provider active and clamps TTL; on mint failure
the lease becomes `failed` and the response is still 200 with `failure_reason`.
Revoking an `active` lease scrubs the stored credential.

### 4.6 Audit

```bash
curl -s -H "$AUTH_ADMIN" \
  "$CSG_SERVER/api/v1/admin/audit?severity=critical&limit=20" | jq .
curl -s -H "$AUTH_ADMIN" \
  "$CSG_SERVER/api/v1/admin/audit?action=lease.revoked" | jq .
curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/audit/verify" | jq .
```

```json
{ "data": { "ok": true, "events": 57, "message": "audit chain verified" } }
```

On failure: `{"ok":false,"first_invalid_seq":N,"message":"..."}`. Events are returned
newest-first and include `seq`, `id`, `time`, actor fields, `action`, `status`, `severity`,
target fields, `metadata`, `prev_hash`, `hash`.

### 4.7 Policy settings

```bash
curl -s -H "$AUTH_ADMIN" "$CSG_SERVER/api/v1/admin/policy" | jq .

curl -s -X PUT "$CSG_SERVER/api/v1/admin/policy" \
  -H "$AUTH_ADMIN" -H 'Content-Type: application/json' \
  -d '{
    "auto_approve_max_risk": "low",
    "auto_approve_max_ttl_seconds": 900,
    "max_lease_ttl_seconds": 3600,
    "pending_timeout_seconds": 600,
    "max_concurrent_leases_per_agent": 3,
    "leases_per_minute_per_agent": 6,
    "require_reason_for_risk": "medium"
  }' | jq .
```

Invalid settings (unknown risk tier, non-positive limits, `max < auto max`) → `400
invalid_request`; every change is audited as `policy.updated` with non-secret before/after
metadata.

---

## 5. Mock cloud API (`/mock-cloud/…`, demo/test only)

Mounted only when at least one `mock` provider exists. **Not** a security boundary; use it
for the demo and tests. Auth uses the mock credential from the agent credential endpoint:

```
Authorization: Bearer <ALIBABA_CLOUD_SECURITY_TOKEN>
```

Responses are Aliyun-shaped JSON (no `{"data": ...}` envelope). Allowed actions are checked
against the lease's rendered IAM policy; out-of-policy calls return `403 Forbidden.RAM`.

| Method | Path | IAM action |
| --- | --- | --- |
| GET | `/mock-cloud/v1/ecs/instances` | `ecs:DescribeInstances` |
| GET | `/mock-cloud/v1/ecs/instances/{id}` | `ecs:DescribeInstances` |
| POST | `/mock-cloud/v1/ecs/instances/{id}/restart` | `ecs:RebootInstance` |
| POST | `/mock-cloud/v1/ecs/instances/{id}/start` | `ecs:StartInstance` |
| POST | `/mock-cloud/v1/ecs/instances/{id}/stop` | `ecs:StopInstance` |
| GET | `/mock-cloud/v1/dns/zones` | `alidns:DescribeDomains` |
| GET | `/mock-cloud/v1/dns/zones/{zone}/records` | `alidns:DescribeDomainRecords` |
| POST | `/mock-cloud/v1/dns/zones/{zone}/records` | `alidns:AddDomainRecord` |
| DELETE | `/mock-cloud/v1/dns/zones/{zone}/records/{rid}` | `alidns:DeleteDomainRecord` |

```bash
# after: eval "$(./bin/csg credential --lease lea_... --export)"
curl -s -H "Authorization: Bearer $ALIBABA_CLOUD_SECURITY_TOKEN" \
  "$CSG_SERVER/mock-cloud/v1/ecs/instances" | jq .

curl -s -X POST \
  -H "Authorization: Bearer $ALIBABA_CLOUD_SECURITY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"www","type":"A","value":"8.153.177.205","ttl":600}' \
  "$CSG_SERVER/mock-cloud/v1/dns/zones/arveykao.com/records" | jq .
```

Record body: `name` = RR (`@` for apex), `type` ∈ `A|AAAA|CNAME|TXT|MX`, non-empty
`value`, `ttl` 60–86400 (default 600). Fixtures (per process, in-memory): account
`1234567890123456`; ECS `i-2ze0demo001` (`web-01`, running), `i-2ze0demo002`
(`worker-01`, stopped), `i-2ze0demo003` (`db-01`, running); DNS zones `arveykao.com` and
`guanlanstudio.com`. Errors use Aliyun codes: `401 InvalidSecurityToken[.Expired|.Revoked]`,
`403 Forbidden.RAM`, `404 InvalidInstance.NotFound|InvalidDomain.NotFound`. Every call is
audited as `cloud.api_called` (or `cloud.api_denied` on failure).

The `csg` CLI wraps this: `csg mock request METHOD /v1/PATH [JSON_BODY]` (uses
`ALIBABA_CLOUD_SECURITY_TOKEN`; never prints the token).

---

## 6. Health

```bash
curl -s "$CSG_SERVER/healthz" | jq .
# {"status":"ok","version":"0.1.0","name":"Cloud Safeguard","time":"..."}
```

Not wrapped in the `data` envelope; no auth.

---

## 7. CLI equivalents

Almost everything here has a CLI wrapper (`csg request`, `csg credential`,
`csg leases approve`, `csg providers rotate`, `csg audit verify`, …). See
[QUICKSTART.md](QUICKSTART.md) and CONTRACT §9. For automation, the CLI and API are
interchangeable; the CLI is a thin client over the same endpoints.
