# Cloud Safeguard — Quickstart

Two paths:

- **Part 1 — Demo (5 minutes, no cloud account):** build the binary, bootstrap a throwaway
  instance with the built-in mock cloud, and walk through auto-approve, least privilege,
  human approval, denial, break-glass revocation and audit verification.
- **Part 2 — Real Alibaba Cloud `sts` mode:** wire a RAM user + RAM role into the platform
  and mint real short-lived STS credentials.

Part 1 commands are the supported demo/verification path. Part 2 commands require a real
Alibaba Cloud account and are **not exercised by this build's automated checks** (the
`sts` signer is unit-tested against a fake STS endpoint); verify them in your account
before relying on them.

---

## Prerequisites

- Go 1.24+ (`go version`)
- Node.js ≥ 20 and npm (needed by `make build` for the embedded console)
- macOS or Linux, a free loopback port (`8787` for the default address, `18787` for the
  scripted demo)
- No cloud account, no credentials, for Part 1

---

# Part 1 — Demo mode (mock cloud)

## 1.1 Build

```bash
cd /path/to/cloud-safeguard
make build
# → bin/csg (single binary with the web console embedded)
```

`make build` installs web dependencies, builds the React console into `web/dist`, then
builds `bin/csg`. `make test` runs the Go suite; `make vet` runs `go vet`.

## 1.2 Bootstrap a throwaway instance

```bash
./bin/csg init --demo --data-dir .demo/data
```

This creates `.demo/data` (mode 0700) with:

- `master.key` (0600) — protects the vault;
- `csg.db` — SQLite store (no plaintext secrets);
- 5 built-in capabilities, the `demo-aliyun` mock provider, and two demo agents:
  `claude-code` and `hermes-researcher`.

It prints the **admin token**, an admin token prefix, and **one-time agent tokens** for
the demo agents. They are shown exactly once and are never retrievable again.

> Save the tokens now, e.g. in a password manager or a 0600 file outside the repo.
> If you lose an agent token, rotate it later with `csg agents rotate-token ID`.
> If you lose the admin token, `csg init --force --data-dir <dir>` rotates it (data is
> kept) and prints the new one.

`--json` emits the whole bootstrap result as `{"data": ...}`; that is useful for scripting
but still contains the secrets, so redirect it somewhere private if you use it.

## 1.3 Start the control plane

```bash
./bin/csg serve --data-dir .demo/data
# console + API: http://127.0.0.1:8787
```

The server binds loopback by default. It logs the console URL and API URL; the console is
the same HTTP origin. Run it in the foreground and stop it with `Ctrl-C` when done.

## 1.4 Log in to the console

Open <http://127.0.0.1:8787>, paste the **admin token** (`csg_adm_...`), and log in.
You should see the overview with the seeded provider and agents, and empty lease counts.
The console polls the API every 4 seconds while a page is visible.

## 1.5 Auto-approved read (no human involved)

In a second terminal, act as the `claude-code` agent. Use the `csg_agt_...` token that
`init` printed for `claude-code`:

```bash
export CSG_SERVER=http://127.0.0.1:8787
export CSG_TOKEN='csg_agt_...'          # claude-code agent token

./bin/csg request --capability aliyun.cloud.read \
  --reason "collect inventory for weekly report" \
  --wait 30s
```

Expected: the policy engine returns `auto_approve` with rule reasons, the lease becomes
`active`, and the command prints the lease id (`lea_...`). No human action was needed.

Fetch the short-lived credential and use it against the mock cloud:

```bash
eval "$(./bin/csg credential --lease lea_... --export)"
./bin/csg mock request GET /v1/ecs/instances
# → 200, {"RequestId":...,"RegionId":"cn-hangzhou","Instances":[...]}
```

`.demo/data` is gitignored; never commit tokens.

## 1.6 Least privilege is in the credential

The same read credential cannot restart an instance:

```bash
./bin/csg mock request POST /v1/ecs/instances/i-2ze0demo001/restart
# → HTTP 403 {"Code":"Forbidden.RAM",...}
```

The read policy only allows `Describe*`/`List*` actions, so the demo cloud rejects the
write even though the request is validly authenticated. Note the CLI exits `1` on HTTP
≥ 400.

One-shot alternative (requests, waits, injects the credential env, runs the child,
revokes the lease on exit):

```bash
./bin/csg exec --capability aliyun.cloud.read \
  --reason "one-shot inventory" \
  -- ./bin/csg mock request GET /v1/ecs/instances
```

## 1.7 One-click approval for a risky change

In the agent terminal, request DNS management for one domain (this stays pending until a
human decides; `--wait 2m` polls every second):

```bash
./bin/csg request --capability aliyun.dns.manage \
  --param domain=arveykao.com \
  --ttl 10m \
  --reason "add ACME DNS-01 TXT record for arveykao.com" \
  --wait 2m
```

In a third terminal, act as the operator:

```bash
export CSG_SERVER=http://127.0.0.1:8787
export CSG_TOKEN='csg_adm_...'          # admin token from init

./bin/csg leases list --status pending
./bin/csg leases approve lea_... --ttl 10m --note "ACME renewal for arveykao.com"
```

The waiting agent request returns `active`. Back in the agent terminal, fetch the
credential and exercise exactly the approved scope:

```bash
eval "$(./bin/csg credential --lease lea_... --export)"
./bin/csg mock request GET /v1/dns/zones/arveykao.com/records
./bin/csg mock request POST /v1/dns/zones/arveykao.com/records \
  '{"name":"_acme-challenge","type":"TXT","value":"demo-challenge-abc","ttl":600}'
# → 200, record created
./bin/csg mock request POST /v1/ecs/instances/i-2ze0demo001/restart
# → 403: the DNS-scoped credential cannot touch ECS
```

The same approval can be done from the console: **Overview → pending queue → Approve**
(or **Leases → open the pending lease → Approve** with TTL + note). A console approval
produces the same API call and audit trail as the CLI.

## 1.8 Denial

Request another DNS lease, then have the operator deny it:

```bash
# agent terminal
./bin/csg request --capability aliyun.dns.manage --param domain=guanlanstudio.com \
  --ttl 10m --reason "add a record" --wait 2m
# → pending; leave it waiting

# admin terminal
./bin/csg leases list --status pending
./bin/csg leases deny lea_... --reason "change window not approved"
```

The agent command returns `denied` (exit code `1`), there is no credential for the lease,
and the audit log holds both `lease.requested` and `lease.denied`.

A policy-level denial is immediate: `hermes-researcher` has only `aliyun.cloud.read`, so
requesting an ECS capability with its token is denied with rule `capability_not_granted`
and no lease credential is ever possible.

## 1.9 Break-glass and revocation

Break-glass is the `critical` capability and always requires explicit intent plus a human:

```bash
# agent terminal (claude-code)
./bin/csg request --capability aliyun.iam.break_glass \
  --reason "incident 42: recover DNS" --wait 2m
# → denied: rule break_glass_required

./bin/csg request --capability aliyun.iam.break_glass --break-glass \
  --reason "incident 42: recover DNS" --wait 2m
# → pending
```

Approve it as operator, then verify the audit severity and the immediate revocation:

```bash
# admin terminal
./bin/csg leases approve lea_... --ttl 5m --note "incident 42, approved by on-call"
./bin/csg audit list --severity critical --limit 20

# agent terminal: use the credential once
eval "$(./bin/csg credential --lease lea_... --export)"
./bin/csg mock request GET /v1/ecs/instances          # 200: break-glass allows it

# admin terminal: revoke
./bin/csg leases revoke lea_... --reason "incident resolved"

# agent terminal: the previously working credential is dead immediately
./bin/csg mock request GET /v1/ecs/instances
# → HTTP 401 {"Code":"InvalidSecurityToken.Revoked",...}
```

In mock mode revocation is instant because the mock cloud re-checks the lease on every
call. In real `sts` mode the control plane stops renewal and scrubs its copy, but an
already-issued cloud session lives until its expiry — see
[SECURITY.md](SECURITY.md) §9.

## 1.10 Audit

```bash
# admin terminal
./bin/csg audit list --limit 20
./bin/csg audit list --severity critical
./bin/csg audit verify
# → ok=true, events=N
```

Every request, decision, issuance, fetch, revoke and mock cloud API call is in the
hash-chained log. The console **Audit** page shows the same data with a *Verify chain*
button.

## 1.11 One-command demo

The full S1–S8 scenario is scripted (clean data dir, mock cloud, port `18787`, PASS/FAIL
lines, exit 0 only if everything passes, server cleaned up):

```bash
make demo
```

## 1.12 Clean up

```bash
# stop the server with Ctrl-C, then remove the throwaway instance:
rm -rf .demo
```

---

# Part 2 — Real Alibaba Cloud `sts` mode

This section requires: an Alibaba Cloud account, its **account ID** (the numeric UID), and
RAM permissions to create users/roles/policies. Credentials are never printed; paste secret
material into 0600 files or stdin.

> ⚠️ Not exercised against a live account in this build. The platform's STS signer is
> implemented and unit-tested against a fake STS endpoint; treat this as a setup guide to
> verify (`csg providers test`, then a read lease) before production use.
> References: [AssumeRole API](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerole)
> (inline policy intersects the role policy; `DurationSeconds` minimum 900 s),
> [RAM role trust policy](https://www.alibabacloud.com/help/en/ram/user-guide/edit-the-trust-policy-of-a-ram-role).

## 2.1 Create the broker RAM user

1. In **RAM → Identities → Users**, create a user `csg-broker` with **programmatic access**
   and save its AccessKey ID + Secret once.
2. Create and attach a custom policy that only allows assuming the platform role. Replace
   `<account-id>`:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["sts:AssumeRole"],
      "Resource": ["acs:ram::<account-id>:role/csg-agent"]
    }
  ]
}
```

This long-lived key is the one value Cloud Safeguard vaults. It has no cloud permissions of
its own — only the right to assume the role (whose attached policy becomes the outer bound,
see 2.9).

## 2.2 Create the RAM role

1. In **RAM → Identities → Roles**, create `csg-agent` trusted by the RAM user
   `csg-broker`. Trust policy:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "RAM": ["acs:ram::<account-id>:user/csg-broker"]
      }
    }
  ]
}
```

2. Attach a permission policy to the role matching the capabilities you will grant.
   **There is no need to attach `AdministratorAccess`.** The per-lease inline policy can
   only narrow permissions, never expand them (Alibaba Cloud computes the intersection), so
   attach the union of what your capability catalog may need. For the five built-ins:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:Describe*",
        "ecs:StartInstance",
        "ecs:StopInstance",
        "ecs:RebootInstance",
        "alidns:Describe*",
        "alidns:AddDomainRecord",
        "alidns:UpdateDomainRecord",
        "alidns:DeleteDomainRecord",
        "alidns:SetDomainRecordStatus",
        "oss:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": ["*"]
    }
  ]
}
```

> Trade-off: `aliyun.iam.break_glass` is still bounded by this role policy unless you
> attach a broader policy to the role. Start narrow; widen only with a documented reason.
> The role's session duration (`MaxSessionDuration`) must be ≥ 3600 s if you want the
> platform's global 3600 s TTL ceiling.

## 2.3 Initialize a non-demo instance

Do **not** use `--demo` for real cloud use: demo seeds a mock provider, and mock mode is
not a security boundary.

```bash
./bin/csg init --data-dir ./data
# prints the admin token once — store it in a password manager
./bin/csg serve --data-dir ./data
```

The data dir contains the SQLite DB and `master.key` (0600). For production, inject the
master key instead of keeping it next to the DB: set `CSG_MASTER_KEY` to a base64-encoded
32-byte key (e.g. from a secret manager via a 0600 `EnvironmentFile`). See
[SECURITY.md](SECURITY.md) §7.

## 2.4 Add and test the provider (one terminal, operator)

```bash
export CSG_SERVER=http://127.0.0.1:8787
export CSG_TOKEN='csg_adm_...'

# Put the broker secret in a private file; never pass it on the command line.
install -m 600 /dev/null /tmp/csg-broker.secret
# write the AccessKey secret into /tmp/csg-broker.secret with your secret tooling, then:

./bin/csg providers add \
  --name aliyun-prod \
  --mode sts \
  --region cn-hangzhou \
  --role-arn 'acs:ram::<account-id>:role/csg-agent' \
  --access-key-id 'LTAI...' \
  --access-key-secret-file /tmp/csg-broker.secret
# → provider id prv_...

rm -f /tmp/csg-broker.secret

./bin/csg providers test prv_...
# → test passes (signed sts:GetCallerIdentity)
```

(`--access-key-secret-stdin` is also supported if piping from a secret manager.)

## 2.5 Create an agent, grant capabilities, request a lease

```bash
./bin/csg agents create \
  --name ops-agent \
  --description "Manages DNS and ECS for the web stack" \
  --capability aliyun.cloud.read,aliyun.dns.manage,aliyun.ecs.instance.ops \
  --max-ttl 30m \
  --max-concurrent 2
# → prints the agent id (agt_...) and a one-time token csg_agt_...

# Agent side: request a read lease and export the STS credential.
```

Now run as the agent in its own environment (use the one-time `csg_agt_...` token printed
by `agents create`):

```bash
export CSG_SERVER=http://127.0.0.1:8787
export CSG_TOKEN='csg_agt_...'       # ops-agent's one-time token

./bin/csg request --capability aliyun.cloud.read \
  --reason "inventory before change" --wait 30s
eval "$(./bin/csg credential --lease lea_... --export)"
```

## 2.6 Use the credential with the Alibaba Cloud CLI

The exported variables are exactly what the Alibaba Cloud CLI/SDKs read:
`ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`,
`ALIBABA_CLOUD_SECURITY_TOKEN`.

> **Careful:** the Alibaba Cloud CLI resolves **config file > environment variables**
> (command-line flags first, then `~/.aliyun/config.json`, then env vars). If an old
> profile with a long-lived AccessKey still exists in `~/.aliyun/config.json`, it will
> silently win over the lease credential. Set `ALIBABA_CLOUD_IGNORE_PROFILE=TRUE` and
> remove the stale profile when retiring old copies.

```bash
export ALIBABA_CLOUD_IGNORE_PROFILE=TRUE
aliyun sts GetCallerIdentity
aliyun ecs DescribeInstances --RegionId cn-hangzhou
```

Or let the platform set up the environment for exactly one child process and revoke the
lease afterwards:

```bash
./bin/csg exec --capability aliyun.cloud.read --reason "inventory" \
  -- aliyun ecs DescribeInstances --RegionId cn-hangzhou
```

A write operation outside the requested capability fails with a RAM `Forbidden` error,
because the session inline policy only carries the lease's actions/resources.

## 2.7 Approve a risky lease

```bash
# agent terminal
./bin/csg request --capability aliyun.dns.manage \
  --param domain=arveykao.com --ttl 15m \
  --reason "add ACME DNS-01 TXT record" --wait 5m

# admin terminal
./bin/csg leases list --status pending
./bin/csg leases approve lea_... --ttl 15m --note "ACME renewal for arveykao.com"
```

In real mode request **at least 900 s** for any lease: Alibaba Cloud STS
`DurationSeconds` minimum is 15 minutes. The built-in `aliyun.cert.dns01` defaults to
600 s (designed for the mock demo), so pass `--ttl 15m` for it in `sts` mode.

## 2.8 Rotate the broker credential

```bash
# Create a new AccessKey for the csg-broker RAM user in the Alibaba Cloud console first.
install -m 600 /dev/null /tmp/csg-broker-new.secret
# write the new secret into that file, then:
./bin/csg providers rotate prv_... \
  --access-key-id 'LTAI...new' \
  --access-key-secret-file /tmp/csg-broker-new.secret
rm -f /tmp/csg-broker-new.secret
./bin/csg providers test prv_...
```

Existing leases keep working; the next lease mints with the new broker credential; no
agent, server script or cron entry changes. Then disable/delete the old AccessKey in RAM.
See the full runbook in [SECURITY.md](SECURITY.md) §6.

## 2.9 Real-mode notes and limits

- **Session policy intersects the role policy.** The inline policy can only narrow the
  role's attached permissions. If an action is denied in the cloud even though the
  capability template allows it, check the role's attached policy first.
- **`DurationSeconds` 900–3600 s.** STS also caps it at the role's `MaxSessionDuration`.
  Requests below 900 s fail minting with a provider error (`InvalidParameter.DurationSeconds`),
  leaving the lease `failed`.
- **Inline policy size is limited** (2,048 characters for the AssumeRole `Policy`
  parameter). Keep custom capability templates compact.
- **No instant single-session revocation** in real STS mode: revoke the lease to stop
  renewal, and tighten the RAM role policy if an issued credential may be leaked
  ([SECURITY.md](SECURITY.md) §9).
- **`RoleSessionName` is `csg-<agentID>-<leaseID>`** — filter Alibaba Cloud ActionTrail by
  it to correlate cloud actions to a platform lease.
- **Not live-tested in this build**: start with `providers test` and a read lease.
  Placeholder credentials still reach Alibaba Cloud and return a provider error (for
  example `InvalidAccessKeyId.NotFound`); that confirms the request path, but only a real
  account produces success.

---

# Part 3 — Verify the build

```bash
go test ./...                 # Go unit/integration suite
go vet ./...                  # static checks
cd web && npm run typecheck && npm run build && cd ..
make build                    # single binary with embedded console
make demo                     # scripted S1–S8 end-to-end demo
```

For a CLI smoke check that needs no data dir:

```bash
./bin/csg version
./bin/csg --help
```

---

# Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `csg: command not found` | Use `./bin/csg` from the repo root (or add `bin/` to `PATH`). |
| `make build` fails while building the console | Node.js < 20 or missing npm; install Node 20+ and re-run. |
| `csg serve` fails with "not initialized" | Wrong `--data-dir` or you skipped `csg init`; run `init` for that dir (or point at `.demo/data`). |
| `address already in use` | Another server uses the port. Find it (`lsof -nP -iTCP:8787 -sTCP:LISTEN`) or use `--addr 127.0.0.1:8788`. |
| Lost admin token | `./bin/csg init --force --data-dir <dir>` rotates the admin token, keeps data and prints the new one once. |
| Lost agent token | `./bin/csg agents rotate-token agt_...` prints a new one-time token; the old token stops working immediately. |
| `401 unauthorized` on CLI | Wrong token kind for the command (agent commands need `csg_agt_`, admin commands `csg_adm_`), token rotated, or stale env/config; check `csg whoami`, `CSG_TOKEN`, `~/.config/cloud-safeguard/config.json`. |
| `403 forbidden` for an agent | Agent is `suspended`/`revoked`; reactivate or issue a new identity. |
| `400 invalid_request` on lease request | Missing/invalid capability param (e.g. no `domain` for `aliyun.dns.manage`), unknown capability param, or malformed duration/JSON. |
| `404 not_found` on `/mock-cloud/` calls | No mock provider exists (you initialized without `--demo`); the mock cloud is only mounted when a mock provider is present. |
| `409 lease_not_active` fetching a credential | Lease is still `pending` (approve it first), or it is already revoked/expired/failed. |
| `410 credential_unavailable` | The credential was scrubbed (revoked/expired); request a new lease. |
| `csg request --wait` times out (exit 4) | No human approved in time (pending timeout is 600 s by default) or the request is still pending; `csg leases mine` / console to check. |
| Lease `denied` immediately | Policy denial; read the printed rule reasons (e.g. `capability_not_granted`, `break_glass_required`, TTL/concurrency/rate limits). |
| Lease `failed` with a provider error | Minting failed: wrong/disabled broker AccessKey, role trust or `sts:AssumeRole` permission missing, `RoleArn` typo, TTL below STS 900 s, or inline policy syntax/size. Run `csg providers test`, then retry. |
| `provider test` fails in `sts` mode | Role trust policy must name the broker RAM user; broker user needs `sts:AssumeRole` on that role ARN; AccessKey must be active; endpoint/region/network reachable. |
| Cloud calls denied despite the capability looking right (real mode) | The RAM role's attached policy is the outer bound (session policy intersects it). Add the action to the role policy — narrowest scope that works. |
| Alibaba Cloud CLI uses the wrong (old long-lived) key | CLI priority is `~/.aliyun/config.json` > env; set `ALIBABA_CLOUD_IGNORE_PROFILE=TRUE` and remove the stale profile. |
| Cannot decrypt provider credential after changing `CSG_MASTER_KEY` | Vault needs the original key. Restore it; if truly lost, re-rotate the provider credential (data encrypted with the old key is unrecoverable) and expire old leases. |
| `csg mock request` 400/401 in the demo | Missing/expired credential env or not initialized from a mock provider; re-fetch the credential with `eval "$(csg credential --lease ... --export)"`. |
| `data dir` permission warning | `init` creates 0700 / 0600 best effort; fix with `chmod 700 <dataDir>`, `chmod 600 <dataDir>/master.key <dataDir>/csg.db`. |

---

# Where to go next

- [SECURITY.md](SECURITY.md) — threat model, residual risks, rotation runbook, hardening,
  incident response (read this before putting real credentials in).
- [ARCHITECTURE.md](ARCHITECTURE.md) — components, lease flows, policy engine, audit chain,
  failure modes.
- [API.md](API.md) — REST endpoints and curl examples.
- [CONTRACT.md](CONTRACT.md) — normative contract for every behavior above.
