# Cloud Safeguard — Quickstart

Two paths:

- **Part 1 — Demo (10 minutes, no cloud account):** build the binary, start a throwaway
  instance with the built-in mock cloud, sign in to the console, sign an agent in, and walk
  through automatic read access, least privilege, approval, revocation and the audit log.
- **Part 2 — Real Alibaba Cloud:** connect an account through a RAM user and a RAM role and
  issue real short-lived STS credentials.

Part 1 is covered by the automated checks (`make demo`). Part 2 needs a real Alibaba Cloud
account and **has not been run against a live account yet**; the STS signer is unit-tested
against a fake endpoint. Verify it in your account before relying on it.

---

## Prerequisites

- Go 1.24+ (`go version`)
- Node.js ≥ 20 and npm (needed by `make build` for the console)
- macOS or Linux, a free loopback port (`8787` by default, `18787` for the scripted demo)
- An authenticator app (any TOTP app) for the console sign-in
- `curl` and `python3` for the scripted demo (`make demo`)

---

# Part 1 — Demo mode (mock cloud)

## 1.1 Build

```bash
make build
```

This builds the console and one binary, `build/csg`.

## 1.2 Create a throwaway instance

```bash
./build/csg init --demo --data-dir .demo/data
```

It creates the master key (`master.key`, unless you set `CSG_MASTER_KEY`, which is then
used and not written to disk), the database, a mock cloud account (`demo-aliyun`, cloud account
ID `1234567890123456`) and the first supervisor, `admin`. It prints one secret: the
supervisor's **setup code**, shown once and valid for 72 hours. There is no admin token and
no agent token.

`csg init` never touches a directory that is already initialized. If the setup code is lost
or expires, run `./build/csg supervisor recover --username admin --data-dir .demo/data` on the
same machine to get a new one.

## 1.3 Start the control plane

```bash
./build/csg serve --data-dir .demo/data
```

The console and the API are at `http://127.0.0.1:8787`. Leave it running.

## 1.4 Set up the supervisor in the console

1. Open `http://127.0.0.1:8787` and choose **Set up your account**.
2. Enter the setup code and choose a password.
3. Scan the QR code with your authenticator app and enter the six-digit code.

You are signed in as a supervisor. A supervisor manages the platform (cloud accounts, people,
roles, limits) and is **Administrator on every cloud account**.

## 1.5 Add a person and give them a role

For the demo you can use the supervisor for everything. To see how roles work, add a second
person:

1. **People → + Add person**, username `mei`. Copy the setup code you are shown.
2. **Cloud accounts → demo-aliyun → People and roles**: add `mei` as **Guest**.
3. Open the console in a private window, choose **Set up your account** and finish mei's
   setup with her code.

| Role | The person's agents can get |
| --- | --- |
| Guest | read |
| Member | read and write (change existing resources) |
| Administrator | read, write and full (create and delete) |

Nobody, at any role, can get permission to manage RAM users, roles or policies.

## 1.6 Sign an agent in

In a second terminal:

```bash
./build/csg login --server http://127.0.0.1:8787 --name my-agent
```

It prints a link and a short code, then waits. Open the link in the console (as mei), check
that the code matches, and approve. The agent now belongs to mei and inherits her role on
each cloud account. No token is copied by hand; it is saved to
`~/.config/cloud-safeguard/config.json` with mode 0600.

```bash
./build/csg whoami
./build/csg accounts          # the cloud accounts this agent may ask for, and up to what
```

## 1.7 Read access: issued at once

```bash
./build/csg exec --account 1234567890123456 --resource ecs --permission read --ttl 10m \
  -- ./build/csg mock request GET /v1/ecs/instances
```

`csg exec` asks for access, runs the command with the credential in its environment, and
gives the credential back when the command ends. Every request names five things: the cloud
account, the resource type (`ecs`, `dns` or `oss`), the permission (`read`, `write` or
`full`), a validity period, and optionally one resource name. A reason is required above
read.

To hold a credential yourself:

```bash
./build/csg access request --account 1234567890123456 --resource ecs --permission read --ttl 10m
# → request lea_..., status active
eval "$(./build/csg credential --lease lea_... --export)"
./build/csg mock request GET /v1/ecs/instances                      # works
./build/csg mock request POST /v1/ecs/instances/i-2ze0demo001/restart
# → 403 Forbidden.RAM: a read credential cannot restart an instance
./build/csg revoke --lease lea_...                                  # give it back early
```

Least privilege is in the credential itself: the policy attached to it allows only what was
asked for.

## 1.8 Write access: the owner approves

A guest's agent cannot get write access at all:

```bash
./build/csg access request --account 1234567890123456 --resource ecs --permission write \
  --ttl 10m --reason "restart after a config change"
# → status denied: the owner's role guest does not permit write access
```

As the supervisor, change mei's role to **Member**, then ask again and wait:

```bash
./build/csg access request --account 1234567890123456 --resource ecs --permission write \
  --name i-2ze0demo001 --ttl 10m --reason "restart after a config change" --wait 5m
```

The request appears in mei's **Inbox**. Only mei can approve it; a supervisor can deny or
revoke any request but cannot approve someone else's. After she approves, the command returns and the
credential can restart that one instance and nothing else.

## 1.9 Approval modes

In **Settings**, each person picks how much their agents get without asking: **Read** (the
default), **Write** or **Full**, optionally for a limited time. A supervisor sets the highest
automatic level per cloud account (default read). What is issued without approval is the
lowest of the person's role, their mode and the account's level.

## 1.10 Revocation

- Lower mei's role back to **Guest**: the write credential is revoked at once, and the mock
  cloud refuses it with `InvalidSecurityToken`.
- The owner can take back one credential in the **Inbox**. A supervisor can stop any
  credential through the API (`POST /api/v1/supervisor/leases/{id}/revoke`); the console
  does not have a button for that yet.
- Suspending a person, or revoking an agent on the **Agents** page, revokes everything that
  agent holds.
- Every credential also ends at its deadline.

## 1.11 Audit

**Activity** (as a supervisor) shows every sign-in, request, decision, credential fetch,
revocation and mock cloud call, with who caused it, and whether the hash chain verifies.

## 1.12 Use it from Claude, Cursor or another agent (MCP)

`csg mcp` is an MCP server over stdio with five tools: `list_accounts`, `request_access`,
`check_status`, `get_credential` and `revoke`. After `csg login`, add it to the agent's MCP
configuration:

```json
{ "mcpServers": { "cloud-safeguard": { "command": "/absolute/path/to/build/csg", "args": ["mcp"] } } }
```

`get_credential` never returns the secret to the model. It writes a file readable only by
you under `~/.config/cloud-safeguard/credentials/` and returns its path, to be sourced by the
command that needs it.

## 1.13 Work as yourself on the command line

```bash
./build/csg person login --server http://127.0.0.1:8787
```

It prints a link and a code like the agent sign-in. Open the link in the console, check the
code and approve. The session is yours (not an agent's), lasts up to 12 hours (30 minutes
without use) and is saved in `~/.config/cloud-safeguard/person.json`, apart from any agent's.

```bash
./build/csg person whoami
./build/csg me requests --status pending
./build/csg me deny lea_... --reason "not now"
./build/csg supervisor people                       # supervisors only
./build/csg supervisor roles set demo-aliyun mei member
#  → "this change raises access: run it again with --code …"
./build/csg supervisor roles set demo-aliyun mei member --code 123456
```

Agents often run on the same machine and could read that file, so the session is guarded:

- reading, and anything that lowers access (deny, revoke, lower a role or remove it,
  suspend, disable an account, set your mode to read), works as is;
- anything that raises access (add or reset a person, make a supervisor, give a role above
  guest, enable or reconfigure an account, replace its AccessKey, raise a level or a limit,
  set your mode above read) needs a fresh code from your authenticator app. In a terminal
  csg asks for it; otherwise pass `--code`. Wrong codes count towards the sign-in lockout;
- approving requests and sign-ins, and adding a cloud account, work in the console only.

End it with `csg person logout`, or from the console in **Settings → Command-line sign-ins**.

## 1.14 The scripted demo

```bash
make demo
```

It starts its own instance on port 18787 and runs ten scenarios end to end (setup, agent
sign-in, automatic read, least privilege, denial, approval, revocation on a role change,
the supervisor's emergency stop, a supervisor on the command line, audit and a secret-leak
check), then prints `all S1-S10 scenarios passed`.

## 1.15 Clean up

Stop the server with Ctrl-C, then:

```bash
rm -rf .demo
rm -f ~/.config/cloud-safeguard/config.json ~/.config/cloud-safeguard/person.json
```

---

# Part 2 — Real Alibaba Cloud

You need an Alibaba Cloud account, its numeric **account ID**, and permission to create RAM
users, roles and policies.

> ⚠️ Not yet run against a live account. Start with the connection test and a read request.
> References: [AssumeRole](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerole)
> (the session policy intersects the role's policy; `DurationSeconds` is at least 900 s),
> [RAM role trust policy](https://www.alibabacloud.com/help/en/ram/user-guide/edit-the-trust-policy-of-a-ram-role).

The console's **Add cloud account** page shows the same three steps with your account ID
filled in, ready to copy. Use these names so the policies fit as they are.

## 2.1 Create the broker RAM user

1. In **RAM → Identities → Users**, create a user `cloud-safeguard-broker` with an AccessKey,
   and save the AccessKey ID and secret once.
2. Attach a custom policy that only allows assuming the platform's role. Replace
   `<account-id>`:

```json
{
  "Version": "1",
  "Statement": [
    { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "acs:ram::<account-id>:role/cloud-safeguard" }
  ]
}
```

This long-lived key is the one value Cloud Safeguard stores, encrypted. It has no cloud
permissions of its own.

## 2.2 Create the RAM role

1. In **RAM → Identities → Roles**, create `cloud-safeguard`, trusted by the RAM user
   `cloud-safeguard-broker` only:

```json
{
  "Version": "1",
  "Statement": [
    { "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": { "RAM": ["acs:ram::<account-id>:user/cloud-safeguard-broker"] } }
  ]
}
```

2. Attach a permission policy to the role. It is the outer limit: each credential's own
   policy can only narrow it. This is everything the built-in templates can ask for:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:Describe*", "ecs:StartInstance", "ecs:StopInstance", "ecs:RebootInstance",
        "ecs:RunInstances", "ecs:CreateInstance", "ecs:DeleteInstance",
        "alidns:Describe*", "alidns:AddDomainRecord", "alidns:UpdateDomainRecord",
        "alidns:DeleteDomainRecord", "alidns:SetDomainRecordStatus", "alidns:AddDomain", "alidns:DeleteDomain",
        "oss:Get*", "oss:List*", "oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload",
        "oss:PutBucket", "oss:DeleteBucket",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    { "Effect": "Deny", "Action": ["ram:*", "sts:AssumeRole"], "Resource": "*" }
  ]
}
```

Leave out what you never want an agent to do; a request for it then fails in the cloud. Do
not attach `AdministratorAccess` and do not use a wildcard per service: `ecs:*` would include
`ecs:ModifyInstanceAttribute`, which can set an instance's login password. If the broker's
AccessKey ever leaks, this policy is what the thief could reach, so keep it narrow. The
role's maximum session duration must be at least 3600 s if you keep the default one-hour
limit.

## 2.3 Start a real instance

Do not use `--demo` for real use: it adds a mock account, and mock mode is not a security
boundary.

```bash
./build/csg init --data-dir /var/lib/csg
./build/csg serve --data-dir /var/lib/csg
```

`init` prints the first supervisor's setup code once. The server listens on `127.0.0.1` only.
To reach it from other machines, put a TLS reverse proxy in front and start it with
`--public-url https://csg.example.com` (and `--trusted-proxy` for the proxy's address). Back
up `master.key` separately from the database: without it the stored AccessKey cannot be
decrypted.

## 2.4 Add the cloud account (console only)

Adding a cloud account is done in the console by a supervisor, never from the command line
and never by an agent.

1. **Cloud accounts → + Add cloud account**.
2. **Account**: the numeric account ID, a name and the region.
3. **Role**: the page shows the three policies from 2.1 and 2.2 with your account ID filled
   in. The role must be named `cloud-safeguard`; the console builds its ARN from that name.
4. **Connect**: the broker's AccessKey ID and secret. The secret is encrypted on arrival and
   never shown again.
5. The connection test runs at once. It checks that the AccessKey is valid
   (`sts:GetCallerIdentity`) and that it can assume the role (one `AssumeRole` for 15
   minutes with a policy that allows nothing useful; the result is thrown away).

Then give people their roles on the account, and decide its highest automatic level.

## 2.5 Sign agents in and ask for access

Exactly as in Part 1: `csg login`, then `csg accounts`, `csg access request`, `csg exec` or
the MCP server. On a real account the shortest validity is 15 minutes.

## 2.6 Use the credential with the Alibaba Cloud CLI

The credential arrives as `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`
and `ALIBABA_CLOUD_SECURITY_TOKEN`, which the Alibaba Cloud CLI and SDKs read.

> **Careful:** the Alibaba Cloud CLI prefers `~/.aliyun/config.json` over environment
> variables. An old profile with a long-lived AccessKey silently wins. Set
> `ALIBABA_CLOUD_IGNORE_PROFILE=TRUE` and remove the old profile.

```bash
export ALIBABA_CLOUD_IGNORE_PROFILE=TRUE
./build/csg exec --account <account-id> --resource ecs --permission read --ttl 15m \
  -- aliyun ecs DescribeInstances --RegionId cn-hangzhou
```

## 2.7 Rotate the broker AccessKey

Create a new AccessKey for `cloud-safeguard-broker` in the Alibaba Cloud console, then in **Cloud
accounts → the account → Replace AccessKey** enter the new pair and run **Test connection**. Delete
the old AccessKey in Alibaba Cloud afterwards. Credentials already issued keep working until
their deadline; no agent or script changes.

## 2.8 Notes and limits

- **The session policy intersects the role's policy.** If the cloud denies an action a
  request should allow, check the policy attached to the role first.
- **Validity is 900–3600 s** on a real account, and never longer than the role's maximum
  session duration.
- **A real STS credential cannot be cancelled in the cloud.** Revoking it here stops the
  agent from fetching it again and removes the stored copy, but a copy the agent already
  has works until its deadline. Keep validity periods short; if one may have leaked,
  tighten the role's policy ([SECURITY.md](SECURITY.md)).
- **The session name is `csg-<agent id>-<request id>`.** Filter ActionTrail by it to match
  cloud actions to a request.

---

# Part 3 — Verify the build

```bash
go vet ./...
go test ./...
cd web && npx tsc --noEmit && npm test && npm run build && cd ..
make build
make demo
```

---

# Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `csg: command not found` | Use `./build/csg` from the repository root. |
| `make build` fails while building the console | Node.js older than 20, or npm missing. |
| `csg serve` says the directory is not initialized | Wrong `--data-dir`, or `csg init` was never run for it. |
| `csg init` refuses the directory | It already holds an instance. `csg serve` upgrades it; `csg supervisor recover` issues a new setup code. |
| `address already in use` | Another server uses the port. Use `--addr 127.0.0.1:8788`. |
| Setup code lost or expired; supervisor locked out | On the server host: `csg supervisor recover --username NAME --data-dir DIR`. |
| Someone else's setup code lost | A supervisor resets that person on the **People** page. |
| Sign-in fails with a correct password | The authenticator code was already used, the clock is off, or the account is locked for 15 minutes after five failures. |
| `agent token required` | Not signed in on this machine. Run `csg login --server URL`. |
| `403` for an agent | The agent was revoked, or its owner is suspended or has not finished setup. Sign in again. |
| `your owner has no role on cloud account …` | A supervisor has not given the owner a role there, or the account ID is wrong. |
| Request `denied` at once | The owner's role does not allow that permission, or the agent is at its limit of credentials or requests per minute. |
| Request stays `pending` | It waits for the owner in the console's Inbox. It expires after 10 minutes by default. |
| `409 lease_not_active` fetching a credential | The request is still pending, or was denied, revoked or expired. |
| Request `failed` with a cloud error | Wrong or disabled broker AccessKey, the role does not trust the broker user, the role is not named `cloud-safeguard`, or a validity below 900 s. **Test connection** on the Cloud accounts page checks the key and the role. |
| `404` on `/mock-cloud/` | No mock account exists (the instance was created without `--demo`). |
| The Alibaba Cloud CLI uses an old key | Set `ALIBABA_CLOUD_IGNORE_PROFILE=TRUE` and remove the old profile. |
| The server refuses to start after `CSG_MASTER_KEY` changed | The key does not match the data directory. Restore the original key. |
| `cannot verify the master key … --trust-master-key` | An old directory with no `master.key` and nothing stored yet: nothing can tell the right key from a mistyped one. Check `CSG_MASTER_KEY`, then run the command once with `--trust-master-key`. |
| Commands such as `csg providers` or `csg request` are unknown | They were removed with the admin token. People use `csg person login`, then `csg me …` and `csg supervisor …`; agents use `csg access`. |
| `this change raises access: run it again with --code` | A command-line session needs a fresh authenticator code for that change. Add `--code 123456`, or run it in a terminal to be asked. |
| `this can only be done in the console` | Approving requests and sign-ins, and adding a cloud account, are console-only on purpose. |

---

# Where to go next

- [CONTRACT.md](CONTRACT.md) §17 — the rules for people, roles, requests and approval.
- [ARCHITECTURE.md](ARCHITECTURE.md) — components and flows.
- [SECURITY.md](SECURITY.md), [API.md](API.md) — written for v0.1 and being rewritten; the
  parts about the vault, the audit chain and incident response still apply.
