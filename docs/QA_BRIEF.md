# QA brief: end-to-end testing of Cloud Safeguard

For the tester (Qoder). Branch `feat/agent-roles`, the commit that removes the admin token or
later.

## Goal

Verify that the current build does what `docs/CONTRACT.md` §17 says, on a local machine,
first against the built-in mock cloud and then against a real Alibaba Cloud account. Report
every problem as a GitHub issue.

## Rules

1. Test from your own clone or worktree. Do not edit product code; the fix belongs to the
   maintainers.
2. Never put an AccessKey, secret, token, setup code, password or TOTP secret in an issue,
   commit, log excerpt or chat. Replace them with `<redacted>`.
3. The project owner types real cloud AccessKey secrets into the console. Do not ask for
   them and do not read them from files.
4. On the real cloud account, run read-only tests first. Change or delete only resources the
   owner created for testing and named for you.
5. A security problem (credential exposure, a way around a role, approval or the IAM ban) is
   reported privately to the owner, not in a public issue.

## Setup

```bash
go build -o build/csg ./cmd/csg
./scripts/demo.sh            # must end with "all S1-S13 scenarios passed"
go test ./...                # must pass
./build/csg init --demo --data-dir ./build/qa-data
./build/csg serve --data-dir ./build/qa-data
```

`csg init` prints one secret, once: the first supervisor's setup code. There is no admin
token. Console: `http://127.0.0.1:8787/`. CLI help: `csg help`, `csg <command> -h`. The API
is listed in CONTRACT §17.8; `docs/QUICKSTART.md` walks through the whole flow.

## In scope

### A. Agents, access requests and the IAM ban (CONTRACT §17.3–§17.7a), mock cloud

- An agent signs in with `csg login`; a person approves the short code in the console. The
  token is never printed and is saved with mode 0600.
- A guest's agent gets read at once; write and full are denied at once.
- A member's agent gets write only after its owner approves; full is denied. An
  administrator's (and a supervisor's) agent can get full after approval.
- Only the owner approves. A supervisor or another person cannot; a supervisor can deny and
  revoke through the API.
- Approval modes per cloud account (Read, Write, Full, with an optional expiry), set by the
  person on the Cloud accounts page, decide what is issued without approval; a mode never
  exceeds the role there, and a mode on one account changes nothing on another.
- An AWS account (mock): read on bucket `claudecode` lists and reads it; writing, another
  bucket and `/v1/iam/users` are refused; the credential comes as `AWS_*` variables. The
  add-account wizard has an AWS choice that shows the IAM user, trust and permission
  policies with the account ID filled in.
- A credential can be refreshed (`csg access refresh ID`, MCP `refresh_credential`): a new
  key under the same request, at most once a minute, within its refresh window (8 hours
  unless the agent declares another, at most the supervisor's limit). A revoked or expired
  request, or one whose owner lost the role, is not refreshed.
- A credential allows only what was asked for (one resource type, one permission level,
  optionally one resource), and is refused on RAM endpoints of the mock cloud at every level.
- Lowering or removing a role, suspending or resetting a person, revoking an agent and
  disabling a cloud account each revoke what is no longer allowed, at once.
- A credential cannot be fetched after it expired, was revoked or was denied.
- The removed routes (`/api/v1/admin/*`, `POST /api/v1/agent/leases`,
  `GET /api/v1/agent/capabilities`) answer 404, and the removed commands (`csg providers`,
  `agents`, `caps`, `policy`, `audit`, `request`) are unknown.
- `csg mcp`: the five tools work, and `get_credential` never returns the secret.
- Remote MCP (`<server>/mcp`): an MCP client connects with the URL alone, the person approves
  in the console and sees where the sign-in goes; `get_credential` returns a one-time link
  that sets the credential in a shell once, within 60 seconds. Try wrong verifiers, reused
  codes, foreign redirect URIs, other origins, used or expired links, a revoked agent.
- The audit log records every step, and the Activity page shows the chain as verified.

### A2. People on the command line (CONTRACT §17.9)

- `csg person login` signs in by approving a code in the console; the session is saved in
  `person.json` (0600), apart from the agent's config, and never printed.
- Reading and lowering access work from the command line without a code.
- Every change that raises access (see §17.9) is refused without `--code`, and works with a
  fresh authenticator code; a code works once; five wrong codes lock the person for 15 minutes.
- Approving a request, an agent sign-in or another command-line sign-in, and adding a cloud
  account, are refused from the command line even with a code.
- The session ends on logout, suspend, reset, 30 minutes idle, 12 hours, and when revoked in
  Settings → Command-line sign-ins.

### B. People, supervisors and sign-in (CONTRACT §17.1–§17.3)

Test in the console (setup, sign-in, Inbox, Agents, Cloud accounts, People, Settings) and with
`curl` against the endpoints in CONTRACT §17.8. Setup and login need the header
`Content-Type: application/json`.

- Setup with the code from `csg init`: weak passwords are refused; a correct authenticator
  code activates the account; the setup code cannot be used twice or after 72 hours.
- Login needs username, password and a fresh code; a code cannot be reused; five failures lock
  the account for 15 minutes; all failures look the same.
- Sessions end after 30 minutes idle, after 12 hours, on logout, and when the person is
  suspended or reset.
- Changing requests without the `X-CSRF-Token` header, or with a foreign `Origin`, get 403.
- Only a supervisor can create people and set role bindings; the last active supervisor cannot
  be suspended, demoted or reset.
- `csg supervisor recover --username NAME` issues a new setup code and ends the old sessions.

### C. Real Alibaba Cloud (after the owner connects an account)

The owner adds the cloud account in the console (Cloud accounts → + Add cloud account) and
tells you which test resources exist.

- A read request yields a working short-lived credential (`csg exec --account ...` with the
  `aliyun` CLI or an SDK), and it lists the expected resources.
- The same credential is refused for an action outside its policy.
- A credential at any level is refused by Alibaba Cloud on a RAM API call.
- The credential stops working at its deadline (minimum validity on real accounts: 15 minutes).
- A write request waits for approval, then works only on the named resource.
- The connection test, replacing the AccessKey and disabling the account behave as
  documented.

## Out of scope (known, do not report)

- SECURITY, API, ARCHITECTURE, SPEC, DECISIONS and PRODUCT still describe v0.1 and say so at
  the top.
- AWS is supported with S3 only, in the standard partition, and tested in mock mode and against a fake STS, not live AWS. GCP is not supported.
- The console has no button for the supervisor's emergency stop (it is in the API).

## Reporting

One GitHub issue per problem, with:

- title: `[area] what is wrong` (areas: `roles`, `iam-ban`, `requests`, `auth`, `supervisor`,
  `console`, `cli`, `mcp`, `sts`, `docs`)
- commit hash, OS, and whether the mock cloud or the real account was used
- exact steps or commands, with secrets redacted
- what you expected (cite the CONTRACT section) and what happened
- severity: `blocker`, `major`, `minor` or `question`

When you finish a section, add a short comment on a tracking issue listing what passed, so
passing results are recorded as well as failures.
