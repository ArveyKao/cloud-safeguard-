# QA brief: end-to-end testing of Cloud Safeguard

For the tester (Qoder). Branch `feat/agent-roles`, commit `42be770` or later.

## Goal

Verify that the current build does what `docs/CONTRACT.md` says, on a local machine, first
against the built-in mock cloud and then against a real Alibaba Cloud account. Report every
problem as a GitHub issue.

## Rules

1. Test from your own clone or worktree. Do not edit product code; the fix belongs to the
   maintainers.
2. Never put an AccessKey, secret, token, setup code, password or TOTP secret in an issue,
   commit, log excerpt or chat. Replace them with `<redacted>`.
3. The project owner types real cloud AccessKey secrets into the tool. Do not ask for them and
   do not read them from files.
4. On the real cloud account, run read-only tests first. Change or delete only resources the
   owner created for testing and named for you.
5. A security problem (credential exposure, a way around a role, approval or the IAM ban) is
   reported privately to the owner, not in a public issue.

## Setup

```bash
go build -o build/csg ./cmd/csg
./scripts/demo.sh            # must end with "all S1-S9 scenarios passed"
go test ./...                # must pass
./build/csg init --data-dir ./build/qa-data --demo
./build/csg serve --data-dir ./build/qa-data
```

`csg init` prints the admin token, two demo agent tokens and the first supervisor's setup code
once. Console: `http://127.0.0.1:8787/`. CLI help: `csg help`, `csg <command> -h`. API
reference: `docs/API.md` (v0.1) plus CONTRACT §16 and §17.8 for what changed since.

## In scope

### A. Agent roles and the IAM ban (CONTRACT §16), mock cloud

- A guest agent gets read capabilities only; a write request is denied with rule
  `role_permits`.
- A member agent can request write capabilities; requests above the auto-approve threshold wait
  for approval; approve, deny and timeout all behave as documented.
- An administrator agent's `aliyun.account.admin` request always needs approval, and the issued
  credential is still refused on RAM endpoints of the mock cloud.
- Creating or editing a capability whose policy allows `ram:*`, any `sts:` action other than
  `GetCallerIdentity`, `NotAction`, `NotResource` or a bare `*` (below admin) is rejected.
- Demoting or suspending an agent, disabling a capability or provider, and tightening the
  policy settings each revoke the leases that are no longer allowed, at once.
- A credential cannot be fetched after its lease expired, was revoked or was denied.
- The audit log records every step and `csg audit verify` passes afterwards.
- Console: the role picker, role and access badges, the grants list and the demotion
  confirmation behave as described in CONTRACT §16.7.

### B. People, supervisors and sign-in (CONTRACT §17.1–§17.3, API only)

There is no console screen for this yet; test with `curl` against the endpoints listed in
CONTRACT §17.8.

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

The owner adds the provider with `csg providers add --mode sts ...` and tells you which test
resources exist.

- A read lease yields a working short-lived credential (`csg exec` with the `aliyun` CLI or an
  SDK), and it lists the expected resources.
- The same credential is refused for an action outside its policy.
- A credential at any level is refused by Alibaba Cloud on a RAM API call.
- The credential stops working at its deadline (minimum validity on real accounts: 15 minutes).
- A write lease waits for approval, then works only on the named resource.
- Provider connection test, credential rotation and disabling the provider behave as
  documented.

## Out of scope (known, do not report)

- Role bindings are not enforced on agent requests yet; agents still use the §16 role.
- Agent ownership, agent-first sign-in, the five-field request (`read`/`write`/`full`), owner
  approval and the MCP server are not built (CONTRACT §17.8).
- The console still signs in with the admin token and has not been redesigned.
- README, QUICKSTART, SECURITY, API and PRODUCT still describe v0.1.
- AWS and GCP are not supported.
- Two known low-severity items: an access-level change racing a new grant, and a retired
  capability shown as a checkbox in the agent detail drawer.

## Reporting

One GitHub issue per problem, with:

- title: `[area] what is wrong` (areas: `roles`, `iam-ban`, `leases`, `auth`, `supervisor`,
  `console`, `cli`, `sts`, `docs`)
- commit hash, OS, and whether the mock cloud or the real account was used
- exact steps or commands, with secrets redacted
- what you expected (cite the CONTRACT section) and what happened
- severity: `blocker`, `major`, `minor` or `question`

When you finish a section, add a short comment on a tracking issue listing what passed, so
passing results are recorded as well as failures.
