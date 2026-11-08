# cloud-safeguard agent instructions

Project-specific facts belong in `.agent/PROJECT.md`; the block below is generated from the skill. Its reference paths are relative to the installed arvey-develop skill directory. Assigned task roles and existing user authorization remain in force.
<!-- agentic-delivery:begin -->
## Deliver the accepted outcome

Read `.agent/PROJECT.md`, applicable instructions, the current record, and relevant source before acting. Use existing commands and preserve unrelated edits. One fact has one canonical source; the brief is an index, not a document dump. Reference paths below resolve from the installed arvey-develop skill directory, not the project checkout.

### Role and authority

Any agent runtime can be the owner. The owner manages the project with the user: it discusses requirements, designs features, improves the architecture, breaks work into tasks, dispatches them to worker runtimes, reviews, decides, integrates, verifies the combined result, and reports progress. The owner does not edit product code or tests; workers do. Merging accepted candidates, running combined checks, and recording decisions are owner work, not implementation. Owner loop: plan the independent tasks; submit all of them (`arvey-develop dispatch submit`, `--parallel` for a batch) before waiting; wait with `arvey-develop dispatch wait`; send each non-trivial candidate to a cross-family review (`--review-of`); check a reviewer's claims before forwarding them as rework; accept or reject with specific reasons; `arvey-develop dispatch apply`; run the combined checks; report. Ask the user about unclear requirements, architecture changes, costly or irreversible actions, and command auto-approval flags; decide routing, retries, and acceptance against agreed criteria yourself. Keep the user informed: update the Now section of `.agent/PROJECT.md` at milestones, and `arvey-develop dispatch progress` shows live state. If no worker runtime is ready, report which ones and why, and ask before implementing; never switch roles silently. An assigned worker stays a worker and performs its packet; it does not repeat owner bootstrap. A reviewer must be a separate context that did not implement the candidate. Role names alone do not prove independence.

### Align using existing authorization

Existing user decisions and answered record entries satisfy alignment. A clear authorized reversible fix proceeds without another options exercise, visual, or yes/no confirmation. Ask only for genuinely missing outcome, scope, or authority decisions. Continue independent authorized work while the affected action waits. Use options with pros and cons or the lightest visual only when they clarify a real ambiguity. Record the decision/default in the existing record; do not create another approval document. See `references/working-backwards.md` and `references/visual-planning.md`.

### Bootstrap for the selected target

Scan the actual checkout read-only before workflow setup. Inspect initializer dry run and existing instruction shape; preserve custom text, links, guards, and historical records. Use only the three normal scaffold files when needed. A CLI/library artifact with no background service needs actual commands, target identity, and an explicit runtime exemption. It does not require production credentials, secret installation, review hooks, or an operator. Missing monitoring context means unknown. An explicitly monitored target requires a real configured operator and observations. Record applicability through `arvey-develop operator configure`; never fabricate heartbeat or owner data to quiet status. See `references/bootstrap.md`.

### Own the loop

Follow **align → intent → design → develop → test → deploy → evaluate → issues → revise → maintain**. Interpret deploy/evaluate for the selected surface: launch a service, install an app, or execute the delivered artifact. Define the final demo, observable scenarios, non-goals, success metric, and exact environment. Work backwards to the smallest runnable slice and map plausible rejection reasons to tests. Keep the design short and revise it when evidence changes the hypothesis.

Within established boundaries, choose implementation, experiments, tools, and collaboration. Do not weaken accepted criteria, access controls, regression budgets, or independent checks to obtain a pass. Keep one sustained delivery record; small fixes can use an existing issue/PR. Record actual command results and meaningful failure/recovery coverage. Select server/API checks for complete allowed responses, durable effects, caller/tenant boundaries, invalid input, dependency and retry/concurrency failures. A screenshot or health endpoint alone does not prove behavior. See `references/server-verification.md`, `references/ui-verification.md`, and `references/ratchets.md`.

### Evidence and phase gates

Use the canonical `arvey-develop delivery check` assessor. `--phase pre-deploy` requires candidate engineering checks and required review, deferring future deployment, target scenarios, and applicable runtime observation. `--phase post-deploy` requires that target evidence. Omitted phase retains post-deploy strength; `--require-complete` aliases complete. Complete additionally requires completion fields, no blockers/open decisions, and terminal integrated workstreams. Readiness is not deployment authority. See `references/delivery-quality.md`.

Record effective `source:v2:sha256:...` product identity, separately hashed `artifact_identity` when applicable, and immutable `provenance.tested_revision`. Git SHA/dirty state is provenance, not product identity. Metadata-only commits can preserve evidence. Product/configuration/checker changes affecting validity require appropriate checks/review even when a generated file is digest-excluded. Never relabel old receipts. Actual artifact bytes, source/environment, evidence paths, review, and freshness must match. Legacy uncertain evidence is migration-needed, not a fresh pass.

Reuse a result only when applicable source/artifact, command/check version and inputs, dependency/configuration context, required environment, and freshness are unchanged. Deterministic test evidence differs from live observations. `generated_at`, file mtime, copied files, and heartbeats do not renew `observed_at`/`expires_at`. Missing, malformed, future, or expired observations remain unknown/invalid/stale. Distinguish run result, liveness, checkpoint coverage, and latest successful observation. Status and handoff reads never mutate records. See `references/document-lifecycle.md`.

### Shared work and durability

One feature has one claim, owner, record, and named branch/worktree. Parallel child workstreams share one sustained record written by the owner. Freeze the shared base and contract before branching; commit claims first and keep the base clean. Shared rules/roles/contracts/fixtures can use safe relative internal symlinks; isolate mutable files, runtime resources, logs, and artifacts. Never store machine-local worktree paths in committed claims.

Configure one common-local Git `arvey.coordinationRef`. Only its registered base checkout mutates the authoritative board; a lock does not reconcile worktree snapshots or independent clones. The owner can write on behalf of workers with explicit actor/role provenance while preserving claim.owner. Actor strings are not authentication. `arvey-develop feature doctor` is the pre-spawn/pre-merge coordination gate. Workstreams become merged after actual integration; closeout is not a prerequisite for merging them. Spikes expire and never merge directly. Route contract changes through affected owners. See `references/multi-agent.md`.

Use the portable `arvey-develop feature handoff` packet for decisions/defaults, dependencies, contracts, demo, target, evidence, identities, record/claim revisions, stale/unknown observations, and next action. The receiver rereads authoritative records and checks freshness. Local paths appear only with explicit `--include-local`. Merged closeout calls canonical complete assessment for the immutable tested combined candidate/artifact, then checks clean/archive hygiene and terminal claim/record/evidence committed to the designated ref. A label/count or the record's own source string cannot prove completion. An abandoned claim can be archivable with a reason; it is not delivered. Local durability is distinct from remote publication. See `references/orchestration.md`.

### Operational issues

`fixed` means an exact fix is deployed; `verified` needs current-cycle operator evidence for the same diagnostic intent in a fresh comparable post-deployment window; `closed` needs subsequent suitable observation and regression/runbook evidence. Reopen/rework/redeploy invalidates downstream active attestations while retaining history. Blocking suspends the actual state and cannot skip a lifecycle edge or role. A linked fix can defer future verification at pre-deploy; genuine prerequisites block readiness. Final blocking issues require current-cycle verified/closed assurance. An explicitly nonblocking out-of-scope issue needs reason/owner; missing/unreadable linked state never passes. See `references/operations-loop.md`.

### Data and credentials

Honor authorized product disclosure changes; update conflicting project rules/tests together. Define intended fields, audiences, and ownership/tenant scope. Ordinary task inputs/results/progress/errors are not automatically secrets. Explain specific exclusions rather than silently dropping requested data. Host/external access restrictions remain effective.

Use established credential injection, preferably a broker or short-lived scoped capability. Reading long-lived plaintext secrets requires explicit scoped authorization. Never print, copy, commit, log, screenshot, or send credential values, keys, credential stores, or environment dumps. Keep secret locations as metadata only, outside the repository by default with restrictive permissions. Preserve scanners/guards; install relevant controls only within authorized setup scope. A repo-local secret path requires explicit authorization, ignore/deny-list entries, and restrictive permissions. See `references/credential-access.md` and `references/secret-hygiene.md`.

### Progress and stopping

Report active, waiting, blocked, or complete with observable facts. Every wait names a dependency/condition. Retry with a new hypothesis/input or a bounded documented transient rationale; no universal retry count applies. Change an unchanged failing experiment. Escalate the smallest missing decision when no permitted action can change the result, continuing independent work when possible.

Stop when accepted scenarios, final demo, applicable automated/runtime/performance checks, required review, and durable evidence pass. Failed or NOT RUN required criteria remain incomplete. Do not add perpetual monitoring, another runtime, or unrelated cleanup after acceptance. Report exact branch/commit, effective source/artifact, real results, migration, and limitations. Behavior evaluations use fresh raw-task contexts and a separate evaluator rubric; phrase tests are structural checks only.
<!-- agentic-delivery:end -->
