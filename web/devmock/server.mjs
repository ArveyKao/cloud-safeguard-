#!/usr/bin/env node
/**
 * Cloud Safeguard — local devmock API for the web console.
 *
 * Implements the subset of docs/CONTRACT.md §3–§5 that the console consumes,
 * with realistic seeded fixtures, so the UI can be developed and screenshotted
 * without the Go control plane. NOT part of the shipped bundle: `npm run build`
 * only compiles src/; this file is development tooling.
 *
 * Run:  npm run mock            (listens on 127.0.0.1:8787)
 *       MOCK_ADMIN_TOKEN=... MOCK_PORT=8787 node devmock/server.mjs
 *
 * No real credentials are used or stored. The admin token is generated at
 * startup (or supplied via MOCK_ADMIN_TOKEN) and printed once to the console.
 */
import http from 'node:http'
import crypto from 'node:crypto'

const PORT = Number(process.env.MOCK_PORT ?? 8787)
const HOST = process.env.MOCK_HOST ?? '127.0.0.1'
const ADMIN_TOKEN = process.env.MOCK_ADMIN_TOKEN ?? `csg_adm_${crypto.randomBytes(24).toString('base64url')}`
const VERSION = '0.1.0'
const STARTED_AT = Date.now() - 9_240_000 // pretend the control plane has been up a while

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

let counter = 0
const rand = (bytes = 12) => crypto.randomBytes(bytes).toString('hex')
const id = (prefix) => `${prefix}_${rand(8)}`
const iso = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString()
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex')

function send(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  })
  res.end(body)
}

const ok = (res, data, status = 200) => send(res, status, { data })
const fail = (res, status, code, message, details) =>
  send(res, status, { error: { code, message, ...(details ? { details } : {}) } })

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 1_048_576) {
        reject(new Error('request body exceeds 1 MiB'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (chunks.length === 0) return resolve({})
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new Error('invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

/* ------------------------------------------------------------------ */
/* Audit chain                                                         */
/* ------------------------------------------------------------------ */

const state = {
  seq: 0,
  audit: [],
  capabilities: [],
  providers: [],
  agents: [],
  leases: [],
  settings: {
    auto_approve_max_risk: 'low',
    auto_approve_max_ttl_seconds: 900,
    max_lease_ttl_seconds: 3600,
    pending_timeout_seconds: 600,
    max_concurrent_leases_per_agent: 3,
    leases_per_minute_per_agent: 6,
    require_reason_for_risk: 'medium',
  },
}

function appendAudit({
  time,
  actor_type = 'system',
  actor_id = 'system',
  actor_name = 'Cloud Safeguard',
  action,
  status = 'ok',
  severity = 'info',
  target_type = '',
  target_id = '',
  metadata,
}) {
  state.seq += 1
  const seq = state.seq
  const eventTime = time ?? new Date().toISOString()
  const prevHash = state.audit.length ? state.audit[state.audit.length - 1].hash : '0'.repeat(64)
  const canonical = JSON.stringify({
    seq,
    time: eventTime,
    actor_type,
    actor_id,
    actor_name,
    action,
    status,
    severity,
    target_type,
    target_id,
    ...(metadata && Object.keys(metadata).length > 0 ? { metadata } : {}),
  })
  const hash = sha256(`csg-audit-v1\n${prevHash}\n${canonical}`)
  const event = {
    seq,
    id: id('evt'),
    time: eventTime,
    actor_type,
    actor_id,
    actor_name,
    action,
    status,
    severity,
    target_type,
    target_id,
    ...(metadata && Object.keys(metadata).length > 0 ? { metadata } : {}),
    prev_hash: prevHash,
    hash,
  }
  state.audit.push(event)
  return event
}

/* ------------------------------------------------------------------ */
/* Seed: capability catalog (docs/CONTRACT.md §7)                      */
/* ------------------------------------------------------------------ */

const ACCESS_RANK = { read: 1, write: 2, admin: 3 }
const ROLE_MAX_ACCESS = { guest: 'read', member: 'write', administrator: 'admin' }
const VALID_ROLES = new Set(['guest', 'member', 'administrator'])
const VALID_ACCESS = new Set(['read', 'write', 'admin'])

function rolePermitsAccess(role, access) {
  return ACCESS_RANK[access] <= ACCESS_RANK[ROLE_MAX_ACCESS[role]]
}

function defaultGrantsForRole(role) {
  return state.capabilities
    .filter((capability) => capability.enabled && rolePermitsAccess(role, capability.access))
    .map((capability) => capability.id)
}

function seedCapability({
  id: capabilityId,
  name,
  risk,
  access,
  description,
  defaultTtl,
  maxTtl,
  policy,
  params = [],
}) {
  const now = iso(-86_400_000 * 3)
  state.capabilities.push({
    id: capabilityId,
    name,
    description,
    provider_type: 'aliyun',
    risk,
    access,
    policy_template: JSON.stringify(policy),
    params,
    default_ttl_seconds: defaultTtl,
    max_ttl_seconds: maxTtl,
    enabled: true,
    builtin: true,
    created_at: now,
    updated_at: now,
  })
}

seedCapability({
  id: 'aliyun.cloud.read',
  name: 'Cloud read-only inventory',
  risk: 'low',
  access: 'read',
  description:
    'List ECS instances, DNS zones and records, and verify the caller identity. Read-only and safe for unattended agents.',
  defaultTtl: 900,
  maxTtl: 1800,
  policy: {
    Version: '1',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['ecs:Describe*', 'alidns:Describe*', 'oss:List*', 'sts:GetCallerIdentity'],
        Resource: ['*'],
      },
    ],
  },
})

seedCapability({
  id: 'aliyun.dns.manage',
  name: 'Manage DNS records for one domain',
  risk: 'medium',
  access: 'write',
  description:
    'Create, update and delete DNS records inside a single domain, for certificate challenges and host cutovers.',
  defaultTtl: 900,
  maxTtl: 1800,
  policy: {
    Version: '1',
    Statement: [
      {
        Effect: 'Allow',
        Action: [
          'alidns:DescribeDomainRecords',
          'alidns:AddDomainRecord',
          'alidns:UpdateDomainRecord',
          'alidns:DeleteDomainRecord',
          'alidns:SetDomainRecordStatus',
        ],
        Resource: ['acs:alidns:*:*:domain/{{domain}}'],
      },
    ],
  },
  params: [
    {
      name: 'domain',
      description: 'Domain the policy is scoped to',
      required: true,
      pattern: '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$',
    },
  ],
})

seedCapability({
  id: 'aliyun.cert.dns01',
  name: 'ACME DNS-01 challenge token for one domain',
  risk: 'medium',
  access: 'write',
  description:
    'Write the single TXT record needed for a certificate challenge, scoped to one domain.',
  defaultTtl: 600,
  maxTtl: 1200,
  policy: {
    Version: '1',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['alidns:DescribeDomainRecords', 'alidns:AddDomainRecord', 'alidns:DeleteDomainRecord'],
        Resource: ['acs:alidns:*:*:domain/{{domain}}'],
      },
    ],
  },
  params: [
    {
      name: 'domain',
      description: 'Domain the policy is scoped to',
      required: true,
      pattern: '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$',
    },
  ],
})

seedCapability({
  id: 'aliyun.ecs.instance.ops',
  name: 'Start/stop/restart one ECS instance',
  risk: 'high',
  access: 'write',
  description:
    'Power operations on exactly one ECS instance. Requires human approval because it can interrupt production.',
  defaultTtl: 900,
  maxTtl: 1800,
  policy: {
    Version: '1',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['ecs:StartInstance', 'ecs:StopInstance', 'ecs:RebootInstance', 'ecs:DescribeInstances'],
        Resource: ['acs:ecs:*:*:instance/{{instance_id}}'],
      },
    ],
  },
  params: [
    {
      name: 'instance_id',
      description: 'ECS instance ID, e.g. i-2ze0demo001',
      required: true,
      pattern: '^i-[A-Za-z0-9]+$',
    },
  ],
})

seedCapability({
  id: 'aliyun.account.admin',
  name: 'Emergency account-wide access, IAM excluded',
  risk: 'critical',
  access: 'admin',
  description:
    'Account-wide emergency access for a declared incident. Always requires break-glass flag and human approval; critical-severity audit. IAM and RAM remain denied.',
  defaultTtl: 900,
  maxTtl: 1800,
  policy: {
    Version: '1',
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
  },
})

/* ------------------------------------------------------------------ */
/* Seed: provider                                                      */
/* ------------------------------------------------------------------ */

state.providers.push({
  id: 'prv_demo_aliyun',
  name: 'demo-aliyun',
  type: 'aliyun',
  mode: 'mock',
  region: 'cn-hangzhou',
  role_arn: 'acs:ram::1234567890123456:role/csg-demo',
  access_key_id_masked: 'LTAI****Demo',
  status: 'active',
  last_tested_at: iso(-3 * 60_000),
  last_test_ok: true,
  created_at: iso(-86_400_000 * 3),
  updated_at: iso(-3 * 60_000),
})

/* ------------------------------------------------------------------ */
/* Seed: agents                                                        */
/* ------------------------------------------------------------------ */

const agentClaude = {
  id: 'agt_claude_code',
  name: 'claude-code',
  description: 'Primary coding agent (Claude Code compatible)',
  status: 'active',
  role: 'administrator',
  grants: [
    'aliyun.cloud.read',
    'aliyun.dns.manage',
    'aliyun.cert.dns01',
    'aliyun.ecs.instance.ops',
    'aliyun.account.admin',
  ],
  max_ttl_seconds: 3600,
  max_concurrent_leases: 3,
  token_prefix: 'csg_agt_7f3a',
  last_seen_at: iso(-2 * 60_000),
  created_at: iso(-86_400_000 * 3),
  updated_at: iso(-86_400_000 * 3),
}

const agentHermes = {
  id: 'agt_hermes_researcher',
  name: 'hermes-researcher',
  description: 'Read-only research agent',
  status: 'active',
  role: 'guest',
  grants: ['aliyun.cloud.read'],
  max_ttl_seconds: 900,
  max_concurrent_leases: 1,
  token_prefix: 'csg_agt_91c2',
  last_seen_at: iso(-16 * 60_000),
  created_at: iso(-86_400_000 * 3),
  updated_at: iso(-86_400_000 * 3),
}
state.agents.push(agentClaude, agentHermes)

/* ------------------------------------------------------------------ */
/* Seed: leases                                                        */
/* ------------------------------------------------------------------ */

const capabilityName = (capabilityId) =>
  state.capabilities.find((capability) => capability.id === capabilityId)?.name ?? capabilityId
const capabilityRisk = (capabilityId) =>
  state.capabilities.find((capability) => capability.id === capabilityId)?.risk ?? 'low'

function decision(outcome, effectiveTtl, reasons) {
  return { outcome, effective_ttl_seconds: effectiveTtl, reasons }
}

function allowReason(rule, detail) {
  return { rule, outcome: 'allow', detail }
}

const baseRules = (capabilityId, agent, ttl) => [
  allowReason('capability_granted', `${agent.name} is granted ${capabilityId}`),
  allowReason('capability_enabled', `${capabilityId} is enabled`),
  allowReason('provider_available', 'provider demo-aliyun matches type aliyun'),
  allowReason('provider_active', 'provider demo-aliyun is active'),
  allowReason('reason_required', 'reason supplied and risk requires one'),
  allowReason('break_glass_required', 'capability risk is below critical'),
  allowReason('ttl_within_capability', `requested ${ttl}s is within capability max`),
  allowReason('ttl_within_agent', `requested ${ttl}s is within agent max`),
  allowReason('ttl_within_global', `requested ${ttl}s is within global max 3600s`),
  allowReason('concurrency_available', 'active leases are below the concurrency cap'),
  allowReason('rate_limit', 'lease rate is within the per-minute limit'),
]

function seedLease(lease) {
  const agent = state.agents.find((item) => item.id === lease.agent_id)
  const provider = state.providers[0]
  const risk = capabilityRisk(lease.capability_id)
  const requested = lease.requested_ttl_seconds ?? 900
  const effective = lease.effective_ttl_seconds ?? requested
  const merged = {
    id: lease.id,
    agent_id: lease.agent_id,
    agent_name: agent?.name ?? lease.agent_id,
    capability_id: lease.capability_id,
    capability_name: capabilityName(lease.capability_id),
    provider_id: provider.id,
    provider_name: provider.name,
    provider_mode: 'mock',
    risk,
    params: lease.params ?? {},
    reason: lease.reason ?? '',
    requested_ttl_seconds: requested,
    effective_ttl_seconds: effective,
    status: lease.status,
    break_glass: lease.break_glass ?? false,
    session_name: `csg-${lease.agent_id}-${lease.id.slice(-6)}`,
    credential_available: lease.status === 'active',
    created_at: lease.created_at ?? iso(-60_000),
    ...lease,
  }
  state.leases.push(merged)
  return merged
}

const claudeId = agentClaude.id
const hermesId = agentHermes.id

seedLease({
  id: 'lea_7f3a91c2d4e5',
  agent_id: claudeId,
  capability_id: 'aliyun.dns.manage',
  params: { domain: 'arveykao.com' },
  reason:
    'Add the ACME challenge TXT record and repoint www to the new origin for the guanlanstudio.com cutover.',
  requested_ttl_seconds: 600,
  effective_ttl_seconds: 600,
  status: 'pending',
  decision: decision('require_approval', 600, [
    ...baseRules('aliyun.dns.manage', agentClaude, 600),
    {
      rule: 'risk_above_auto',
      outcome: 'require_approval',
      detail: 'risk medium exceeds auto-approve maximum low',
    },
  ]),
  created_at: iso(-2 * 60_000 - 12_000),
})

seedLease({
  id: 'lea_2b8c14a06f77',
  agent_id: claudeId,
  capability_id: 'aliyun.ecs.instance.ops',
  params: { instance_id: 'i-2ze0demo001' },
  reason: 'Restart web-01 after the nginx config rollout; health checks are failing.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'pending',
  decision: decision('require_approval', 900, [
    ...baseRules('aliyun.ecs.instance.ops', agentClaude, 900),
    {
      rule: 'risk_above_auto',
      outcome: 'require_approval',
      detail: 'risk high exceeds auto-approve maximum low',
    },
  ]),
  created_at: iso(-6 * 60_000),
})

seedLease({
  id: 'lea_c93d8e11a204',
  agent_id: claudeId,
  capability_id: 'aliyun.account.admin',
  reason: 'Emergency containment: deploy credentials were leaked in a build log.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'pending',
  break_glass: true,
  decision: decision('require_approval', 900, [
    ...baseRules('aliyun.account.admin', agentClaude, 900).map((reason) =>
      reason.rule === 'break_glass_required'
        ? { rule: 'break_glass_required', outcome: 'allow', detail: 'break_glass flag set' }
        : reason,
    ),
    {
      rule: 'break_glass_approval',
      outcome: 'require_approval',
      detail: 'break-glass requests always require human approval',
    },
  ]),
  created_at: iso(-90_000),
})

seedLease({
  id: 'lea_5a1f7c0b93de',
  agent_id: claudeId,
  capability_id: 'aliyun.cert.dns01',
  params: { domain: 'guanlanstudio.com' },
  reason: 'Renew the wildcard certificate for guanlanstudio.com.',
  requested_ttl_seconds: 600,
  effective_ttl_seconds: 600,
  status: 'pending',
  decision: decision('require_approval', 600, [
    ...baseRules('aliyun.cert.dns01', agentClaude, 600),
    {
      rule: 'risk_above_auto',
      outcome: 'require_approval',
      detail: 'risk medium exceeds auto-approve maximum low',
    },
  ]),
  created_at: iso(-4 * 60_000),
})

seedLease({
  id: 'lea_9d02aa6e5b41',
  agent_id: claudeId,
  capability_id: 'aliyun.cloud.read',
  params: {},
  reason: 'Inventory ECS instances and DNS zones before the cutover runbook.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'active',
  approved_by: 'auto',
  decision: decision('auto_approve', 900, [
    ...baseRules('aliyun.cloud.read', agentClaude, 900),
    { rule: 'auto_approve', outcome: 'allow', detail: 'no deny or require-approval rule triggered' },
  ]),
  created_at: iso(-3 * 60_000),
  approved_at: iso(-3 * 60_000),
  issued_at: iso(-3 * 60_000),
  expires_at: iso(12 * 60_000),
  credential_fingerprint: 'LTAI****A4F2',
})

seedLease({
  id: 'lea_3c7e0b2aa118',
  agent_id: claudeId,
  capability_id: 'aliyun.dns.manage',
  params: { domain: 'arveykao.com' },
  reason: 'Publish the certificate renewal TXT records for arveykao.com.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'active',
  approved_by: 'admin',
  approval_note: 'Approved for the certificate renewal window; expires with the TXT cleanup.',
  decision: decision('require_approval', 900, baseRules('aliyun.dns.manage', agentClaude, 900)),
  created_at: iso(-8 * 60_000),
  approved_at: iso(-7 * 60_000),
  issued_at: iso(-7 * 60_000),
  expires_at: iso(3 * 60_000 + 30_000),
  credential_fingerprint: 'LTAI****7C31',
})

seedLease({
  id: 'lea_1e6b8d90c3f2',
  agent_id: hermesId,
  capability_id: 'aliyun.ecs.instance.ops',
  params: { instance_id: 'i-2ze0demo001' },
  reason: 'Restart the instance to pick up a dependency update.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'denied',
  denied_reason:
    'capability_not_granted: hermes-researcher is not granted aliyun.ecs.instance.ops',
  decision: decision('deny', 900, [
    {
      rule: 'capability_granted',
      outcome: 'deny',
      detail: 'hermes-researcher is not granted aliyun.ecs.instance.ops',
    },
  ]),
  created_at: iso(-30 * 60_000),
})

seedLease({
  id: 'lea_8b4c02fe7a19',
  agent_id: hermesId,
  capability_id: 'aliyun.cloud.read',
  params: {},
  reason: 'Collect account inventory for the weekly research digest.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'expired',
  approved_by: 'auto',
  decision: decision('auto_approve', 900, baseRules('aliyun.cloud.read', agentHermes, 900)),
  created_at: iso(-2 * 60 * 60_000),
  approved_at: iso(-2 * 60 * 60_000),
  issued_at: iso(-2 * 60 * 60_000),
  expires_at: iso(-105 * 60_000),
  credential_fingerprint: 'LTAI****92B7',
})

seedLease({
  id: 'lea_0f5a9c3d7e21',
  agent_id: claudeId,
  capability_id: 'aliyun.account.admin',
  reason: 'Break-glass approved for the suspected key leak; access window now closed by operator.',
  requested_ttl_seconds: 900,
  effective_ttl_seconds: 900,
  status: 'revoked',
  break_glass: true,
  approved_by: 'admin',
  approval_note: 'Emergency window approved — incident INC-2041.',
  revoke_reason: 'break-glass window closed by operator after containment',
  decision: decision('require_approval', 900, baseRules('aliyun.account.admin', agentClaude, 900)),
  created_at: iso(-55 * 60_000),
  approved_at: iso(-54 * 60_000),
  issued_at: iso(-54 * 60_000),
  expires_at: iso(-45 * 60_000),
  revoked_at: iso(-40 * 60_000),
})

seedLease({
  id: 'lea_6d2e81bc0a54',
  agent_id: claudeId,
  capability_id: 'aliyun.ecs.instance.ops',
  params: { instance_id: 'i-2ze0demo002' },
  reason: 'Stop the idle worker before the maintenance window.',
  requested_ttl_seconds: 1800,
  effective_ttl_seconds: 1800,
  status: 'failed',
  approved_by: 'admin',
  failure_reason: 'provider_error: STS AssumeRole timed out after 10s',
  decision: decision('require_approval', 1800, baseRules('aliyun.ecs.instance.ops', agentClaude, 1800)),
  created_at: iso(-70 * 60_000),
  approved_at: iso(-69 * 60_000),
})

/* ------------------------------------------------------------------ */
/* Seed: audit events (chronological; hash chain is real)              */
/* ------------------------------------------------------------------ */

const t = (minutesAgo) => iso(-minutesAgo * 60_000)

appendAudit({
  time: t(24 * 60),
  action: 'auth.admin_login',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  metadata: { remote_addr: '127.0.0.1:53211' },
})
appendAudit({
  time: t(23 * 60),
  action: 'provider.created',
  target_type: 'provider',
  target_id: 'prv_demo_aliyun',
  metadata: { id: 'prv_demo_aliyun', name: 'demo-aliyun', mode: 'mock' },
})
appendAudit({
  time: t(22 * 60),
  action: 'agent.created',
  target_type: 'agent',
  target_id: 'agt_claude_code',
  metadata: { agent: 'claude-code', grants: 5 },
})
appendAudit({
  time: t(90),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_1e6b8d90c3f2',
  metadata: {
    capability: 'aliyun.ecs.instance.ops',
    risk: 'high',
    ttl_seconds: 900,
    decision: 'deny',
  },
})
appendAudit({
  time: t(90),
  action: 'lease.denied',
  actor_type: 'system',
  actor_id: 'system',
  actor_name: 'Cloud Safeguard',
  severity: 'warning',
  target_type: 'lease',
  target_id: 'lea_1e6b8d90c3f2',
  metadata: { reasons: ['capability_not_granted'], denied_reason: 'capability not granted' },
})
appendAudit({
  time: t(70),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_6d2e81bc0a54',
  metadata: { capability: 'aliyun.ecs.instance.ops', risk: 'high', ttl_seconds: 1800 },
})
appendAudit({
  time: t(69),
  action: 'lease.approved',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  target_type: 'lease',
  target_id: 'lea_6d2e81bc0a54',
  metadata: { ttl_seconds: 1800, note: 'maintenance window' },
})
appendAudit({
  time: t(69),
  action: 'lease.credential_issued',
  actor_type: 'system',
  actor_id: 'system',
  actor_name: 'Cloud Safeguard',
  target_type: 'lease',
  target_id: 'lea_6d2e81bc0a54',
  metadata: { fingerprint: 'LTAI****11C0', expires_at: iso(-51 * 60_000) },
})
appendAudit({
  time: t(69),
  action: 'lease.failed',
  actor_type: 'system',
  actor_id: 'system',
  actor_name: 'Cloud Safeguard',
  severity: 'warning',
  status: 'failed',
  target_type: 'lease',
  target_id: 'lea_6d2e81bc0a54',
  metadata: { error: 'provider_error: STS AssumeRole timed out after 10s' },
})
appendAudit({
  time: t(55),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_0f5a9c3d7e21',
  severity: 'critical',
  metadata: { capability: 'aliyun.account.admin', risk: 'critical', break_glass: true },
})
appendAudit({
  time: t(54),
  action: 'lease.approved',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  severity: 'critical',
  target_type: 'lease',
  target_id: 'lea_0f5a9c3d7e21',
  metadata: { ttl_seconds: 900, note: 'Emergency window approved — incident INC-2041' },
})
appendAudit({
  time: t(54),
  action: 'lease.credential_issued',
  actor_type: 'system',
  actor_id: 'system',
  actor_name: 'Cloud Safeguard',
  target_type: 'lease',
  target_id: 'lea_0f5a9c3d7e21',
  metadata: { fingerprint: 'LTAI****E7D4', expires_at: iso(-45 * 60_000) },
})
appendAudit({
  time: t(53),
  action: 'cloud.api_called',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_0f5a9c3d7e21',
  metadata: {
    service: 'ecs',
    action: 'ecs:DescribeInstances',
    resource: 'acs:ecs:cn-hangzhou:1234567890123456:instance/*',
    http_status: 200,
    request_id: 'req_8f2c1a',
  },
})
appendAudit({
  time: t(45),
  action: 'lease.revoked',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  severity: 'critical',
  status: 'ok',
  target_type: 'lease',
  target_id: 'lea_0f5a9c3d7e21',
  metadata: { reason: 'break-glass window closed by operator after containment' },
})
appendAudit({
  time: t(40),
  action: 'policy.updated',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  severity: 'warning',
  target_type: 'policy',
  target_id: 'global',
  metadata: {
    before: { auto_approve_max_risk: 'low', max_lease_ttl_seconds: 3600 },
    after: { auto_approve_max_risk: 'low', max_lease_ttl_seconds: 3600 },
  },
})
appendAudit({
  time: t(30),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_hermes_researcher',
  actor_name: 'hermes-researcher',
  target_type: 'lease',
  target_id: 'lea_1e6b8d90c3f2',
  metadata: { capability: 'aliyun.ecs.instance.ops', risk: 'high', decision: 'deny' },
})
appendAudit({
  time: t(30),
  action: 'cloud.api_called',
  actor_type: 'agent',
  actor_id: 'agt_hermes_researcher',
  actor_name: 'hermes-researcher',
  target_type: 'lease',
  target_id: 'lea_8b4c02fe7a19',
  metadata: {
    service: 'ecs',
    action: 'ecs:DescribeInstances',
    resource: 'acs:ecs:cn-hangzhou:1234567890123456:instance/*',
    http_status: 200,
    request_id: 'req_31d9bb',
  },
})
appendAudit({
  time: t(16),
  action: 'auth.admin_login',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  metadata: { remote_addr: '127.0.0.1:60122' },
})
appendAudit({
  time: t(10),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_3c7e0b2aa118',
  metadata: { capability: 'aliyun.dns.manage', risk: 'medium', ttl_seconds: 900 },
})
appendAudit({
  time: t(8),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_3c7e0b2aa118',
  metadata: { capability: 'aliyun.dns.manage', risk: 'medium', ttl_seconds: 900 },
})
appendAudit({
  time: t(7),
  action: 'lease.approved',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  target_type: 'lease',
  target_id: 'lea_3c7e0b2aa118',
  metadata: { ttl_seconds: 900, note: 'certificate renewal window' },
})
appendAudit({
  time: t(7),
  action: 'lease.credential_issued',
  actor_type: 'system',
  actor_id: 'system',
  actor_name: 'Cloud Safeguard',
  target_type: 'lease',
  target_id: 'lea_3c7e0b2aa118',
  metadata: { fingerprint: 'LTAI****7C31', expires_at: iso(3 * 60_000) },
})
appendAudit({
  time: t(6),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_2b8c14a06f77',
  metadata: { capability: 'aliyun.ecs.instance.ops', risk: 'high', decision: 'require_approval' },
})
appendAudit({
  time: t(5),
  action: 'cloud.api_called',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_9d02aa6e5b41',
  metadata: {
    service: 'ecs',
    action: 'ecs:DescribeInstances',
    resource: 'acs:ecs:cn-hangzhou:1234567890123456:instance/*',
    http_status: 200,
    request_id: 'req_7ac51f',
  },
})
appendAudit({
  time: t(4),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_5a1f7c0b93de',
  metadata: { capability: 'aliyun.cert.dns01', risk: 'medium', decision: 'require_approval' },
})
appendAudit({
  time: t(3),
  action: 'provider.tested',
  actor_type: 'admin',
  actor_id: 'admin',
  actor_name: 'operator',
  target_type: 'provider',
  target_id: 'prv_demo_aliyun',
  metadata: { ok: true, message: 'mock signing key present' },
})
appendAudit({
  time: t(2),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_7f3a91c2d4e5',
  metadata: { capability: 'aliyun.dns.manage', risk: 'medium', decision: 'require_approval' },
})
appendAudit({
  time: t(1.5),
  action: 'lease.requested',
  actor_type: 'agent',
  actor_id: 'agt_claude_code',
  actor_name: 'claude-code',
  target_type: 'lease',
  target_id: 'lea_c93d8e11a204',
  severity: 'critical',
  metadata: { capability: 'aliyun.account.admin', risk: 'critical', break_glass: true },
})

/* ------------------------------------------------------------------ */
/* Views                                                               */
/* ------------------------------------------------------------------ */

function riskBreakdown() {
  const inFlight = state.leases.filter(
    (lease) => lease.status === 'active' || lease.status === 'pending',
  )
  return {
    low: inFlight.filter((lease) => lease.risk === 'low').length,
    medium: inFlight.filter((lease) => lease.risk === 'medium').length,
    high: inFlight.filter((lease) => lease.risk === 'high').length,
    critical: inFlight.filter((lease) => lease.risk === 'critical').length,
  }
}

function buildOverview() {
  const now = Date.now()
  const dayAgo = now - 86_400_000
  const active = state.leases.filter((lease) => lease.status === 'active')
  const pending = state.leases.filter((lease) => lease.status === 'pending')
  return {
    counts: {
      agents: state.agents.length,
      active_agents: state.agents.filter((agent) => agent.status === 'active').length,
      capabilities: state.capabilities.length,
      providers: state.providers.length,
      active_leases: active.length,
      pending_leases: pending.length,
      events_24h: state.audit.filter((event) => Date.parse(event.time) >= dayAgo).length,
      denied_leases_24h: state.leases.filter(
        (lease) => lease.status === 'denied' && Date.parse(lease.created_at) >= dayAgo,
      ).length,
    },
    risk_breakdown: riskBreakdown(),
    policy: state.settings,
    vault: {
      configured: true,
      key_fingerprint: sha256('devmock-master-key').slice(0, 32),
      secrets_stored: state.providers.length + active.length,
    },
    pending_leases: pending.slice(0, 20),
    active_leases: active.slice(0, 20),
    recent_events: [...state.audit].reverse().slice(0, 20),
    providers: state.providers,
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - STARTED_AT) / 1000) + 120,
    server_time: new Date().toISOString(),
  }
}

/* ------------------------------------------------------------------ */
/* Request handling                                                    */
/* ------------------------------------------------------------------ */

function authorized(req) {
  const header = req.headers.authorization ?? ''
  if (!header.startsWith('Bearer ')) return false
  const token = header.slice('Bearer '.length).trim()
  return token.length > 0 && token === ADMIN_TOKEN
}

function listResult(items, url) {
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 50), 1), 200)
  const offset = Math.max(Number(url.searchParams.get('offset') ?? 0), 0)
  return { items: items.slice(offset, offset + limit), total: items.length }
}

function findLease(leaseId) {
  return state.leases.find((lease) => lease.id === leaseId)
}

function leaseNotFound(res) {
  return fail(res, 404, 'not_found', 'lease not found')
}

async function handleAdmin(req, res, url, segments) {
  const method = req.method
  const path = segments.join('/')

  // POST /admin/login
  if (path === 'login' && method === 'POST') {
    if (!authorized(req)) return fail(res, 401, 'unauthorized', 'invalid admin token')
    appendAudit({
      action: 'auth.admin_login',
      actor_type: 'admin',
      actor_id: 'admin',
      actor_name: 'operator',
      metadata: { remote_addr: req.socket.remoteAddress ?? '127.0.0.1' },
    })
    return ok(res, { ok: true, role: 'admin', version: VERSION })
  }

  if (!authorized(req)) return fail(res, 401, 'unauthorized', 'invalid admin token')

  if (path === 'overview' && method === 'GET') return ok(res, buildOverview())

  if (path === 'providers' && method === 'GET') {
    return ok(res, { items: state.providers, total: state.providers.length })
  }
  if (segments[0] === 'providers' && segments[1]) {
    const provider = state.providers.find((item) => item.id === segments[1])
    if (!provider) return fail(res, 404, 'not_found', 'provider not found')
    if (segments[2] === 'test' && method === 'POST') {
      provider.last_tested_at = new Date().toISOString()
      provider.last_test_ok = true
      provider.updated_at = provider.last_tested_at
      appendAudit({
        action: 'provider.tested',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        target_type: 'provider',
        target_id: provider.id,
        metadata: { ok: true, message: 'mock signing key present' },
      })
      return ok(res, { ok: true, message: 'mock signing key present', tested_at: provider.last_tested_at })
    }
    if (segments[2] === 'rotate' && method === 'POST') {
      const body = await readBody(req)
      if (!body.access_key_id || !body.access_key_secret) {
        return fail(res, 400, 'invalid_request', 'access_key_id and access_key_secret are required')
      }
      const rawId = String(body.access_key_id)
      const masked = `${rawId.slice(0, 4)}****${rawId.slice(-4)}`
      const previous = provider.access_key_id_masked
      provider.access_key_id_masked = masked
      provider.updated_at = new Date().toISOString()
      // Never log or persist the supplied secret, not even in the mock.
      appendAudit({
        action: 'provider.credential_rotated',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        severity: 'warning',
        target_type: 'provider',
        target_id: provider.id,
        metadata: { provider_id: provider.id, old_access_key_id_masked: previous, new_access_key_id_masked: masked },
      })
      return ok(res, provider)
    }
    if (method === 'PATCH') {
      const body = await readBody(req)
      for (const field of ['name', 'region', 'role_arn', 'status']) {
        if (body[field] !== undefined) provider[field] = body[field]
      }
      provider.updated_at = new Date().toISOString()
      appendAudit({
        action: 'provider.updated',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        target_type: 'provider',
        target_id: provider.id,
        metadata: { fields: Object.keys(body) },
      })
      return ok(res, provider)
    }
    if (method === 'GET') return ok(res, provider)
  }

  if (path === 'capabilities' && method === 'GET') {
    return ok(res, { items: state.capabilities, total: state.capabilities.length })
  }
  if (path === 'capabilities' && method === 'POST') {
    const body = await readBody(req)
    if (!body.name || !body.policy_template) {
      return fail(res, 400, 'invalid_request', 'name and policy_template are required')
    }
    try {
      JSON.parse(body.policy_template)
    } catch {
      return fail(res, 400, 'invalid_request', 'policy_template must be valid JSON')
    }
    const access =
      body.access === undefined || body.access === '' || body.access === null
        ? 'admin'
        : body.access
    if (!VALID_ACCESS.has(access)) {
      return fail(res, 400, 'invalid_request', `invalid access: ${access}`)
    }
    const now = new Date().toISOString()
    const capability = {
      id: id('cap'),
      name: body.name,
      description: body.description ?? '',
      provider_type: 'aliyun',
      risk: body.risk ?? 'low',
      access,
      policy_template: body.policy_template,
      params: body.params ?? [],
      default_ttl_seconds: Number(body.default_ttl_seconds ?? 900),
      max_ttl_seconds: Number(body.max_ttl_seconds ?? 1800),
      enabled: true,
      builtin: false,
      created_at: now,
      updated_at: now,
    }
    state.capabilities.push(capability)
    appendAudit({
      action: 'capability.created',
      actor_type: 'admin',
      actor_id: 'admin',
      actor_name: 'operator',
      target_type: 'capability',
      target_id: capability.id,
      metadata: { capability_id: capability.id, risk: capability.risk },
    })
    return ok(res, capability, 201)
  }
  if (segments[0] === 'capabilities' && segments[1] && method === 'PATCH') {
    const capability = state.capabilities.find((item) => item.id === segments[1])
    if (!capability) return fail(res, 404, 'not_found', 'capability not found')
    const body = await readBody(req)
    if (body.access !== undefined) {
      if (!VALID_ACCESS.has(body.access)) {
        return fail(res, 400, 'invalid_request', `invalid access: ${body.access}`)
      }
      if (capability.builtin) {
        if (body.access !== capability.access) {
          return fail(res, 400, 'invalid_request', 'cannot change access on a built-in capability')
        }
      } else {
        const nextAccess = body.access
        if (ACCESS_RANK[nextAccess] > ACCESS_RANK[capability.access]) {
          const blocked = state.agents.filter(
            (agent) =>
              agent.grants.includes(capability.id) && !rolePermitsAccess(agent.role, nextAccess),
          )
          if (blocked.length > 0) {
            const names = blocked.map((agent) => agent.name).join(', ')
            return fail(
              res,
              400,
              'invalid_request',
              `cannot raise access to ${nextAccess}; granted agents whose role would not permit it: ${names}`,
            )
          }
        }
        capability.access = nextAccess
      }
    }
    for (const field of [
      'enabled',
      'description',
      'default_ttl_seconds',
      'max_ttl_seconds',
      'policy_template',
      'risk',
      'params',
    ]) {
      if (body[field] !== undefined) capability[field] = body[field]
    }
    capability.updated_at = new Date().toISOString()
    appendAudit({
      action: 'capability.updated',
      actor_type: 'admin',
      actor_id: 'admin',
      actor_name: 'operator',
      target_type: 'capability',
      target_id: capability.id,
      metadata: { capability_id: capability.id, fields: Object.keys(body) },
    })
    return ok(res, capability)
  }

  if (path === 'agents' && method === 'GET') {
    return ok(res, { items: state.agents, total: state.agents.length })
  }
  if (path === 'agents' && method === 'POST') {
    const body = await readBody(req)
    if (!body.name) return fail(res, 400, 'invalid_request', 'name is required')
    const role = body.role === undefined || body.role === '' ? 'guest' : body.role
    if (!VALID_ROLES.has(role)) {
      return fail(res, 400, 'invalid_request', `invalid role: ${role}`)
    }
    let grants = Array.isArray(body.grants) ? body.grants : []
    if (grants.length === 0) {
      grants = defaultGrantsForRole(role)
    }
    const missing = grants.filter(
      (grant) => !state.capabilities.some((capability) => capability.id === grant),
    )
    if (missing.length > 0) {
      return fail(res, 400, 'invalid_request', `unknown capability grants: ${missing.join(', ')}`)
    }
    const outOfRole = grants.filter((grant) => {
      const capability = state.capabilities.find((item) => item.id === grant)
      return capability && !rolePermitsAccess(role, capability.access)
    })
    if (outOfRole.length > 0) {
      return fail(
        res,
        400,
        'invalid_request',
        `grants outside role ${role}: ${outOfRole.join(', ')}`,
      )
    }
    const now = new Date().toISOString()
    const agent = {
      id: id('agt'),
      name: body.name,
      description: body.description ?? '',
      status: 'active',
      role,
      grants,
      max_ttl_seconds: Number(body.max_ttl_seconds ?? state.settings.max_lease_ttl_seconds),
      max_concurrent_leases: Number(
        body.max_concurrent_leases ?? state.settings.max_concurrent_leases_per_agent,
      ),
      token_prefix: `csg_agt_${rand(2)}`,
      created_at: now,
      updated_at: now,
    }
    state.agents.push(agent)
    appendAudit({
      action: 'agent.created',
      actor_type: 'admin',
      actor_id: 'admin',
      actor_name: 'operator',
      target_type: 'agent',
      target_id: agent.id,
      metadata: { agent_id: agent.id, role, grants },
    })
    const token = `csg_agt_${crypto.randomBytes(32).toString('base64url')}`
    return ok(res, { agent, token }, 201)
  }
  if (segments[0] === 'agents' && segments[1]) {
    const agent = state.agents.find((item) => item.id === segments[1])
    if (!agent) return fail(res, 404, 'not_found', 'agent not found')
    if (segments[2] === 'suspend' && method === 'POST') {
      agent.status = 'suspended'
      agent.updated_at = new Date().toISOString()
      appendAudit({
        action: 'agent.suspended',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        severity: 'warning',
        target_type: 'agent',
        target_id: agent.id,
      })
      return ok(res, agent)
    }
    if (segments[2] === 'activate' && method === 'POST') {
      agent.status = 'active'
      agent.updated_at = new Date().toISOString()
      appendAudit({
        action: 'agent.activated',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        target_type: 'agent',
        target_id: agent.id,
      })
      return ok(res, agent)
    }
    if (segments[2] === 'token' && segments[3] === 'rotate' && method === 'POST') {
      agent.updated_at = new Date().toISOString()
      const token = `csg_agt_${crypto.randomBytes(32).toString('base64url')}`
      appendAudit({
        action: 'agent.token_rotated',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        severity: 'warning',
        target_type: 'agent',
        target_id: agent.id,
      })
      return ok(res, { agent, token })
    }
    if (method === 'PATCH') {
      const body = await readBody(req)
      const previousRole = agent.role
      let nextRole = previousRole
      if (body.role !== undefined) {
        if (!VALID_ROLES.has(body.role)) {
          return fail(res, 400, 'invalid_request', `invalid role: ${body.role}`)
        }
        nextRole = body.role
      }
      let nextGrants = agent.grants
      if (Array.isArray(body.grants)) {
        const missing = body.grants.filter(
          (grant) => !state.capabilities.some((capability) => capability.id === grant),
        )
        if (missing.length > 0) {
          return fail(res, 400, 'invalid_request', `unknown capability grants: ${missing.join(', ')}`)
        }
        nextGrants = body.grants
      } else if (body.role !== undefined && body.role !== previousRole) {
        nextGrants = defaultGrantsForRole(nextRole)
      }
      const outOfRole = nextGrants.filter((grant) => {
        const capability = state.capabilities.find((item) => item.id === grant)
        return capability && !rolePermitsAccess(nextRole, capability.access)
      })
      if (outOfRole.length > 0) {
        return fail(
          res,
          400,
          'invalid_request',
          `grants outside role ${nextRole}: ${outOfRole.join(', ')}`,
        )
      }
      const revokedLeaseIds = []
      if (nextRole !== previousRole) {
        for (const lease of state.leases) {
          if (lease.agent_id !== agent.id) continue
          if (lease.status !== 'pending' && lease.status !== 'active') continue
          const capability = state.capabilities.find((item) => item.id === lease.capability_id)
          if (capability && rolePermitsAccess(nextRole, capability.access)) continue
          lease.status = 'revoked'
          lease.revoke_reason = `role changed to ${nextRole}`
          lease.revoked_at = new Date().toISOString()
          lease.credential_available = false
          revokedLeaseIds.push(lease.id)
          appendAudit({
            action: 'lease.revoked',
            actor_type: 'admin',
            actor_id: 'admin',
            actor_name: 'operator',
            severity: 'warning',
            target_type: 'lease',
            target_id: lease.id,
            metadata: { reason: lease.revoke_reason, agent_id: agent.id },
          })
        }
      }
      for (const field of [
        'name',
        'description',
        'max_ttl_seconds',
        'max_concurrent_leases',
        'status',
      ]) {
        if (body[field] !== undefined) agent[field] = body[field]
      }
      agent.role = nextRole
      agent.grants = nextGrants
      agent.updated_at = new Date().toISOString()
      if (nextRole !== previousRole) {
        appendAudit({
          action: 'agent.role_changed',
          actor_type: 'admin',
          actor_id: 'admin',
          actor_name: 'operator',
          severity: 'warning',
          target_type: 'agent',
          target_id: agent.id,
          metadata: { from: previousRole, to: nextRole, revoked_lease_ids: revokedLeaseIds },
        })
      }
      appendAudit({
        action: 'agent.updated',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        target_type: 'agent',
        target_id: agent.id,
        metadata: { fields: Object.keys(body) },
      })
      return ok(res, agent)
    }
    if (method === 'GET') return ok(res, agent)
  }

  if (path === 'leases' && method === 'GET') {
    let items = [...state.leases].sort(
      (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
    )
    const status = url.searchParams.get('status')
    const agentId = url.searchParams.get('agent_id')
    const capabilityId = url.searchParams.get('capability_id')
    if (status) items = items.filter((lease) => lease.status === status)
    if (agentId) items = items.filter((lease) => lease.agent_id === agentId)
    if (capabilityId) items = items.filter((lease) => lease.capability_id === capabilityId)
    return ok(res, listResult(items, url))
  }
  if (segments[0] === 'leases' && segments[1]) {
    const lease = findLease(segments[1])
    if (!lease) return leaseNotFound(res)
    const action = segments[2]
    if (action === 'approve' && method === 'POST') {
      if (lease.status !== 'pending') return fail(res, 409, 'conflict', 'lease is not pending')
      const agent = state.agents.find((item) => item.id === lease.agent_id)
      const capability = state.capabilities.find((item) => item.id === lease.capability_id)
      if (!agent || agent.status !== 'active') {
        return fail(res, 409, 'conflict', 'agent is not active')
      }
      if (!capability) {
        return fail(res, 409, 'conflict', 'capability no longer exists')
      }
      if (!capability.enabled) {
        return fail(res, 409, 'conflict', 'capability is disabled')
      }
      if (!agent.grants.includes(lease.capability_id)) {
        return fail(res, 409, 'conflict', 'capability is not in agent grants')
      }
      if (!rolePermitsAccess(agent.role, capability.access)) {
        return fail(res, 409, 'conflict', 'agent role does not permit capability access')
      }
      const body = await readBody(req)
      const ttl = Number(body.ttl_seconds) > 0 ? Number(body.ttl_seconds) : lease.effective_ttl_seconds
      const now = new Date().toISOString()
      lease.status = 'active'
      lease.approved_by = 'admin'
      lease.approval_note = body.note ?? ''
      lease.effective_ttl_seconds = ttl
      lease.approved_at = now
      lease.issued_at = now
      lease.expires_at = new Date(Date.now() + ttl * 1000).toISOString()
      lease.credential_available = true
      lease.credential_fingerprint = `LTAI****${rand(2).toUpperCase()}`
      appendAudit({
        action: 'lease.approved',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        target_type: 'lease',
        target_id: lease.id,
        severity: lease.break_glass ? 'critical' : 'info',
        metadata: { ttl_seconds: ttl, note: lease.approval_note },
      })
      appendAudit({
        action: 'lease.credential_issued',
        actor_type: 'system',
        actor_id: 'system',
        actor_name: 'Cloud Safeguard',
        target_type: 'lease',
        target_id: lease.id,
        metadata: { fingerprint: lease.credential_fingerprint, expires_at: lease.expires_at },
      })
      return ok(res, lease)
    }
    if (action === 'deny' && method === 'POST') {
      if (lease.status !== 'pending') return fail(res, 409, 'conflict', 'lease is not pending')
      const body = await readBody(req)
      const reason = String(body.reason ?? '').trim()
      if (reason.length < 1 || reason.length > 500) {
        return fail(res, 400, 'invalid_request', 'reason must be between 1 and 500 characters')
      }
      lease.status = 'denied'
      lease.denied_reason = reason
      appendAudit({
        action: 'lease.denied',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        severity: lease.break_glass ? 'critical' : 'warning',
        target_type: 'lease',
        target_id: lease.id,
        metadata: { reason },
      })
      return ok(res, lease)
    }
    if (action === 'revoke' && method === 'POST') {
      if (lease.status !== 'pending' && lease.status !== 'active') {
        return fail(res, 409, 'conflict', 'lease is not pending or active')
      }
      const body = await readBody(req)
      lease.status = 'revoked'
      lease.revoke_reason = String(body.reason ?? '').trim() || 'revoked by operator'
      lease.revoked_at = new Date().toISOString()
      lease.credential_available = false
      appendAudit({
        action: 'lease.revoked',
        actor_type: 'admin',
        actor_id: 'admin',
        actor_name: 'operator',
        severity: lease.break_glass ? 'critical' : 'warning',
        target_type: 'lease',
        target_id: lease.id,
        metadata: { reason: lease.revoke_reason },
      })
      return ok(res, lease)
    }
    if (method === 'GET') return ok(res, lease)
  }

  if (path === 'audit' && method === 'GET') {
    let items = [...state.audit].reverse()
    const action = url.searchParams.get('action')
    const actorType = url.searchParams.get('actor_type')
    const actorId = url.searchParams.get('actor_id')
    const severity = url.searchParams.get('severity')
    const since = url.searchParams.get('since')
    if (action) items = items.filter((event) => event.action.toLowerCase().includes(action.toLowerCase()))
    if (actorType) items = items.filter((event) => event.actor_type === actorType)
    if (actorId) items = items.filter((event) => event.actor_id === actorId)
    if (severity) items = items.filter((event) => event.severity === severity)
    if (since) {
      const sinceMs = Date.parse(since)
      if (!Number.isNaN(sinceMs)) items = items.filter((event) => Date.parse(event.time) >= sinceMs)
    }
    return ok(res, listResult(items, url))
  }
  if (path === 'audit/verify' && method === 'GET') {
    let previous = '0'.repeat(64)
    for (const event of state.audit) {
      if (event.prev_hash !== previous) {
        return ok(res, {
          ok: false,
          events: event.seq,
          first_invalid_seq: event.seq,
          message: `hash chain broken at seq ${event.seq}`,
        })
      }
      previous = event.hash
    }
    return ok(res, {
      ok: true,
      events: state.audit.length,
      message: `audit chain intact across ${state.audit.length} events`,
    })
  }

  if (path === 'policy' && method === 'GET') return ok(res, state.settings)
  if (path === 'policy' && method === 'PUT') {
    const body = await readBody(req)
    const risks = ['low', 'medium', 'high', 'critical']
    const problems = []
    if (!risks.includes(body.auto_approve_max_risk))
      problems.push(`auto_approve_max_risk: unknown risk tier "${body.auto_approve_max_risk}"`)
    if (!risks.includes(body.require_reason_for_risk))
      problems.push(`require_reason_for_risk: unknown risk tier "${body.require_reason_for_risk}"`)
    if (!(Number(body.auto_approve_max_ttl_seconds) > 0))
      problems.push('auto_approve_max_ttl_seconds must be positive')
    if (Number(body.max_lease_ttl_seconds) < Number(body.auto_approve_max_ttl_seconds))
      problems.push('max_lease_ttl_seconds must be >= auto_approve_max_ttl_seconds')
    if (!(Number(body.pending_timeout_seconds) > 0)) problems.push('pending_timeout_seconds must be positive')
    if (!(Number(body.max_concurrent_leases_per_agent) > 0))
      problems.push('max_concurrent_leases_per_agent must be positive')
    if (!(Number(body.leases_per_minute_per_agent) > 0))
      problems.push('leases_per_minute_per_agent must be positive')
    if (problems.length > 0) {
      return fail(res, 400, 'invalid_request', problems.join('; '))
    }
    const before = { ...state.settings }
    state.settings = {
      auto_approve_max_risk: body.auto_approve_max_risk,
      auto_approve_max_ttl_seconds: Number(body.auto_approve_max_ttl_seconds),
      max_lease_ttl_seconds: Number(body.max_lease_ttl_seconds),
      pending_timeout_seconds: Number(body.pending_timeout_seconds),
      max_concurrent_leases_per_agent: Number(body.max_concurrent_leases_per_agent),
      leases_per_minute_per_agent: Number(body.leases_per_minute_per_agent),
      require_reason_for_risk: body.require_reason_for_risk,
    }
    appendAudit({
      action: 'policy.updated',
      actor_type: 'admin',
      actor_id: 'admin',
      actor_name: 'operator',
      severity: 'warning',
      target_type: 'policy',
      target_id: 'global',
      metadata: { before, after: state.settings },
    })
    return ok(res, state.settings)
  }

  return fail(res, 404, 'not_found', `unknown admin endpoint: ${method} /admin/${path}`)
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`)
  try {
    if (url.pathname === '/healthz') {
      return sentHealth(res)
    }
    if (url.pathname.startsWith('/api/v1/admin/')) {
      const segments = url.pathname
        .slice('/api/v1/admin/'.length)
        .split('/')
        .filter(Boolean)
        .map(decodeURIComponent)
      return await handleAdmin(req, res, url, segments)
    }
    counter += 1
    return fail(res, 404, 'not_found', `unknown endpoint: ${req.method} ${url.pathname}`)
  } catch (error) {
    console.error('[devmock] error:', error)
    return fail(res, 500, 'internal', error instanceof Error ? error.message : 'internal error')
  }
})

function sentHealth(res) {
  return send(res, 200, {
    status: 'ok',
    version: VERSION,
    name: 'Cloud Safeguard',
    time: new Date().toISOString(),
  })
}

server.listen(PORT, HOST, () => {
  console.log(`[devmock] Cloud Safeguard dev API on http://${HOST}:${PORT}`)
  console.log('[devmock] fixtures: 5 capabilities, 1 mock provider, 2 agents, 10 leases, hash-chained audit')
  console.log(`[devmock] admin token: ${ADMIN_TOKEN}`)
  console.log('[devmock] paste the token into the console login screen (it is generated per run).')
})

process.on('SIGINT', () => {
  server.close(() => process.exit(0))
})
process.on('SIGTERM', () => {
  server.close(() => process.exit(0))
})
