/**
 * Wire types for the Cloud Safeguard control-plane API.
 *
 * Source of truth: internal/model/model.go (JSON tags are the frozen wire
 * contract, docs/CONTRACT.md §3–§5). Keep this file a 1:1 mirror — do not
 * invent fields here; extend model.go through the Lead instead.
 */

export type RiskTier = 'low' | 'medium' | 'high' | 'critical'
export type ProviderType = 'aliyun'
export type ProviderMode = 'sts' | 'mock'
export type ProviderStatus = 'active' | 'disabled'
export type AgentStatus = 'active' | 'suspended' | 'revoked'
export type LeaseStatus = 'pending' | 'active' | 'denied' | 'expired' | 'revoked' | 'failed'
export type DecisionOutcome = 'auto_approve' | 'require_approval' | 'deny'
export type RuleOutcome = 'allow' | 'require_approval' | 'deny'
export type Severity = 'info' | 'warning' | 'critical'
export type ActorType = 'agent' | 'admin' | 'system'

export interface Provider {
  id: string
  name: string
  type: ProviderType
  mode: ProviderMode
  region: string
  role_arn?: string
  access_key_id_masked: string
  status: ProviderStatus
  last_tested_at?: string
  last_test_ok?: boolean
  created_at: string
  updated_at: string
}

export interface CreateProviderInput {
  name: string
  type: ProviderType
  mode: ProviderMode
  region: string
  role_arn?: string
  access_key_id: string
  access_key_secret: string
}

export interface UpdateProviderInput {
  name?: string
  region?: string
  role_arn?: string
  status?: ProviderStatus
}

export interface RotateProviderCredentialInput {
  access_key_id: string
  access_key_secret: string
}

export interface ProviderTestResult {
  ok: boolean
  message: string
  tested_at: string
}

export interface CapabilityParam {
  name: string
  description: string
  required: boolean
  pattern?: string
}

export interface Capability {
  id: string
  name: string
  description: string
  provider_type: ProviderType
  risk: RiskTier
  policy_template: string
  params: CapabilityParam[] | null
  default_ttl_seconds: number
  max_ttl_seconds: number
  enabled: boolean
  builtin: boolean
  created_at: string
  updated_at: string
}

export interface CreateCapabilityInput {
  id?: string
  name: string
  description: string
  provider_type: ProviderType
  risk: RiskTier
  policy_template: string
  params: CapabilityParam[]
  default_ttl_seconds: number
  max_ttl_seconds: number
}

export interface UpdateCapabilityInput {
  enabled?: boolean
  description?: string
  default_ttl_seconds?: number
  max_ttl_seconds?: number
  policy_template?: string
  risk?: RiskTier
  params?: CapabilityParam[]
}

export interface Agent {
  id: string
  name: string
  description: string
  status: AgentStatus
  grants: string[]
  max_ttl_seconds: number
  max_concurrent_leases: number
  token_prefix: string
  last_seen_at?: string
  created_at: string
  updated_at: string
}

export interface CreateAgentInput {
  name: string
  description: string
  grants: string[]
  max_ttl_seconds: number
  max_concurrent_leases: number
}

export interface UpdateAgentInput {
  name?: string
  description?: string
  grants?: string[]
  max_ttl_seconds?: number
  max_concurrent_leases?: number
  status?: AgentStatus
}

/** Returned exactly once on agent create / token rotation. Never persisted. */
export interface AgentWithToken {
  agent: Agent
  token: string
}

export interface DecisionReason {
  rule: string
  outcome: RuleOutcome
  detail: string
}

export interface PolicyDecision {
  outcome: DecisionOutcome
  effective_ttl_seconds: number
  reasons: DecisionReason[] | null
}

export interface Lease {
  id: string
  agent_id: string
  agent_name: string
  capability_id: string
  capability_name: string
  provider_id: string
  provider_name: string
  provider_mode: ProviderMode
  risk: RiskTier
  params?: Record<string, string>
  reason: string
  requested_ttl_seconds: number
  effective_ttl_seconds: number
  status: LeaseStatus
  decision: PolicyDecision
  break_glass: boolean
  approved_by?: string
  approval_note?: string
  denied_reason?: string
  revoke_reason?: string
  failure_reason?: string
  session_name: string
  credential_available: boolean
  credential_fingerprint?: string
  created_at: string
  approved_at?: string
  issued_at?: string
  expires_at?: string
  revoked_at?: string
}

export interface ApproveLeaseInput {
  ttl_seconds?: number
  note?: string
}

export interface DenyLeaseInput {
  reason: string
}

export interface RevokeLeaseInput {
  reason: string
}

export interface AuditEvent {
  seq: number
  id: string
  time: string
  actor_type: ActorType | string
  actor_id: string
  actor_name: string
  action: string
  status: 'ok' | 'denied' | 'failed' | string
  severity: Severity | string
  target_type: string
  target_id: string
  metadata?: Record<string, unknown>
  prev_hash: string
  hash: string
}

export interface AuditVerifyResult {
  ok: boolean
  events: number
  first_invalid_seq?: number
  message: string
}

export interface PolicySettings {
  auto_approve_max_risk: RiskTier
  auto_approve_max_ttl_seconds: number
  max_lease_ttl_seconds: number
  pending_timeout_seconds: number
  max_concurrent_leases_per_agent: number
  leases_per_minute_per_agent: number
  require_reason_for_risk: RiskTier
}

export interface OverviewCounts {
  agents: number
  active_agents: number
  capabilities: number
  providers: number
  active_leases: number
  pending_leases: number
  events_24h: number
  denied_leases_24h: number
}

export interface RiskBreakdown {
  low: number
  medium: number
  high: number
  critical: number
}

export interface VaultStatus {
  configured: boolean
  key_fingerprint: string
  secrets_stored: number
}

export interface Overview {
  counts: OverviewCounts
  risk_breakdown: RiskBreakdown
  policy: PolicySettings
  vault: VaultStatus
  pending_leases: Lease[] | null
  active_leases: Lease[] | null
  recent_events: AuditEvent[] | null
  providers: Provider[] | null
  version: string
  uptime_seconds: number
  server_time: string
}

export interface LoginResult {
  ok: boolean
  role: string
  version: string
}

export interface Health {
  status: string
  version: string
  name: string
  time: string
}

export interface ListResponse<T> {
  items: T[]
  total: number
}

export interface ErrorDetail {
  code: string
  message: string
  details?: Record<string, unknown>
}

/** Filter sets for the collection endpoints (CONTRACT §4 query params). */
export interface LeaseFilter {
  status?: LeaseStatus | ''
  agent_id?: string
  capability_id?: string
  limit?: number
  offset?: number
}

export interface AuditFilter {
  action?: string
  actor_type?: string
  actor_id?: string
  severity?: string
  since?: string
  limit?: number
  offset?: number
}

export const RISK_ORDER: RiskTier[] = ['low', 'medium', 'high', 'critical']

export const RISK_RANK: Record<RiskTier, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export const LEASE_STATUSES: LeaseStatus[] = [
  'pending',
  'active',
  'denied',
  'expired',
  'revoked',
  'failed',
]

export const TERMINAL_LEASE_STATUSES: LeaseStatus[] = ['denied', 'expired', 'revoked', 'failed']
