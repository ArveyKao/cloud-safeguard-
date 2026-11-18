/** Types of the person-facing API (CONTRACT §17). */

export type Role = 'guest' | 'member' | 'administrator'
export type ApprovalMode = 'read' | 'write' | 'full'
export type LeaseStatus = 'pending' | 'active' | 'denied' | 'expired' | 'revoked' | 'failed'

export interface SetupIssue {
  by_id: string
  by_name: string
  kind: 'created' | 'reset' | 'recovered' | 'bootstrap'
  at: string
}

export interface Person {
  id: string
  username: string
  display_name: string
  status: 'pending' | 'active' | 'suspended'
  supervisor: boolean
  setup_issued?: SetupIssue
  last_login_at?: string
  created_at: string
}

export interface RoleBinding {
  person_id: string
  provider_id: string
  role: Role
  created_at: string
}

export interface SessionInfo {
  person: Person
  bindings: RoleBinding[]
  csrf_token: string
  expires_at: string
}

export interface SetupBeginResult {
  username: string
  totp_secret: string
  otpauth_url: string
}

export interface PersonWithSetupCode {
  person: Person
  setup_code: string
  setup_expires_at: string
}

export interface PersonAccount {
  provider_id: string
  cloud_account_id: string
  name: string
  provider_type: string
  status: 'active' | 'disabled'
  role: Role
  highest_permission: string
  /** The person's mode here as it applies now (read once expired). */
  approval_mode: ApprovalMode
  approval_mode_expires_at?: string
  automatic_up_to: string
}

export interface Provider {
  id: string
  name: string
  type: string
  mode: 'sts' | 'mock'
  region: string
  role_arn?: string
  cloud_account_id?: string
  access_key_id_masked: string
  status: 'active' | 'disabled'
  last_tested_at?: string
  last_test_ok?: boolean
  created_at: string
}

export interface Agent {
  id: string
  name: string
  description: string
  status: 'active' | 'suspended' | 'revoked'
  owner_id?: string
  token_prefix: string
  last_seen_at?: string
  created_at: string
}

export interface AccessRequest {
  id: string
  agent_id: string
  agent_name: string
  cloud_account_id: string
  cloud_account_name: string
  resource: string
  permission: string
  resource_name?: string
  ttl_seconds: number
  reason: string
  status: LeaseStatus
  denied_reason?: string
  revoke_reason?: string
  approved_by?: string
  created_at: string
  issued_at?: string
  expires_at?: string
  /** How long the agent may keep refreshing the key (CONTRACT §17.12). */
  max_lifetime_seconds: number
  refresh_until?: string
  refresh_count: number
}

export interface CLISignIn {
  user_code: string
  client_name: string
  status: string
  remote_addr: string
  created_at: string
  expires_at: string
}

export interface MCPConnection {
  client_name: string
  redirect_uri: string
  redirect_host: string
  local: boolean
  suggested_agent_name: string
  remote_addr: string
  created_at: string
  expires_at: string
}

export interface CLISession {
  id: string
  client_name: string
  remote_addr: string
  created_at: string
  last_seen_at: string
  expires_at: string
  current: boolean
}

export interface AgentSignIn {
  user_code: string
  agent_name: string
  description: string
  status: string
  remote_addr: string
  created_at: string
  expires_at: string
}

export interface AuditEvent {
  seq: number
  id: string
  time: string
  actor_type: string
  actor_id: string
  actor_name: string
  action: string
  status: string
  severity: 'info' | 'warning' | 'critical'
  target_type: string
  target_id: string
  metadata?: Record<string, unknown>
}

export interface PolicySettings {
  max_lease_ttl_seconds: number
  pending_timeout_seconds: number
  max_concurrent_leases_per_agent: number
  leases_per_minute_per_agent: number
  max_refresh_lifetime_seconds: number
}

export interface List<T> {
  items: T[]
  total: number
}
