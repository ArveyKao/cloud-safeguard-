/**
 * Typed client for the Cloud Safeguard control-plane API.
 *
 * Contract: docs/CONTRACT.md §2–§4.
 *   - base path is same-origin `/api/v1`
 *   - success envelope `{ "data": <payload> }`, list envelope
 *     `{ "data": { "items": [...], "total": N } }`
 *   - error envelope `{ "error": { code, message, details } }`
 *   - bearer token from localStorage key `csg.adminToken`
 *   - 401 clears the token and returns the operator to the login screen
 */
import { clearToken, readToken } from '../auth'
import type {
  Agent,
  AgentWithToken,
  ApproveLeaseInput,
  AuditEvent,
  AuditFilter,
  AuditVerifyResult,
  Capability,
  CreateAgentInput,
  CreateCapabilityInput,
  CreateProviderInput,
  DenyLeaseInput,
  Lease,
  LeaseFilter,
  ListResponse,
  LoginResult,
  Overview,
  PolicySettings,
  Provider,
  ProviderTestResult,
  RevokeLeaseInput,
  RotateProviderCredentialInput,
  UpdateAgentInput,
  UpdateCapabilityInput,
  UpdateProviderInput,
} from './types'

const API_BASE = '/api/v1'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details?: Record<string, unknown>

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }

  /** True when the operator must sign in again. */
  get isAuthError(): boolean {
    return this.status === 401 || this.code === 'unauthorized'
  }

  get isNetworkError(): boolean {
    return this.status === 0
  }
}

type UnauthorizedHandler = () => void
let unauthorizedHandler: UnauthorizedHandler | null = null

/** Register the shell callback that clears auth state on a 401. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function extractError(status: number, body: unknown): ApiError {
  if (isRecord(body) && isRecord(body.error)) {
    const err = body.error
    const code = typeof err.code === 'string' ? err.code : 'internal'
    const message = typeof err.message === 'string' ? err.message : `HTTP ${status}`
    const details = isRecord(err.details) ? err.details : undefined
    return new ApiError(status, code, message, details)
  }
  return new ApiError(status, 'internal', `HTTP ${status}`)
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  signal?: AbortSignal
  /**
   * `auth: false` for the login call which validates a candidate token and
   * must not clear an existing session on failure.
   */
  auth?: boolean
  /** Called instead of the global unauthorized handler on 401. */
  onUnauthorized?: 'global' | 'ignore'
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, signal, onUnauthorized = 'global' } = options
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const token = readToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: 'same-origin',
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'network_error', 'Cannot reach the Cloud Safeguard control plane.')
  }

  const text = await response.text()
  let parsed: unknown = null
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      if (!response.ok) throw new ApiError(response.status, 'internal', `HTTP ${response.status}`)
      throw new ApiError(response.status, 'internal', 'The server returned a non-JSON response.')
    }
  }

  if (!response.ok) {
    const error = extractError(response.status, parsed)
    if (error.isAuthError && onUnauthorized === 'global') {
      clearToken()
      unauthorizedHandler?.()
    }
    throw error
  }

  // Notify the shell that a successful sync happened (topbar "last updated").
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('csg:api-ok', { detail: { at: Date.now() } }))
  }

  if (isRecord(parsed) && 'data' in parsed) {
    return parsed.data as T
  }
  return parsed as T
}

function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    search.set(key, String(value))
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

/* ------------------------------------------------------------------ */
/* Auth                                                               */
/* ------------------------------------------------------------------ */

export function adminLogin(): Promise<LoginResult> {
  return request<LoginResult>('/admin/login', { method: 'POST', onUnauthorized: 'ignore' })
}

/* ------------------------------------------------------------------ */
/* Overview                                                           */
/* ------------------------------------------------------------------ */

export function fetchOverview(signal?: AbortSignal): Promise<Overview> {
  return request<Overview>('/admin/overview', { signal })
}

/* ------------------------------------------------------------------ */
/* Providers                                                          */
/* ------------------------------------------------------------------ */

export function listProviders(signal?: AbortSignal): Promise<ListResponse<Provider>> {
  return request<ListResponse<Provider>>('/admin/providers', { signal })
}

export function createProvider(input: CreateProviderInput): Promise<Provider> {
  return request<Provider>('/admin/providers', { method: 'POST', body: input })
}

export function updateProvider(id: string, input: UpdateProviderInput): Promise<Provider> {
  return request<Provider>(`/admin/providers/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: input,
  })
}

export function rotateProviderCredential(
  id: string,
  input: RotateProviderCredentialInput,
): Promise<Provider> {
  return request<Provider>(`/admin/providers/${encodeURIComponent(id)}/rotate`, {
    method: 'POST',
    body: input,
  })
}

export function testProvider(id: string): Promise<ProviderTestResult> {
  return request<ProviderTestResult>(`/admin/providers/${encodeURIComponent(id)}/test`, {
    method: 'POST',
  })
}

/* ------------------------------------------------------------------ */
/* Capabilities                                                       */
/* ------------------------------------------------------------------ */

export function listCapabilities(signal?: AbortSignal): Promise<ListResponse<Capability>> {
  return request<ListResponse<Capability>>('/admin/capabilities', { signal })
}

export function createCapability(input: CreateCapabilityInput): Promise<Capability> {
  return request<Capability>('/admin/capabilities', { method: 'POST', body: input })
}

export function updateCapability(id: string, input: UpdateCapabilityInput): Promise<Capability> {
  return request<Capability>(`/admin/capabilities/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: input,
  })
}

/* ------------------------------------------------------------------ */
/* Agents                                                             */
/* ------------------------------------------------------------------ */

export function listAgents(signal?: AbortSignal): Promise<ListResponse<Agent>> {
  return request<ListResponse<Agent>>('/admin/agents', { signal })
}

export function createAgent(input: CreateAgentInput): Promise<AgentWithToken> {
  return request<AgentWithToken>('/admin/agents', { method: 'POST', body: input })
}

export function getAgent(id: string, signal?: AbortSignal): Promise<Agent> {
  return request<Agent>(`/admin/agents/${encodeURIComponent(id)}`, { signal })
}

export function updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
  return request<Agent>(`/admin/agents/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: input,
  })
}

export function suspendAgent(id: string): Promise<Agent> {
  return request<Agent>(`/admin/agents/${encodeURIComponent(id)}/suspend`, { method: 'POST' })
}

export function activateAgent(id: string): Promise<Agent> {
  return request<Agent>(`/admin/agents/${encodeURIComponent(id)}/activate`, { method: 'POST' })
}

export function rotateAgentToken(id: string): Promise<AgentWithToken> {
  return request<AgentWithToken>(`/admin/agents/${encodeURIComponent(id)}/token/rotate`, {
    method: 'POST',
  })
}

/* ------------------------------------------------------------------ */
/* Leases                                                             */
/* ------------------------------------------------------------------ */

export function listLeases(
  filter: LeaseFilter = {},
  signal?: AbortSignal,
): Promise<ListResponse<Lease>> {
  return request<ListResponse<Lease>>(
    `/admin/leases${query({
      status: filter.status,
      agent_id: filter.agent_id,
      capability_id: filter.capability_id,
      limit: filter.limit,
      offset: filter.offset,
    })}`,
    { signal },
  )
}

export function getLease(id: string, signal?: AbortSignal): Promise<Lease> {
  return request<Lease>(`/admin/leases/${encodeURIComponent(id)}`, { signal })
}

export function approveLease(id: string, input: ApproveLeaseInput): Promise<Lease> {
  return request<Lease>(`/admin/leases/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    body: input,
  })
}

export function denyLease(id: string, input: DenyLeaseInput): Promise<Lease> {
  return request<Lease>(`/admin/leases/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    body: input,
  })
}

export function revokeLease(id: string, input: RevokeLeaseInput): Promise<Lease> {
  return request<Lease>(`/admin/leases/${encodeURIComponent(id)}/revoke`, {
    method: 'POST',
    body: input,
  })
}

/* ------------------------------------------------------------------ */
/* Audit                                                              */
/* ------------------------------------------------------------------ */

export function listAudit(
  filter: AuditFilter = {},
  signal?: AbortSignal,
): Promise<ListResponse<AuditEvent>> {
  return request<ListResponse<AuditEvent>>(
    `/admin/audit${query({
      action: filter.action,
      actor_type: filter.actor_type,
      actor_id: filter.actor_id,
      severity: filter.severity,
      since: filter.since,
      limit: filter.limit,
      offset: filter.offset,
    })}`,
    { signal },
  )
}

export function verifyAuditChain(): Promise<AuditVerifyResult> {
  return request<AuditVerifyResult>('/admin/audit/verify')
}

/* ------------------------------------------------------------------ */
/* Policy                                                             */
/* ------------------------------------------------------------------ */

export function fetchPolicy(signal?: AbortSignal): Promise<PolicySettings> {
  return request<PolicySettings>('/admin/policy', { signal })
}

export function updatePolicy(settings: PolicySettings): Promise<PolicySettings> {
  return request<PolicySettings>('/admin/policy', { method: 'PUT', body: settings })
}

/** Health probe is unauthenticated and outside the API version prefix. */
export async function fetchHealth(signal?: AbortSignal): Promise<{ status: string }> {
  const response = await fetch('/healthz', { signal })
  if (!response.ok) throw new ApiError(response.status, 'internal', 'health check failed')
  return (await response.json()) as { status: string }
}
