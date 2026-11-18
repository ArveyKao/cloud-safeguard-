/**
 * Client for the person-facing API. The session is an HttpOnly cookie; the
 * CSRF token from /auth/me is kept in memory only and sent on every change.
 * No token is ever stored in localStorage.
 */
import type { AccessRequest, Agent, AgentSignIn, ApprovalMode, AuditEvent, List, Person, PersonAccount, PersonWithSetupCode, PolicySettings, Provider, Role, RoleBinding, SessionInfo, SetupBeginResult, CLISignIn, CLISession, MCPConnection } from './types'

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message)
  }
}

let csrf = ''
let onSignedOut: (() => void) | null = null

export function setCsrf(token: string) { csrf = token }
export function setSignedOutHandler(fn: (() => void) | null) { onSignedOut = fn }

export interface TestResult { ok: boolean; message: string; warning?: string; tested_at: string }

async function call<T>(method: string, path: string, body?: unknown, retried = false): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf
  let res: Response
  try {
    res = await fetch('/api/v1' + path, {
      method, headers, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach Cloud Safeguard. Check that the server is running.')
  }
  const text = await res.text()
  let json: unknown = null
  try { json = text ? JSON.parse(text) : null } catch { /* not JSON */ }
  if (!res.ok) {
    const err = (json as { error?: { code?: string; message?: string } } | null)?.error
    if (res.status === 401 && !path.startsWith('/auth/')) onSignedOut?.()
    // Signing in again in another tab replaces the session and its CSRF
    // token; fetch the current one once and repeat the change.
    if (res.status === 403 && method !== 'GET' && !retried && /CSRF/i.test(err?.message ?? '')) {
      try {
        const me = await call<SessionInfo>('GET', '/auth/me')
        csrf = me.csrf_token
      } catch {
        onSignedOut?.()
        throw new ApiError(401, 'unauthorized', 'Please sign in again.')
      }
      return call<T>(method, path, body, true)
    }
    throw new ApiError(res.status, err?.code ?? 'error', err?.message ?? `Request failed (${res.status})`)
  }
  return (json as { data: T }).data
}

const enc = encodeURIComponent

export const api = {
  // session
  me: () => call<SessionInfo>('GET', '/auth/me'),
  login: (username: string, password: string, totp_code: string) =>
    call<SessionInfo>('POST', '/auth/login', { username, password, totp_code }),
  logout: () => call<{ ok: boolean }>('POST', '/auth/logout', {}),
  setupBegin: (setup_code: string, password: string) =>
    call<SetupBeginResult>('POST', '/auth/setup/begin', { setup_code, password }),
  setupFinish: (setup_code: string, totp_code: string) =>
    call<SessionInfo>('POST', '/auth/setup/finish', { setup_code, totp_code }),

  // everyone
  myRequests: (status?: string) =>
    call<List<AccessRequest>>('GET', '/me/requests' + (status ? `?status=${enc(status)}` : '')),
  approveRequest: (id: string) => call<AccessRequest>('POST', `/me/requests/${enc(id)}/approve`, {}),
  denyRequest: (id: string, reason: string) => call<AccessRequest>('POST', `/me/requests/${enc(id)}/deny`, { reason }),
  revokeRequest: (id: string) => call<AccessRequest>('POST', `/me/requests/${enc(id)}/revoke`, {}),
  myAgents: () => call<List<Agent>>('GET', '/me/agents'),
  revokeAgent: (id: string) => call<Agent>('POST', `/me/agents/${enc(id)}/revoke`, {}),
  myAccounts: () => call<List<PersonAccount>>('GET', '/me/accounts'),
  signIn: (code: string) => call<AgentSignIn>('GET', `/me/signins/${enc(code)}`),
  approveSignIn: (code: string) => call<AgentSignIn>('POST', `/me/signins/${enc(code)}/approve`, {}),
  denySignIn: (code: string) => call<AgentSignIn>('POST', `/me/signins/${enc(code)}/deny`, {}),
  mcpConnection: (id: string) => call<MCPConnection>('GET', `/me/mcp-connections/${enc(id)}`),
  approveMCPConnection: (id: string, agentName: string) => call<{ redirect_url: string }>('POST', `/me/mcp-connections/${enc(id)}/approve`, { agent_name: agentName }),
  denyMCPConnection: (id: string) => call<{ redirect_url: string }>('POST', `/me/mcp-connections/${enc(id)}/deny`, {}),
  cliSignIn: (code: string) => call<CLISignIn>('GET', `/me/cli-signins/${enc(code)}`),
  approveCLISignIn: (code: string) => call<{ status: string }>('POST', `/me/cli-signins/${enc(code)}/approve`, {}),
  denyCLISignIn: (code: string) => call<{ status: string }>('POST', `/me/cli-signins/${enc(code)}/deny`, {}),
  cancelCLISignIn: (code: string) => call<{ status: string }>('POST', `/me/cli-signins/${enc(code)}/cancel`, {}),
  cliSessions: () => call<List<CLISession>>('GET', '/me/cli-sessions'),
  revokeCLISession: (id: string) => call<{ ok: boolean }>('POST', `/me/cli-sessions/${enc(id)}/revoke`, {}),
  setMode: (providerId: string, mode: ApprovalMode, expires_in_seconds: number) =>
    call<PersonAccount>('PUT', `/me/accounts/${enc(providerId)}/mode`, { mode, expires_in_seconds }),

  // supervisors
  people: () => call<List<Person>>('GET', '/supervisor/people'),
  createPerson: (username: string, display_name: string, supervisor: boolean) =>
    call<PersonWithSetupCode>('POST', '/supervisor/people', { username, display_name, supervisor }),
  updatePerson: (id: string, patch: { status?: string; supervisor?: boolean; display_name?: string }) =>
    call<Person>('PATCH', `/supervisor/people/${enc(id)}`, patch),
  resetPerson: (id: string) => call<PersonWithSetupCode>('POST', `/supervisor/people/${enc(id)}/reset`, {}),
  bindings: (providerId: string) => call<List<RoleBinding>>('GET', `/supervisor/bindings?provider_id=${enc(providerId)}`),
  putBinding: (providerId: string, personId: string, role: Role) =>
    call<RoleBinding>('PUT', `/supervisor/accounts/${enc(providerId)}/people/${enc(personId)}`, { role }),
  deleteBinding: (providerId: string, personId: string) =>
    call<{ ok: boolean }>('DELETE', `/supervisor/accounts/${enc(providerId)}/people/${enc(personId)}`),
  accounts: () => call<List<Provider>>('GET', '/supervisor/accounts'),
  createAccount: (input: Record<string, string>) => call<Provider>('POST', '/supervisor/accounts', input),
  updateAccount: (id: string, patch: Record<string, string>) => call<Provider>('PATCH', `/supervisor/accounts/${enc(id)}`, patch),
  testAccount: (id: string) => call<TestResult>('POST', `/supervisor/accounts/${enc(id)}/test`, {}),
  rotateAccount: (id: string, access_key_id: string, access_key_secret: string) =>
    call<Provider>('POST', `/supervisor/accounts/${enc(id)}/rotate`, { access_key_id, access_key_secret }),
  settings: () => call<PolicySettings>('GET', '/supervisor/settings'),
  putSettings: (s: PolicySettings) => call<PolicySettings>('PUT', '/supervisor/settings', s),
  audit: (limit = 100) => call<List<AuditEvent>>('GET', `/supervisor/audit?limit=${limit}`),
  verifyAudit: () => call<{ ok: boolean; events: number; message: string }>('GET', '/supervisor/audit/verify'),
}
