// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { api, setCsrf } from './api'
import { ToastProvider } from './ui'
import { InboxPage } from './pages/Inbox'
import { PeoplePage } from './pages/People'
import { AccountsPage } from './pages/Accounts'
import { AddAccountPage } from './pages/AddAccount'
import { SignInApprovalPage } from './pages/SignInApproval'
import { rememberSignIn, takeSignIn } from './App'
import { CLISignInApprovalPage } from './pages/CLISignInApproval'
import { MCPConnectApprovalPage, redirect } from './pages/MCPConnectApproval'
import type { Person } from './types'

// A fake API: routes map "METHOD /path" to a payload or a function.
type Route = unknown | ((body: unknown) => { status: number; body: unknown })
let routes: Record<string, Route> = {}
let calls: { method: string; path: string; headers: Record<string, string>; body: unknown }[] = []

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

beforeEach(() => {
  routes = {}
  calls = []
  setCsrf('csrf-1')
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const path = String(url).replace(/^\/api\/v1/, '')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, path, headers: (init.headers ?? {}) as Record<string, string>, body })
    const route = routes[`${method} ${path.split('?')[0]}`]
    if (route === undefined) return respond(404, { error: { code: 'not_found', message: 'no route' } })
    if (typeof route === 'function') {
      const r = (route as (b: unknown) => { status: number; body: unknown })(body)
      return respond(r.status, r.body)
    }
    return respond(200, { data: route })
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  sessionStorage.clear()
})

const wrap = (node: ReactNode) => render(<ToastProvider>{node}</ToastProvider>)
const changes = () => calls.filter((c) => c.method !== 'GET')

const person: Person = {
  id: 'per_1', username: 'mei', display_name: 'Mei', status: 'active', supervisor: true,
  created_at: '2026-11-01T00:00:00Z',
}

describe('server text is shown as text', () => {
  it('does not interpret HTML in agent names or reasons', async () => {
    const evil = '<img src=x onerror="window.pwned=1">'
    routes['GET /me/requests'] = {
      items: [{ id: 'lea_1', agent_name: evil, cloud_account_id: '1', cloud_account_name: evil, resource: 'ecs',
        permission: 'write', ttl_seconds: 600, reason: evil, status: 'pending', created_at: new Date().toISOString() }],
      total: 1,
    }
    const { container } = wrap(<InboxPage person={{ ...person, supervisor: false }} onChange={() => {}} />)
    await screen.findByText(`“${evil}”`)
    expect(container.querySelectorAll('img').length).toBe(0)
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined()
  })
})

describe('CSRF token', () => {
  it('is sent on every change and never on a read', async () => {
    routes['POST /me/requests/lea_1/approve'] = { id: 'lea_1' }
    routes['GET /me/agents'] = { items: [], total: 0 }
    await api.approveRequest('lea_1')
    await api.myAgents()
    expect(calls[0].headers['X-CSRF-Token']).toBe('csrf-1')
    expect(calls[1].headers['X-CSRF-Token']).toBeUndefined()
  })

  it('is refreshed once when another tab replaced the session', async () => {
    let first = true
    routes['POST /me/requests/lea_1/approve'] = () => {
      if (first) { first = false; return { status: 403, body: { error: { code: 'forbidden', message: 'missing or invalid CSRF token' } } } }
      return { status: 200, body: { data: { id: 'lea_1' } } }
    }
    routes['GET /auth/me'] = { person, bindings: [], csrf_token: 'csrf-2', expires_at: '' }
    await api.approveRequest('lea_1')
    const posts = changes()
    expect(posts.length).toBe(2)
    expect(posts[1].headers['X-CSRF-Token']).toBe('csrf-2')
  })
})

describe('authority changes ask first', () => {
  it('does not suspend, reset or change a supervisor before confirmation', async () => {
    routes['GET /supervisor/people'] = { items: [person, { ...person, id: 'per_2', username: 'jun', display_name: 'Jun', supervisor: false }], total: 2 }
    routes['PATCH /supervisor/people/per_2'] = { ...person, id: 'per_2' }
    wrap(<PeoplePage me={person} />)
    await screen.findByText('Jun')
    for (const label of ['Suspend', 'Reset', 'Make supervisor']) {
      fireEvent.click(screen.getAllByRole('button', { name: label })[0])
      expect(changes().length).toBe(0)
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    }
    fireEvent.click(screen.getByRole('button', { name: 'Suspend' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Suspend')!)
    await waitFor(() => expect(changes().map((c) => c.method + ' ' + c.path)).toEqual(['PATCH /supervisor/people/per_2']))
  })
})

describe('approval mode', () => {
  const account = {
    provider_id: 'prv_1', cloud_account_id: '1234567890123456', name: 'demo', provider_type: 'aliyun', status: 'active',
    role: 'administrator', highest_permission: 'full', approval_mode: 'read', automatic_up_to: 'read',
  }

  it('keeps the end of a temporary mode when saved unchanged', async () => {
    const end = new Date(Date.now() + 3600_000).toISOString()
    routes['GET /me/accounts'] = { items: [{ ...account, approval_mode: 'write', approval_mode_expires_at: end }], total: 1 }
    routes['PUT /me/accounts/prv_1/mode'] = (b: unknown) => ({ status: 200, body: { data: { ...account, ...(b as object) } } })
    wrap(<AccountsPage person={{ ...person, supervisor: false }} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(changes().length).toBe(1))
    expect(changes()[0].path).toBe('/me/accounts/prv_1/mode')
    const sent = changes()[0].body as { mode: string; expires_in_seconds: number }
    expect(sent.mode).toBe('write')
    expect(sent.expires_in_seconds).toBeGreaterThan(3500)
    expect(sent.expires_in_seconds).toBeLessThanOrEqual(3600)
  })

  it('asks before keeping a temporary mode longer', async () => {
    const end = new Date(Date.now() + 3600_000).toISOString()
    routes['GET /me/accounts'] = { items: [{ ...account, approval_mode: 'write', approval_mode_expires_at: end }], total: 1 }
    routes['PUT /me/accounts/prv_1/mode'] = account
    wrap(<AccountsPage person={{ ...person, supervisor: false }} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change' }))
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '86400' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(changes().length).toBe(0)
    fireEvent.click(await screen.findByRole('button', { name: 'Switch' }))
    await waitFor(() => expect(changes().length).toBe(1))
    expect((changes()[0].body as { expires_in_seconds: number }).expires_in_seconds).toBe(86400)
  })

  it('asks before raising the mode, on that account only', async () => {
    routes['GET /me/accounts'] = { items: [account], total: 1 }
    routes['PUT /me/accounts/prv_1/mode'] = account
    wrap(<AccountsPage person={{ ...person, supervisor: false }} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Change' }))
    fireEvent.click(screen.getByRole('radio', { name: 'Full mode' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(changes().length).toBe(0)
    await screen.findByText(/all your agents on demo/)
    fireEvent.click(screen.getByRole('button', { name: 'Switch' }))
    await waitFor(() => expect(changes().map((c) => c.method + ' ' + c.path)).toEqual(['PUT /me/accounts/prv_1/mode']))
    expect((changes()[0].body as { mode: string }).mode).toBe('full')
  })
})

describe('add an AWS account', () => {
  it('shows the IAM setup and creates an aws account with its role ARN', async () => {
    routes['POST /supervisor/accounts'] = { id: 'prv_9', name: 'prod', type: 'aws', mode: 'sts', region: 'eu-west-1', access_key_id_masked: 'AKIA****', status: 'active', created_at: '' }
    routes['POST /supervisor/accounts/prv_9/test'] = { ok: true, message: 'ok', warning: 'the role allows IAM', tested_at: '' }
    wrap(<AddAccountPage />)
    fireEvent.click(screen.getByRole('radio', { name: 'AWS' }))
    fireEvent.change(screen.getByLabelText(/^Account ID/), { target: { value: '123456789012' } })
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'prod' } })
    fireEvent.change(screen.getByLabelText(/^Region/), { target: { value: 'eu-west-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(screen.getAllByText(/arn:aws:iam::123456789012:role\/cloud-safeguard/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/acs:ram::/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'I created them' }))
    fireEvent.change(screen.getByLabelText(/^Access key ID/), { target: { value: 'AKIAEXAMPLE' } })
    fireEvent.change(screen.getByLabelText(/^Secret access key/), { target: { value: 'placeholder' } })
    fireEvent.click(screen.getByRole('button', { name: 'Connect and test' }))
    await screen.findByText('the role allows IAM')
    const sent = changes()[0].body as Record<string, string>
    expect(sent.type).toBe('aws')
    expect(sent.role_arn).toBe('arn:aws:iam::123456789012:role/cloud-safeguard')
    expect(sent.region).toBe('eu-west-1')
  })
})

describe('agent sign-in', () => {
  it('needs the person to confirm the code before Approve works', async () => {
    routes['GET /me/signins/ABC-DEFG'] = { user_code: 'ABC-DEFG', agent_name: 'laptop', description: '', status: 'pending',
      remote_addr: '10.0.0.5', created_at: '', expires_at: new Date(Date.now() + 600_000).toISOString() }
    routes['GET /me/accounts'] = { items: [], total: 0 }
    routes['GET /me/agents'] = { items: [{ id: 'agt_1', name: 'laptop', status: 'active', description: '', token_prefix: '', created_at: '' }], total: 1 }
    routes['POST /me/signins/ABC-DEFG/approve'] = { status: 'approved' }
    wrap(<SignInApprovalPage code="ABC-DEFG" />)
    const approve = await screen.findByRole('button', { name: 'Approve sign-in' })
    await screen.findByText(/Approving replaces it/)
    expect((approve as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(approve)
    expect(changes().length).toBe(0)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(approve)
    await waitFor(() => expect(changes().map((c) => c.path)).toEqual(['/me/signins/ABC-DEFG/approve']))
  })

  it('approves a command-line sign-in only after the code is confirmed', async () => {
    routes['GET /me/cli-signins/CLI-CODE'] = { user_code: 'CLI-CODE', client_name: 'laptop', status: 'pending',
      remote_addr: '10.0.0.7', created_at: '', expires_at: new Date(Date.now() + 600_000).toISOString() }
    routes['POST /me/cli-signins/CLI-CODE/approve'] = { status: 'approved' }
    const me = { id: 'per_1', username: 'mei', display_name: '', status: 'active', supervisor: true } as unknown as Person
    wrap(<CLISignInApprovalPage code="CLI-CODE" person={me} />)
    const approve = await screen.findByRole('button', { name: 'Approve sign-in' })
    await screen.findByText(/Approving requests and sign-ins is never possible from it/)
    expect((approve as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(approve)
    expect(changes().length).toBe(0)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(approve)
    await waitFor(() => expect(changes().map((c) => c.path)).toEqual(['/me/cli-signins/CLI-CODE/approve']))
    await screen.findByText('csg is signed in as you')
    // Approved by mistake: it can be withdrawn before csg picks it up.
    routes['POST /me/cli-signins/CLI-CODE/cancel'] = { status: 'denied' }
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw approval' }))
    await screen.findByText('Approval withdrawn')
    expect(changes().map((c) => c.path)).toEqual(['/me/cli-signins/CLI-CODE/approve', '/me/cli-signins/CLI-CODE/cancel'])
  })

  it('offers to withdraw an approval when the page is opened again', async () => {
    routes['GET /me/cli-signins/CLI-CODE'] = { user_code: 'CLI-CODE', client_name: 'laptop', status: 'approved',
      remote_addr: '10.0.0.7', created_at: '', expires_at: new Date(Date.now() + 600_000).toISOString() }
    routes['POST /me/cli-signins/CLI-CODE/cancel'] = { status: 'denied' }
    const me = { id: 'per_1', username: 'mei', display_name: '', status: 'active', supervisor: false } as unknown as Person
    wrap(<CLISignInApprovalPage code="CLI-CODE" person={me} />)
    await screen.findByText('You approved this sign-in')
    expect(screen.queryByRole('button', { name: 'Approve sign-in' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw approval' }))
    await screen.findByText('Approval withdrawn')
    expect(changes().map((c) => c.path)).toEqual(['/me/cli-signins/CLI-CODE/cancel'])
  })

  it('connects an MCP client only after the destination is confirmed, then returns to it', async () => {
    const id = 'k'.repeat(32)
    routes[`GET /me/mcp-connections/${id}`] = { client_name: 'Claude Code', redirect_uri: 'http://127.0.0.1:40000/callback',
      redirect_host: '127.0.0.1:40000', local: true, suggested_agent_name: 'claude-code', remote_addr: '10.0.0.9',
      created_at: '', expires_at: new Date(Date.now() + 600_000).toISOString() }
    routes[`POST /me/mcp-connections/${id}/approve`] = { redirect_url: 'http://127.0.0.1:40000/callback?code=C&state=S' }
    const went: string[] = []
    redirect.to = (url) => { went.push(url) }
    const me = { id: 'per_1', username: 'mei', display_name: '', status: 'active', supervisor: false } as unknown as Person
    wrap(<MCPConnectApprovalPage id={id} person={me} />)
    const approve = await screen.findByRole('button', { name: 'Approve and connect' })
    expect(screen.getAllByText('127.0.0.1:40000').length).toBeGreaterThan(0)
    expect((screen.getByLabelText(/^Agent name/) as HTMLInputElement).value).toBe('claude-code')
    expect((approve as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.change(screen.getByLabelText(/^Agent name/), { target: { value: 'x' } })
    expect((approve as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText(/^Agent name/), { target: { value: 'laptop-claude' } })
    fireEvent.click(approve)
    await waitFor(() => expect(went).toEqual(['http://127.0.0.1:40000/callback?code=C&state=S']))
    expect(changes()).toMatchObject([{ method: 'POST', path: `/me/mcp-connections/${id}/approve`, body: { agent_name: 'laptop-claude' } }])
    await screen.findByText('Connected')
  })

  it('remembers a sign-in link once, and only for ten minutes', () => {
    rememberSignIn('ABC-DEFG')
    expect(takeSignIn()).toEqual({ code: 'ABC-DEFG', kind: 'agent' })
    expect(takeSignIn()).toBeNull()
    rememberSignIn('CLI-CODE', 'cli')
    expect(takeSignIn()).toEqual({ code: 'CLI-CODE', kind: 'cli' })
    rememberSignIn('mcp_1', 'mcp')
    expect(takeSignIn()).toEqual({ code: 'mcp_1', kind: 'mcp' })
    const now = Date.now()
    rememberSignIn('OLD-CODE')
    vi.spyOn(Date, 'now').mockReturnValue(now + 11 * 60 * 1000)
    expect(takeSignIn()).toBeNull()
    vi.restoreAllMocks()
  })
})

// keep `act` imported for React's act environment in older setups
void act
