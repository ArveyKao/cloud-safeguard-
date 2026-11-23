import { useEffect, useState } from 'react'
import { api } from '../api'
import type { MCPConnection, Person } from '../types'
import { navigate } from '../router'
import { Button, Card, ErrorNote, Field, PageHead, ago, useAction, useLoad } from '../ui'

const AGENT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/

/** Leaves the console for the MCP client's redirect URI (replaceable in tests). */
export const redirect = { to: (url: string) => window.location.assign(url) }
const goTo = (url: string) => redirect.to(url)

/** A remote MCP client (Claude, Cursor, …) asks to connect as an agent of this person. */
export function MCPConnectApprovalPage({ id, person }: { id: string; person: Person }) {
  const conn = useLoad(() => api.mcpConnection(id), [id])
  const [agentName, setAgentName] = useState('')
  const [checked, setChecked] = useState(false)
  const [done, setDone] = useState<{ kind: 'approved' | 'denied'; url: string } | null>(null)
  const action = useAction()
  const c: MCPConnection | null = conn.data

  useEffect(() => {
    if (c && !agentName) setAgentName(c.suggested_agent_name)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [c])

  if (done) {
    return (
      <>
        <PageHead title={done.kind === 'approved' ? 'Connected' : 'Connection denied'} />
        <Card>
          <p>{done.kind === 'approved'
            ? <>Returning to the app. The agent <b>{agentName}</b> now acts for you; you can revoke it any time on the Agents page.</>
            : 'The app was told that you denied it. If you did not start this, nothing else is needed; it is in the activity log.'}</p>
          <div className="row-actions left">
            <Button kind="primary" onClick={() => goTo(done.url)}>Return to the app</Button>
            <Button onClick={() => navigate(done.kind === 'approved' ? '/agents' : '/inbox')}>{done.kind === 'approved' ? 'Go to Agents' : 'Back to Inbox'}</Button>
          </div>
        </Card>
      </>
    )
  }
  if (conn.error) {
    return (
      <>
        <PageHead title="Connect an MCP client" />
        <Card><p>This connection request is unknown, already decided or expired. Start connecting again in your app.</p>
          <Button onClick={() => navigate('/inbox')}>Back to Inbox</Button></Card>
      </>
    )
  }
  if (!c) return null

  const nameOK = AGENT_NAME.test(agentName.trim())
  const decide = (approve: boolean) => action.run(async () => {
    const out = approve ? await api.approveMCPConnection(id, agentName.trim()) : await api.denyMCPConnection(id)
    setDone({ kind: approve ? 'approved' : 'denied', url: out.redirect_url })
    goTo(out.redirect_url)
  })

  return (
    <>
      <PageHead title={`${c.client_name} wants to connect as your agent`} lead="Only approve if you just added Cloud Safeguard to this app yourself." />
      <Card>
        <dl className="facts facts-spaced">
          <div><dt>App says it is</dt><dd><b>{c.client_name}</b> <span className="muted small">(any app can call itself anything)</span></dd></div>
          <div><dt>Sign-in goes to</dt><dd><b className="mono">{c.redirect_host}</b>{c.local && <span className="muted small"> · an app on this computer</span>}</dd></div>
          <div><dt>Acts for</dt><dd><b>{person.display_name || person.username}</b>{person.supervisor && <span className="muted small"> · supervisor</span>}</dd></div>
          <div><dt>Started from</dt><dd className="mono">{c.remote_addr}</dd></div>
        </dl>
        <Field label="Agent name" value={agentName} onChange={setAgentName}
          hint={nameOK ? 'Shown on the Agents page and in the activity log. A sign-in with the same name replaces your earlier agent.' : '2-64 letters, digits, dot, dash or underscore.'} />
        <p className="note note-info">
          The agent can ask for cloud access within your role, as your approval mode allows, until you revoke it on the Agents page.
          It can never approve anything or manage IAM or RAM. Someone who tricks you into approving a connection they started gets this agent, so check where the sign-in goes.
        </p>
        <label className="check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          I started this connection myself, and <span className="mono">{c.redirect_host}</span> is the app I am connecting.
        </label>
        <p className="muted small">Expires {ago(c.expires_at)}.</p>
        <ErrorNote error={action.error} />
        <div className="row-actions">
          <Button busy={action.busy} onClick={() => decide(false)}>Deny</Button>
          <Button kind="primary" busy={action.busy} disabled={!checked || !nameOK} onClick={() => decide(true)}>Approve and connect</Button>
        </div>
      </Card>
    </>
  )
}
