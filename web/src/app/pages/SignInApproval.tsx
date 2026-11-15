import { useState } from 'react'
import { api } from '../api'
import type { AgentSignIn } from '../types'
import { navigate } from '../router'
import { Button, Card, ErrorNote, PageHead, ago, roleLabel, useAction, useLoad } from '../ui'

/** An agent asks to sign in as the person's agent (the link csg login prints). */
export function SignInApprovalPage({ code }: { code: string }) {
  const signIn = useLoad(() => api.signIn(code), [code])
  const accounts = useLoad(() => api.myAccounts(), [])
  const [done, setDone] = useState<'approved' | 'denied' | null>(null)
  const action = useAction()
  const leave = () => navigate('/inbox')

  if (signIn.error && !done) {
    return (
      <>
        <PageHead title="Agent sign-in" />
        <Card><p>This sign-in code is unknown, already used or expired. Run <code>csg login</code> again to get a new one.</p>
          <Button onClick={leave}>Back to Inbox</Button></Card>
      </>
    )
  }
  const s: AgentSignIn | null = signIn.data
  if (!s) return null

  if (done) {
    return (
      <>
        <PageHead title={done === 'approved' ? `${s.agent_name} is signed in` : 'Sign-in denied'} />
        <Card>
          {done === 'approved'
            ? <p>It now belongs to you and can ask for access up to your role on each cloud account. You can revoke it any time in Agents.</p>
            : <p>The code no longer works. If you did not start this sign-in, nothing else is needed; it is in the activity log.</p>}
          <Button kind="primary" onClick={() => navigate(done === 'approved' ? '/agents' : '/inbox')}>{done === 'approved' ? 'Go to Agents' : 'Back to Inbox'}</Button>
        </Card>
      </>
    )
  }

  return (
    <>
      <PageHead title="An agent wants to sign in" lead="Only approve if you just started this sign-in yourself." />
      <Card>
        <div className="code-box">
          <span className="muted small">Code shown by the agent</span>
          <span className="big-code">{s.user_code}</span>
          <span className="muted small">Does it match your terminal? Expires {ago(s.expires_at)}.</span>
        </div>
        <dl className="facts">
          <div><dt>Agent name</dt><dd><b>{s.agent_name}</b></dd></div>
          {s.description && <div><dt>Description</dt><dd>{s.description}</dd></div>}
          <div><dt>Started from</dt><dd className="mono">{s.remote_addr}</dd></div>
        </dl>
        <h3>It will inherit your role on each cloud account</h3>
        {(accounts.data?.items ?? []).length === 0
          ? <p className="muted">You have no role on any cloud account yet, so it cannot get access until a supervisor gives you one.</p>
          : (
            <table className="table compact">
              <tbody>
                {accounts.data!.items.map((a) => (
                  <tr key={a.provider_id}><td>{a.name}</td><td className="muted">{roleLabel[a.role] ?? a.role}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        <p className="muted small">What is issued without asking you is set by your approval mode in Settings.</p>
        <ErrorNote error={action.error} />
        <div className="row-actions">
          <Button busy={action.busy} onClick={() => action.run(async () => { await api.denySignIn(code); setDone('denied') })}>Deny</Button>
          <Button kind="primary" busy={action.busy} onClick={() => action.run(async () => { await api.approveSignIn(code); setDone('approved') })}>Approve sign-in</Button>
        </div>
      </Card>
    </>
  )
}
