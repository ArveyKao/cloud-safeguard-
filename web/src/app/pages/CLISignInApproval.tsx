import { useState } from 'react'
import { api } from '../api'
import type { CLISignIn, Person } from '../types'
import { navigate } from '../router'
import { Button, Card, ErrorNote, PageHead, ago, useAction, useLoad } from '../ui'

/** csg on the command line asks to sign in as this person (the link csg person login prints). */
export function CLISignInApprovalPage({ code, person }: { code: string; person: Person }) {
  const signIn = useLoad(() => api.cliSignIn(code), [code])
  const [matched, setMatched] = useState(false)
  const [done, setDone] = useState<'approved' | 'denied' | null>(null)
  const action = useAction()
  const leave = () => navigate('/inbox')

  if (signIn.error && !done) {
    return (
      <>
        <PageHead title="Command-line sign-in" />
        <Card><p>This sign-in code is unknown, already used or expired. Run <code>csg person login</code> again to get a new one.</p>
          <Button onClick={leave}>Back to Inbox</Button></Card>
      </>
    )
  }
  const s: CLISignIn | null = signIn.data
  if (!s) return null

  if (done) {
    return (
      <>
        <PageHead title={done === 'approved' ? 'csg is signed in as you' : 'Sign-in denied'} />
        <Card>
          {done === 'approved'
            ? <p>The command line can now read, deny and revoke as you. Anything that raises access asks for a code from your authenticator app, and approving stays here in the console. You can end this sign-in any time in Settings.</p>
            : <p>The code no longer works. If you did not start this sign-in, nothing else is needed; it is in the activity log.</p>}
          <Button kind="primary" onClick={() => navigate(done === 'approved' ? '/settings' : '/inbox')}>{done === 'approved' ? 'Go to Settings' : 'Back to Inbox'}</Button>
        </Card>
      </>
    )
  }

  return (
    <>
      <PageHead title="csg wants to sign in as you" lead="Only approve if you just ran csg person login yourself." />
      <Card>
        <div className="code-box">
          <span className="muted small">Code shown by csg</span>
          <span className="big-code">{s.user_code}</span>
          <span className="muted small">Does it match your terminal? Expires {ago(s.expires_at)}.</span>
        </div>
        <dl className="facts">
          <div><dt>Signs in as</dt><dd><b>{person.display_name || person.username}</b>{person.supervisor && <span className="muted small"> · supervisor</span>}</dd></div>
          <div><dt>Client name</dt><dd>{s.client_name}</dd></div>
          <div><dt>Started from</dt><dd className="mono">{s.remote_addr}</dd></div>
        </dl>
        <p className="note note-info">
          The command line can read and lower access as you for up to 12 hours (30 minutes without use).
          Raising access needs a code from your authenticator app each time. Approving requests and sign-ins is never possible from it.
          Someone who tricks you into approving a code they started gets this sign-in, so check the code.
        </p>
        <label className="check">
          <input type="checkbox" checked={matched} onChange={(e) => setMatched(e.target.checked)} />
          I ran csg person login myself, and the code above matches the one in my terminal.
        </label>
        <ErrorNote error={action.error} />
        <div className="row-actions">
          <Button busy={action.busy} onClick={() => action.run(async () => { await api.denyCLISignIn(code); setDone('denied') })}>Deny</Button>
          <Button kind="primary" busy={action.busy} disabled={!matched} onClick={() => action.run(async () => { await api.approveCLISignIn(code); setDone('approved') })}>Approve sign-in</Button>
        </div>
      </Card>
    </>
  )
}
