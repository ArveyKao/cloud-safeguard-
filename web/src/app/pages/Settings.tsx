import { useEffect, useState } from 'react'
import { api } from '../api'
import type { Person, PolicySettings } from '../types'
import { navigate } from '../router'
import { Button, Card, ErrorNote, PageHead, ago, useAction, useLoad, useToast, when } from '../ui'

export function SettingsPage({ person }: { person: Person; onPersonChange?: (p: Person) => void }) {
  const issued = person.setup_issued

  return (
    <>
      <PageHead title="Settings" />
      <Card title="Your approval mode">
        <p className="muted">How much your agents get without asking you is set per cloud account, on the <a href="/accounts" onClick={(e) => { e.preventDefault(); navigate('/accounts') }}>Cloud accounts</a> page.</p>
      </Card>

      <Card title="Your account">
        <dl className="facts">
          <div><dt>Username</dt><dd>{person.username}</dd></div>
          <div><dt>Supervisor</dt><dd>{person.supervisor ? 'yes' : 'no'}</dd></div>
          {issued && <div><dt>Password set up with a code from</dt><dd>{issued.by_name} · {when(issued.at)}</dd></div>}
        </dl>
        {issued && issued.by_id !== 'system' && issued.by_id !== person.id && (
          <p className="muted small">If you did not choose your own password after that, tell another supervisor.</p>
        )}
      </Card>

      <CLISessions />

      {person.supervisor && <Limits />}
    </>
  )
}

/** The person's command-line sign-ins, each of which can be ended here. */
function CLISessions() {
  const sessions = useLoad(() => api.cliSessions(), [])
  const action = useAction()
  const toast = useToast()
  const items = sessions.data?.items ?? []
  return (
    <Card title="Command-line sign-ins">
      <p className="muted">Each <code>csg person login</code> you approved. End one you do not recognise, or no longer use.</p>
      <ErrorNote error={action.error ?? sessions.error} />
      {items.length === 0 ? <p className="muted">None.</p> : (
        <table className="table compact">
          <thead><tr><th>Client</th><th>From</th><th>Signed in</th><th>Last used</th><th /></tr></thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.id}>
                <td>{s.client_name}</td>
                <td className="mono">{s.remote_addr}</td>
                <td>{ago(s.created_at)}</td>
                <td>{ago(s.last_seen_at)}</td>
                <td className="right"><Button kind="link" busy={action.busy} onClick={() => action.run(async () => {
                  await api.revokeCLISession(s.id); toast('Sign-in ended'); sessions.reload()
                })}>End</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

const LIMITS: { key: keyof PolicySettings; label: string; unit: string }[] = [
  { key: 'max_lease_ttl_seconds', label: 'Longest validity of a credential', unit: 'seconds' },
  { key: 'pending_timeout_seconds', label: 'A request waits for approval at most', unit: 'seconds' },
  { key: 'max_concurrent_leases_per_agent', label: 'Open requests and credentials per agent', unit: '' },
  { key: 'leases_per_minute_per_agent', label: 'Requests per agent per minute', unit: '' },
  { key: 'max_refresh_lifetime_seconds', label: 'An agent may keep refreshing one request for at most', unit: 'seconds' },
]

function Limits() {
  const settings = useLoad(() => api.settings(), [])
  const [draft, setDraft] = useState<PolicySettings | null>(null)
  const action = useAction()
  const toast = useToast()
  useEffect(() => { if (settings.data) setDraft(settings.data) }, [settings.data])
  if (!draft) return null
  return (
    <Card title="Platform limits">
      <p className="muted">Apply to every agent. Lowering the longest validity also ends credentials that run longer.</p>
      <div className="limits">
        {LIMITS.map((l) => (
          <label key={l.key} className="field">
            <span>{l.label}</span>
            <input type="number" min={1} value={draft[l.key] as number}
              onChange={(e) => setDraft({ ...draft, [l.key]: Number(e.target.value) })} />
            {l.unit && <small>{l.unit}</small>}
          </label>
        ))}
      </div>
      <ErrorNote error={action.error ?? settings.error} />
      <div className="row-actions left">
        <Button kind="primary" busy={action.busy} onClick={() => action.run(async () => { setDraft(await api.putSettings(draft)); toast('Limits saved') })}>Save limits</Button>
      </div>
    </Card>
  )
}
