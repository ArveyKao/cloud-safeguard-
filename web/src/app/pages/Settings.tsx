import { useEffect, useState } from 'react'
import { api } from '../api'
import type { ApprovalMode, Person, PolicySettings } from '../types'
import { Button, Card, ErrorNote, PageHead, ago, useAction, useConfirm, useLoad, useToast, when } from '../ui'

const MODES: { value: ApprovalMode; title: string; text: string }[] = [
  { value: 'read', title: 'Read mode', text: 'Reading is automatic. Every change asks you.' },
  { value: 'write', title: 'Write mode', text: 'Reading and changing existing resources are automatic. Creating and deleting ask you.' },
  { value: 'full', title: 'Full mode', text: 'Everything your role allows is automatic. Nothing asks you.' },
]

const KEEP = -1

const EXPIRY = [
  { seconds: 0, label: 'Until I change it' }, { seconds: 3600, label: 'For 1 hour' },
  { seconds: 8 * 3600, label: 'For 8 hours' }, { seconds: 86400, label: 'For 1 day' },
]

export function SettingsPage({ person, onPersonChange }: { person: Person; onPersonChange: (p: Person) => void }) {
  const [mode, setMode] = useState<ApprovalMode>(person.approval_mode)
  // KEEP keeps the current end of a temporary mode; saving must never turn
  // a temporary mode into a permanent one by accident.
  const hasEnd = Boolean(person.approval_mode_expires_at)
  const [expiry, setExpiry] = useState(hasEnd ? KEEP : 0)
  const action = useAction()
  const toast = useToast()
  const { confirm, element: confirmDialog } = useConfirm()
  const issued = person.setup_issued
  const rank = { read: 1, write: 2, full: 3 }

  function expirySeconds(): number {
    if (mode === 'read') return 0
    if (expiry !== KEEP) return expiry
    const left = Math.ceil((new Date(person.approval_mode_expires_at ?? 0).getTime() - Date.now()) / 1000)
    return Math.max(1, left)
  }
  async function save() {
    onPersonChange(await api.setMode(mode, expirySeconds()))
    toast('Approval mode saved')
  }
  function onSave() {
    const raising = rank[mode] > rank[person.approval_mode]
    const endingRemoved = hasEnd && mode !== 'read' && expiry === 0
    if (!raising && !endingRemoved) {
      action.run(save)
      return
    }
    const what = MODES.find((m) => m.value === mode)!
    confirm({
      title: `Switch to ${what.title.toLowerCase()}${expiry === 0 ? ' until you change it' : ''}?`,
      body: `${what.text} This applies to all your agents, on every account whose supervisor allows it.`,
      confirmLabel: 'Switch', run: save,
    })
  }

  return (
    <>
      <PageHead title="Settings" />
      <Card title="Your approval mode">
        <p className="muted">How much your agents get without asking you. It applies to all your agents, never goes beyond your role, and a supervisor may cap it per cloud account.</p>
        <div className="mode-grid" role="radiogroup">
          {MODES.map((m) => (
            <label key={m.value} className="mode" data-selected={mode === m.value}>
              <input type="radio" name="mode" aria-label={m.title} checked={mode === m.value} onChange={() => setMode(m.value)} />
              <b>{m.title}</b><span>{m.text}</span>
            </label>
          ))}
        </div>
        {mode !== 'read' && (
          <label className="field inline">
            <span>Keep it</span>
            <select value={expiry} onChange={(e) => setExpiry(Number(e.target.value))}>
              {hasEnd && <option value={KEEP}>Until {when(person.approval_mode_expires_at)}, as now</option>}
              {EXPIRY.map((x) => <option key={x.seconds} value={x.seconds}>{x.label}</option>)}
            </select>
          </label>
        )}
        {person.approval_mode_expires_at && <p className="muted small">Your current mode falls back to read on {when(person.approval_mode_expires_at)}.</p>}
        <ErrorNote error={action.error} />
        <div className="row-actions left">
          <Button kind="primary" busy={action.busy} onClick={onSave}>Save</Button>
        </div>
        {confirmDialog}
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
